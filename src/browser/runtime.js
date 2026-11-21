import express, { dispatch } from 'express';
import { BASE_PATH, BASE_URL } from './config.js';
import { createMockCognitoRouter, MOCK_PREFIX } from '../mock/cognito.js';
import { createMockGatewayRouter, MOCK_GATEWAY_PATH } from '../mock/gateway.js';
import { createBackendRouter } from '../backend.js';
import { createMockProvider } from '../providers/mock.js';
import { createAppRouter } from '../routes.js';
import { isDynamicPath } from './dynamic-paths.js';

const provider = createMockProvider();
provider.label = '模擬モード（ブラウザ内で動作）';
provider.capabilities = { ...provider.capabilities, staticSite: true };

const app = express();
app.use(MOCK_PREFIX, createMockCognitoRouter());
app.use(MOCK_GATEWAY_PATH, createMockGatewayRouter());
app.use('/backend', createBackendRouter(() => provider.verifier()));
app.use(createAppRouter({ providers: { mock: provider }, initialMode: 'mock' }));

const relPath = (url) => {
  const u = new URL(url, BASE_URL);
  if (u.origin !== location.origin || !u.pathname.startsWith(`${BASE_PATH}/`)) return null;
  return u.pathname.slice(BASE_PATH.length);
};

export const handleRequest = (request) => dispatch(app, request, { stripPrefix: BASE_PATH });

const realFetch = globalThis.fetch.bind(globalThis);
globalThis.fetch = (input, init) => {
  const request = new Request(input, init);
  const rel = relPath(request.url);
  return rel && isDynamicPath(rel) ? handleRequest(request) : realFetch(input, init);
};

async function startServiceWorker() {
  if (!('serviceWorker' in navigator)) throw new Error('このブラウザは Service Worker に対応していないため、ログインのポップアップを使えません');
  navigator.serviceWorker.addEventListener('message', async (event) => {
    if (event.data?.type !== 'demo-request') return;
    const { url, method, headers, body } = event.data;
    const port = event.ports[0];
    try {
      const res = await handleRequest(new Request(url, { method, headers, body: ['GET', 'HEAD'].includes(method) ? undefined : body }));
      port.postMessage({ status: res.status, headers: [...res.headers], body: await res.text() });
    } catch (err) {
      port.postMessage({ status: 500, headers: [['content-type', 'text/plain; charset=utf-8']], body: String(err?.message ?? err) });
    }
  });
  navigator.serviceWorker.startMessages();
  await navigator.serviceWorker.register(`${BASE_URL}/sw.js`, { scope: `${BASE_PATH}/` });
  await navigator.serviceWorker.ready;
}

try {
  await startServiceWorker();
} catch (err) {
  console.error(err);
  document.addEventListener('DOMContentLoaded', () => alert(err.message));
}
