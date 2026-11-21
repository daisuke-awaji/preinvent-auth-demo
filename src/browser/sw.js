import { isDynamicPath } from './dynamic-paths.js';

const BASE = new URL('./', self.location.href).pathname;

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', (event) => event.waitUntil(self.clients.claim()));

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin || !url.pathname.startsWith(BASE)) return;
  if (!isDynamicPath(`/${url.pathname.slice(BASE.length)}`)) return;
  event.respondWith(forward(event.request));
});

const page = (msg) =>
  new Response(`<!doctype html><meta charset="utf-8"><body style="font-family:system-ui,sans-serif;background:#000;color:#ededed;padding:2rem">${msg}</body>`, {
    status: 503,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  });

async function forward(request) {
  const windows = await self.clients.matchAll({ type: 'window', includeUncontrolled: true });
  const host = windows.find((c) => {
    const p = new URL(c.url).pathname;
    return p === BASE || p === `${BASE}index.html`;
  });
  if (!host) return page(`デモのページ（<a style="color:#fff" href="${BASE}">${BASE}</a>）を開いた状態で操作してください。`);
  const body = ['GET', 'HEAD'].includes(request.method) ? undefined : await request.text();
  const channel = new MessageChannel();
  const reply = new Promise((resolve) => {
    channel.port1.onmessage = (m) => resolve(m.data);
    setTimeout(() => resolve(null), 20000);
  });
  host.postMessage({ type: 'demo-request', url: request.url, method: request.method, headers: [...request.headers], body }, [channel.port2]);
  const r = await reply;
  if (!r) return page('デモのページから応答がありませんでした。ページを再読み込みしてください。');
  const location = new Headers(r.headers).get('location');
  if (r.status >= 300 && r.status < 400 && location) return Response.redirect(new URL(location, request.url).href, [301, 302, 303, 307, 308].includes(r.status) ? r.status : 302);
  return new Response([204, 304].includes(r.status) ? null : r.body, { status: r.status, headers: r.headers });
}
