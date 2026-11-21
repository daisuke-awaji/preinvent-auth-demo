import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';

process.env.PORT = '3999';
process.env.DEMO_MODE = 'mock';
const { createServer } = await import('../src/server.js');
const BASE = 'http://localhost:3999';
let server;

before(async () => {
  const { app } = createServer();
  await new Promise((resolve) => {
    server = app.listen(3999, '127.0.0.1', resolve);
  });
});
after(() => server.close());

const api = async (path, { method = 'GET', body } = {}) => {
  const res = await fetch(BASE + path, { method, headers: body ? { 'Content-Type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined });
  return { status: res.status, body: await res.json() };
};

async function popupLogin(clientId, kind, label) {
  let res = await fetch(`${BASE}/api/login/start?${new URLSearchParams({ client: clientId, kind, label })}`, { redirect: 'manual' });
  assert.equal(res.status, 302);
  res = await fetch(res.headers.get('location'), { redirect: 'manual' });
  const page = await res.text();
  if (res.status !== 200) return { ok: false, status: res.status, page };
  const txn = /name="txn" value="([^"]+)"/.exec(page)[1];
  res = await fetch(`${BASE}/mock/cognito/login`, { method: 'POST', redirect: 'manual', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ txn, username: 'demo', password: 'Passw0rd!' }) });
  assert.equal(res.status, 302);
  res = await fetch(res.headers.get('location'), { redirect: 'manual' });
  const cb = await res.text();
  const msg = JSON.parse(/postMessage\((\{.*?\}),location.origin\)/.exec(cb)[1].replace(/\\u003c/g, '<'));
  return { ok: msg.type === 'login-complete', msg };
}

const wallet = async () => (await api('/api/state')).body.wallet;

test('① CIMD: trusted URL logs in and client_id is the URL; untrusted is rejected', async () => {
  const state = (await api('/api/state')).body;
  const trusted = state.cimdDocs.find((d) => d.key === 'trusted');
  const untrusted = state.cimdDocs.find((d) => d.key === 'untrusted');
  const login = await popupLogin(trusted.url, 'cimd', 'CIMD client');
  assert.ok(login.ok);
  const w = (await wallet()).find((x) => x.kind === 'cimd');
  assert.equal(w.claims.client_id, trusted.url);

  const probe = await api('/api/cimd/probe', { method: 'POST', body: { key: 'untrusted' } });
  const authz = probe.body.trace.steps.at(-1);
  assert.equal(authz.response.status, 400);
  const denied = await popupLogin(untrusted.url, 'cimd', 'untrusted');
  assert.equal(denied.ok, false);
  assert.match(denied.page, /unauthorized_client/);
});

test('① DCR: open registration issues dcr_ client; closing it yields 401; token-based works', async () => {
  const open = await api('/api/dcr/register', { method: 'POST', body: { withToken: false } });
  assert.match(open.body.registration.clientId, /^dcr_/);
  const login = await popupLogin(open.body.registration.clientId, 'dcr', 'DCR client');
  assert.ok(login.ok);

  await api('/api/dcr/open', { method: 'POST', body: { enabled: false } });
  const closed = await api('/api/dcr/register', { method: 'POST', body: { withToken: false } });
  assert.equal(closed.body.registration, null);
  assert.equal(closed.body.trace.steps.at(-1).response.status, 401);
  const authed = await api('/api/dcr/register', { method: 'POST', body: { withToken: true, clientName: 'second' } });
  assert.match(authed.body.registration.clientId, /^dcr_/);
  await api('/api/dcr/open', { method: 'POST', body: { enabled: true } });
  const list = await api('/api/dcr/clients');
  assert.equal(list.body.clients.length, 2);
});

test('② Gateway: Deny by client_id → 403 only for that client; Deny-only → all 403', async () => {
  const state = (await api('/api/state')).body;
  const users = state.wallet.filter((w) => ['cimd', 'dcr'].includes(w.kind));
  const target = users.find((w) => w.kind === 'dcr');
  const allow = { Sid: 'AllowAll', Effect: 'Allow', Principal: '*', Action: 'bedrock-agentcore:InvokeGateway', Resource: state.gatewayArn };
  const deny = {
    Sid: 'DenyClient',
    Effect: 'Deny',
    Principal: '*',
    Action: 'bedrock-agentcore:InvokeGateway',
    Resource: state.gatewayArn,
    Condition: { StringEquals: { 'bedrock-agentcore:InboundJwtClaim/client_id': target.claims.client_id } },
  };
  let m = await api('/api/gateway/matrix', { method: 'POST' });
  assert.ok(m.body.rows.every((r) => r.status === 200));

  await api('/api/gateway/policy', { method: 'PUT', body: { policy: { Version: '2012-10-17', Statement: [allow, deny] } } });
  m = await api('/api/gateway/matrix', { method: 'POST' });
  for (const r of m.body.rows) assert.equal(r.status, r.walletId === target.id ? 403 : 200);

  await api('/api/gateway/policy', { method: 'PUT', body: { policy: { Version: '2012-10-17', Statement: [deny] } } });
  m = await api('/api/gateway/matrix', { method: 'POST' });
  assert.ok(m.body.rows.every((r) => r.status === 403));
  await api('/api/gateway/policy', { method: 'DELETE' });
});

test('③ Token exchange: narrowed scope, aud, act, no refresh; broadening → 400', async () => {
  const user = (await wallet()).find((w) => w.kind === 'cimd');
  const fwd = await api('/api/exchange/forward', { method: 'POST', body: { walletId: user.id } });
  assert.ok(fwd.body.trace.notes.some((n) => n.level === 'warn'));

  const ex = await api('/api/exchange/exchange', { method: 'POST', body: { walletId: user.id, scope: 'demo-backend/read' } });
  assert.ok(ex.body.walletId);
  const issued = (await wallet()).find((w) => w.id === ex.body.walletId);
  assert.equal(issued.claims.scope, 'demo-backend/read');
  assert.equal(issued.claims.aud, 'demo-backend');
  assert.equal(issued.claims.act.sub, 'mock-mcp-server');
  assert.equal(issued.hasRefreshToken, false);

  const read = await api('/api/backend/call', { method: 'POST', body: { walletId: issued.id, op: 'read' } });
  assert.equal(read.body.trace.steps.at(-1).response.status, 200);
  const write = await api('/api/backend/call', { method: 'POST', body: { walletId: issued.id, op: 'write' } });
  assert.equal(write.body.trace.steps.at(-1).response.status, 403);

  const broad = await api('/api/exchange/exchange', { method: 'POST', body: { walletId: user.id, scope: 'demo-backend/admin' } });
  assert.equal(broad.body.walletId, null);
  assert.equal(broad.body.trace.steps.at(-1).response.status, 400);

  const imp = await api('/api/exchange/exchange', { method: 'POST', body: { walletId: user.id, scope: 'demo-backend/read', withActor: false } });
  const impTok = (await wallet()).find((w) => w.id === imp.body.walletId);
  assert.equal(impTok.claims.act, undefined);
});
