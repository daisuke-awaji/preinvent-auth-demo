import { createHash, randomBytes, randomUUID } from 'node:crypto';
import express from 'express';
import { BASE_URL, REDIRECT_URI, RESOURCE_SERVERS, SCOPES, USER_LOGIN_SCOPE } from './config.js';
import { Trace, decodeToken } from './lib/trace.js';
import { buildCimdDocument, CIMD_DOCS } from './providers/cimd-docs.js';

const TOKEN_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';
const ACCESS_TOKEN_TYPE = 'urn:ietf:params:oauth:token-type:access_token';
const basic = (id, secret) => `Basic ${Buffer.from(`${encodeURIComponent(id)}:${encodeURIComponent(secret)}`).toString('base64')}`;

function newSession() {
  return { wallet: [], registrations: [], pending: new Map(), traces: new Map() };
}

export function createAppRouter({ providers, initialMode }) {
  const sessions = { mock: newSession(), aws: newSession() };
  let mode = providers[initialMode] ? initialMode : 'mock';
  const p = () => providers[mode];
  const s = () => sessions[mode];

  const saveTrace = (trace) => {
    const id = randomUUID();
    s().traces.set(id, trace.toJSON());
    if (s().traces.size > 50) s().traces.delete(s().traces.keys().next().value);
    return id;
  };
  const addToWallet = (entry) => {
    const item = { id: randomUUID().slice(0, 8), createdAt: new Date().toISOString(), ...entry };
    s().wallet.push(item);
    return item;
  };
  const walletSummary = (w) => ({
    id: w.id,
    label: w.label,
    kind: w.kind,
    clientId: w.clientId,
    hasRefreshToken: Boolean(w.refreshToken),
    claims: decodeToken(w.accessToken)?.payload ?? null,
    createdAt: w.createdAt,
  });
  const findWallet = (id) => {
    const w = s().wallet.find((x) => x.id === id);
    if (!w) throw Object.assign(new Error('トークンが見つかりません。先にログインしてください'), { status: 404 });
    return w;
  };

  const r = express.Router();
  r.use(express.json({ limit: '200kb' }));

  const wrap = (fn) => async (req, res) => {
    try {
      await fn(req, res);
    } catch (err) {
      res.status(err.status ?? 500).json({ error: err.name ?? 'Error', message: err.message });
    }
  };

  r.get('/cimd/:dir/:file', (req, res) => {
    const doc = CIMD_DOCS.find((d) => d.path === `${req.params.dir}/${req.params.file}`);
    if (!doc) return res.status(404).json({ error: 'not_found' });
    const url = `${BASE_URL}/cimd/${doc.path}`;
    res.json(buildCimdDocument(url, doc.name));
  });

  r.get('/api/state', wrap(async (_req, res) => {
    const prov = p();
    let described;
    try {
      described = await prov.describe();
    } catch (err) {
      described = { errors: [`${err.name}: ${err.message}`] };
    }
    res.json({
      mode,
      label: prov.label,
      loginHint: prov.loginHint,
      availableModes: Object.keys(providers),
      endpoints: prov.endpoints,
      clients: { cimdBase: prov.clients.cimdBase, registrar: prov.clients.registrar.id, mcpServer: prov.clients.mcpServer.id },
      cimdDocs: prov.cimdDocs,
      gatewayArn: prov.gatewayArn,
      capabilities: prov.capabilities,
      scopes: SCOPES,
      resourceServers: RESOURCE_SERVERS,
      userLoginScope: USER_LOGIN_SCOPE,
      redirectUri: REDIRECT_URI,
      described,
      wallet: s().wallet.map(walletSummary),
      registrations: s().registrations,
    });
  }));

  r.post('/api/mode', wrap(async (req, res) => {
    if (!providers[req.body.mode]) throw Object.assign(new Error(`${req.body.mode} モードは使えません（aws-config.json がありません）`), { status: 400 });
    mode = req.body.mode;
    res.json({ mode });
  }));

  r.post('/api/reset', wrap(async (_req, res) => {
    await p().reset();
    sessions[mode] = newSession();
    res.json({ ok: true });
  }));

  r.get('/api/trace/:id', (req, res) => {
    const t = s().traces.get(req.params.id);
    if (!t) return res.status(404).json({ error: 'not_found' });
    res.json(t);
  });

  // ① CIMD / DCR
  r.post('/api/cimd/probe', wrap(async (req, res) => {
    const doc = p().cimdDocs.find((d) => d.key === req.body.key);
    if (!doc) throw Object.assign(new Error('unknown CIMD document'), { status: 400 });
    const trace = new Trace(`CIMD: ${doc.name} の URL を client_id として名乗る`);
    const disc = await trace.fetch('認可サーバーのメタデータ（discovery）', p().endpoints.discovery);
    if (disc.body && typeof disc.body === 'object') {
      const supported = disc.body.client_id_metadata_document_supported;
      trace.note(supported ? 'ok' : 'info', `client_id_metadata_document_supported = ${supported ?? '（未記載）'}`);
    }
    await trace.fetch('クライアントが公開しているメタデータドキュメント', doc.url);
    const { url } = buildAuthorize(doc.url, 'probe');
    const authz = await trace.fetch('認可エンドポイントに client_id=URL で問い合わせ（サーバーから試行）', url);
    if (authz.status >= 400) trace.note('error', 'Cognito がこのクライアントを拒否しました（CIMD ポリシーの URL パターンに一致しない等）');
    else trace.note('ok', 'Cognito がクライアントを受け入れ、ログイン画面へ進めます');
    res.json({ traceId: saveTrace(trace), trace: trace.toJSON() });
  }));

  r.post('/api/cimd/patterns', wrap(async (req, res) => {
    const patterns = (req.body.patterns ?? []).map((x) => String(x).trim()).filter(Boolean);
    if (!patterns.length) throw Object.assign(new Error('URL パターンを1つ以上指定してください'), { status: 400 });
    const trace = new Trace('CIMD ポリシーの URL パターンを更新');
    await p().setCimdPatterns(patterns, trace);
    res.json({ trace: trace.toJSON() });
  }));

  function buildAuthorize(clientId, stateValue, codeChallenge) {
    const u = new URL(p().endpoints.authorize);
    u.searchParams.set('response_type', 'code');
    u.searchParams.set('client_id', clientId);
    u.searchParams.set('redirect_uri', REDIRECT_URI);
    u.searchParams.set('scope', USER_LOGIN_SCOPE);
    u.searchParams.set('state', stateValue);
    u.searchParams.set('code_challenge', codeChallenge ?? createHash('sha256').update('probe').digest('base64url'));
    u.searchParams.set('code_challenge_method', 'S256');
    return { url: u.toString() };
  }

  r.get('/api/login/start', (req, res) => {
    const { client, kind = 'user', label = client } = req.query;
    if (!client) return res.status(400).send('client is required');
    const verifier = randomBytes(32).toString('base64url');
    const challenge = createHash('sha256').update(verifier).digest('base64url');
    const stateValue = randomBytes(16).toString('base64url');
    const trace = new Trace(`${label} でログイン（認可コード＋PKCE）`);
    const { url } = buildAuthorize(String(client), stateValue, challenge);
    trace.steps.push({ kind: 'http', title: '認可リクエスト（ブラウザをリダイレクト）', request: { method: 'GET', url }, response: { status: 302, body: 'ログイン画面へ' } });
    s().pending.set(stateValue, { clientId: String(client), kind, label, verifier, trace, mode });
    res.redirect(302, url);
  });

  r.get('/callback', async (req, res) => {
    const pending = s().pending.get(String(req.query.state ?? ''));
    const finish = (msg) => res.send(`<!doctype html><meta charset="utf-8"><body style="font-family:sans-serif;padding:2rem">${msg.type === 'login-complete' ? 'ログインしました。このウィンドウは閉じて構いません。' : 'ログインに失敗しました。'}<script>window.opener&&window.opener.postMessage(${JSON.stringify(msg).replace(/</g, '\\u003c')},location.origin);setTimeout(()=>window.close(),600)</script>`);
    if (!pending) return finish({ type: 'login-error', error: 'invalid_state', description: 'state が一致しません' });
    s().pending.delete(String(req.query.state));
    const { trace } = pending;
    if (req.query.error) {
      trace.steps.push({ kind: 'http', title: 'コールバック（エラー）', request: { method: 'GET', url: `${REDIRECT_URI}?error=…` }, response: { status: 302, body: { error: req.query.error, error_description: req.query.error_description } } });
      trace.note('error', `${req.query.error}: ${req.query.error_description ?? ''}`);
      return finish({ type: 'login-error', traceId: saveTrace(trace), error: req.query.error, description: req.query.error_description });
    }
    const tokenRes = await trace.fetch('認可コードをトークンに交換', p().endpoints.token, {
      method: 'POST',
      form: { grant_type: 'authorization_code', client_id: pending.clientId, code: String(req.query.code), redirect_uri: REDIRECT_URI, code_verifier: pending.verifier },
    });
    if (!tokenRes.ok) {
      trace.note('error', 'トークンの取得に失敗しました');
      return finish({ type: 'login-error', traceId: saveTrace(trace), error: tokenRes.body?.error });
    }
    const claims = decodeToken(tokenRes.body.access_token)?.payload ?? {};
    trace.note('ok', `アクセストークンの client_id = ${claims.client_id}`);
    if (pending.kind === 'cimd') trace.note('ok', '名乗った URL がそのまま client_id に入っています（事前登録なし）');
    if (pending.kind === 'dcr') trace.note('ok', '動的に登録した dcr_ クライアントでログインできました');
    const item = addToWallet({ label: pending.label, kind: pending.kind, clientId: pending.clientId, accessToken: tokenRes.body.access_token, idToken: tokenRes.body.id_token, refreshToken: tokenRes.body.refresh_token });
    finish({ type: 'login-complete', traceId: saveTrace(trace), walletId: item.id });
  });

  r.post('/api/dcr/register', wrap(async (req, res) => {
    const withToken = Boolean(req.body.withToken);
    const clientName = String(req.body.clientName || 'Demo MCP client (DCR)').slice(0, 100);
    const trace = new Trace(withToken ? 'DCR: 初期アクセストークンを付けて登録（認証済み登録）' : 'DCR: トークンなしで登録（オープン登録）');
    const headers = {};
    if (withToken) {
      const { id, secret } = p().clients.registrar;
      const tok = await trace.fetch('初期アクセストークンを取得（client_credentials, aws.cognito/dcr/register）', p().endpoints.token, {
        method: 'POST',
        headers: { Authorization: basic(id, secret) },
        form: { grant_type: 'client_credentials', scope: SCOPES.dcrRegister },
      });
      if (!tok.ok) {
        trace.note('error', '初期アクセストークンを取得できませんでした');
        return res.json({ traceId: saveTrace(trace), trace: trace.toJSON() });
      }
      headers.Authorization = `Bearer ${tok.body.access_token}`;
    }
    const reg = await trace.fetch('登録エンドポイントへ POST（RFC 7591）', p().endpoints.register, {
      method: 'POST',
      headers,
      json: { client_name: clientName, redirect_uris: [REDIRECT_URI], grant_types: ['authorization_code'], token_endpoint_auth_method: 'none', scope: USER_LOGIN_SCOPE },
    });
    let registration = null;
    if (reg.status === 201) {
      registration = { clientId: reg.body.client_id, clientName: reg.body.client_name, via: withToken ? 'authenticated' : 'open', createdAt: new Date().toISOString() };
      s().registrations.push(registration);
      trace.note('ok', `${reg.body.client_id} が発行されました（dcr_ で始まる ID）`);
    } else if (reg.status === 401) {
      trace.note('error', 'オープン登録が無効なので、初期アクセストークンなしの登録は 401 で拒否されました');
    } else if (reg.status === 404) {
      trace.note('error', 'DCR が無効か、まだ反映されていません（登録エンドポイントが 404）');
    } else {
      trace.note('error', `登録に失敗しました（HTTP ${reg.status}）`);
    }
    res.json({ traceId: saveTrace(trace), trace: trace.toJSON(), registration });
  }));

  r.post('/api/dcr/open', wrap(async (req, res) => {
    const trace = new Trace(`オープン登録を${req.body.enabled ? '有効' : '無効'}にする`);
    await p().setOpenRegistration(Boolean(req.body.enabled), trace);
    if (req.body.enabled) trace.note('warn', '誰でもクライアントを登録できます。登録用トークンを必須にするか、AWS WAF でレート制限をかけましょう');
    res.json({ trace: trace.toJSON() });
  }));

  r.get('/api/dcr/clients', wrap(async (_req, res) => {
    const trace = new Trace('DCR で登録されたクライアントの一覧');
    const clients = await p().listDcrClients(trace);
    res.json({ clients, trace: trace.toJSON() });
  }));

  r.delete('/api/dcr/clients/:id', wrap(async (req, res) => {
    const trace = new Trace(`DCR クライアント ${req.params.id} を削除`);
    await p().deleteDcrClient(req.params.id, trace);
    s().registrations = s().registrations.filter((x) => x.clientId !== req.params.id);
    res.json({ trace: trace.toJSON() });
  }));

  // ② Gateway resource policy
  r.get('/api/gateway/policy', wrap(async (_req, res) => {
    res.json({ policy: await p().getGatewayPolicy(), gatewayArn: p().gatewayArn });
  }));

  r.put('/api/gateway/policy', wrap(async (req, res) => {
    const trace = new Trace('Gateway にリソースポリシーを適用');
    let policy = req.body.policy;
    if (typeof policy === 'string') {
      try {
        policy = JSON.parse(policy);
      } catch (err) {
        throw Object.assign(new Error(`ポリシーの JSON が不正です: ${err.message}`), { status: 400 });
      }
    }
    if (!policy || !Array.isArray(policy.Statement)) throw Object.assign(new Error('Statement 配列が必要です'), { status: 400 });
    await p().putGatewayPolicy(policy, trace);
    if (!policy.Statement.some((st) => st.Effect === 'Allow')) trace.note('warn', 'Allow 文がありません。条件に当たらない呼び出しも含めて全部 403 になります');
    if (mode === 'aws') trace.note('info', 'ポリシーの反映には数秒〜数十秒かかることがあります');
    res.json({ trace: trace.toJSON() });
  }));

  r.delete('/api/gateway/policy', wrap(async (_req, res) => {
    const trace = new Trace('Gateway のリソースポリシーを削除');
    await p().deleteGatewayPolicy(trace);
    res.json({ trace: trace.toJSON() });
  }));

  const invokeGateway = async (trace, w, method = 'tools/list') => {
    const r2 = await trace.fetch(`Gateway を呼び出し（${w.label}）`, p().endpoints.gateway, {
      method: 'POST',
      headers: { Authorization: `Bearer ${w.accessToken}`, Accept: 'application/json, text/event-stream' },
      json: { jsonrpc: '2.0', id: 1, method, params: {} },
    });
    return r2;
  };

  r.post('/api/gateway/invoke', wrap(async (req, res) => {
    const w = findWallet(req.body.walletId);
    const trace = new Trace(`Gateway 呼び出し: ${w.label}`);
    const r2 = await invokeGateway(trace, w);
    trace.note(r2.status === 200 ? 'ok' : 'error', `HTTP ${r2.status}`);
    res.json({ traceId: saveTrace(trace), trace: trace.toJSON(), status: r2.status });
  }));

  r.post('/api/gateway/matrix', wrap(async (_req, res) => {
    const trace = new Trace('ログイン済みの全クライアントから Gateway を呼び出し');
    const rows = [];
    for (const w of s().wallet.filter((x) => ['cimd', 'dcr'].includes(x.kind))) {
      const r2 = await invokeGateway(trace, w);
      const ev = r2.body?._demo;
      rows.push({
        walletId: w.id,
        label: w.label,
        kind: w.kind,
        clientId: decodeToken(w.accessToken)?.payload?.client_id,
        status: r2.status,
        decision: ev?.decision ?? null,
        decidedBy: ev?.decidedBy ?? null,
        message: r2.status === 200 ? 'OK' : r2.body?.message ?? r2.body?.error ?? '',
      });
    }
    if (!rows.length) trace.note('info', 'ログイン済みのトークンがありません。タブ①でログインしてください');
    res.json({ traceId: saveTrace(trace), trace: trace.toJSON(), rows });
  }));

  // ③ Token exchange
    const callBackend = (trace, title, token, op) =>
    trace.fetch(title, `${BASE_URL}/backend/orders`, { method: op === 'write' ? 'POST' : 'GET', headers: { Authorization: `Bearer ${token}` }, ...(op === 'write' ? { json: { item: 'demo' } } : {}) });

  r.post('/api/exchange/forward', wrap(async (req, res) => {
    const w = findWallet(req.body.walletId);
    const op = req.body.op === 'write' ? 'write' : 'read';
    const trace = new Trace('Before: ユーザーのトークンをそのまま後段 API に転送');
    trace.tokens('転送するトークン（ユーザーがログインで得たもの）', { access_token: w.accessToken });
    const r2 = await callBackend(trace, `後段 API を呼び出し（${op}）`, w.accessToken, op);
    for (const n of r2.body?.analysis ?? []) trace.note(n.level, n.text);
    res.json({ traceId: saveTrace(trace), trace: trace.toJSON() });
  }));

  async function getActorToken(trace) {
    const { id, secret } = p().clients.mcpServer;
    const r2 = await trace.fetch('MCP サーバー自身のトークンを取得（actor_token 用, client_credentials）', p().endpoints.token, {
      method: 'POST',
      headers: { Authorization: basic(id, secret) },
      form: { grant_type: 'client_credentials', scope: SCOPES.mcpInvoke },
    });
    if (!r2.ok) throw Object.assign(new Error(`actor トークンを取得できません: ${r2.body?.error ?? r2.status}`), { status: 502 });
    return r2.body.access_token;
  }

  r.post('/api/exchange/exchange', wrap(async (req, res) => {
    const w = findWallet(req.body.walletId);
    const scope = String(req.body.scope ?? SCOPES.backendRead).trim();
    const audience = String(req.body.audience ?? RESOURCE_SERVERS.backend.identifier);
    const withActor = req.body.withActor !== false;
    const trace = new Trace(`After: トークン交換（${withActor ? '委任 delegation' : 'なりすまし impersonation'}）`);
    const actorToken = withActor ? await getActorToken(trace) : null;
    const { id, secret } = p().clients.mcpServer;
    const form = { grant_type: TOKEN_EXCHANGE_GRANT, subject_token: w.accessToken, subject_token_type: ACCESS_TOKEN_TYPE, audience, scope };
    if (actorToken) Object.assign(form, { actor_token: actorToken, actor_token_type: ACCESS_TOKEN_TYPE });
    const r2 = await trace.fetch('トークン交換（RFC 8693, grant_type=token-exchange）', p().endpoints.token, { method: 'POST', headers: { Authorization: basic(id, secret) }, form });
    let item = null;
    if (r2.ok) {
      const before = decodeToken(w.accessToken)?.payload ?? {};
      const after = decodeToken(r2.body.access_token)?.payload ?? {};
      const beforeScopes = String(before.scope ?? '').split(' ').filter(Boolean);
      const afterScopes = String(after.scope ?? '').split(' ').filter(Boolean);
      const dropped = scope.split(' ').filter((x) => x && !afterScopes.includes(x));
      trace.note('ok', `スコープ: ${beforeScopes.length} 個 → ${afterScopes.length} 個（${afterScopes.join(', ')}）`);
      trace.note('ok', `aud: ${before.aud ?? '（なし）'} → ${[].concat(after.aud ?? '（なし）').join(', ')}`);
      if (after.act) trace.note('ok', `act.sub = ${after.act.sub}（中継した MCP サーバー）`);
      else trace.note('info', 'act クレームなし（なりすまし: ユーザー本人の呼び出しに見えます）');
      trace.note(r2.body.refresh_token ? 'warn' : 'ok', r2.body.refresh_token ? 'リフレッシュトークンが返されました' : 'リフレッシュトークンは返されません');
      if (dropped.length) trace.note('warn', `元のトークンにないスコープは付与されませんでした: ${dropped.join(', ')}`);
      item = addToWallet({ label: `交換後トークン（${afterScopes.join(' ')}）`, kind: 'exchanged', clientId: after.client_id, accessToken: r2.body.access_token });
    } else {
      trace.note('error', `交換に失敗しました: HTTP ${r2.status} ${r2.body?.error ?? ''}`);
      if (r2.body?.error === 'invalid_scope') trace.note('info', 'スコープを広げる交換は断られます');
    }
    res.json({ traceId: saveTrace(trace), trace: trace.toJSON(), walletId: item?.id ?? null });
  }));

  r.post('/api/backend/call', wrap(async (req, res) => {
    const w = findWallet(req.body.walletId);
    const op = req.body.op === 'write' ? 'write' : 'read';
    const trace = new Trace(`後段 API を呼び出し（${op}）: ${w.label}`);
    const r2 = await callBackend(trace, `後段 API（${op === 'write' ? 'POST' : 'GET'} /orders）`, w.accessToken, op);
    for (const n of r2.body?.analysis ?? []) trace.note(n.level, n.text);
    if (r2.status === 403) trace.note('error', `${r2.body?.error_description ?? '権限が足りません'}`);
    res.json({ traceId: saveTrace(trace), trace: trace.toJSON() });
  }));

  r.currentMode = () => mode;
  return r;
}
