import { createHash, randomUUID } from 'node:crypto';
import express from 'express';
import { jwks, randomId, signToken, verifyToken } from './keys.js';
import { BASE_URL, RESOURCE_SERVERS, SCOPES } from '../config.js';

export const MOCK_PREFIX = '/mock/cognito';
export const MOCK_ISSUER = `${BASE_URL}${MOCK_PREFIX}`;
export const MOCK_GATEWAY_ARN = 'arn:aws:bedrock-agentcore:ap-northeast-1:111122223333:gateway/mock-demo-gw';

const TOKEN_EXCHANGE_GRANT = 'urn:ietf:params:oauth:grant-type:token-exchange';
const TOKEN_TYPE = {
  'urn:ietf:params:oauth:token-type:access_token': 'access',
  'urn:ietf:params:oauth:token-type:id_token': 'id',
};
const STANDARD_SCOPES = new Set(['openid', 'email', 'phone', 'profile']);
const RS_IDS = new Set(Object.values(RESOURCE_SERVERS).map((r) => r.identifier));
const ALL_CUSTOM_SCOPES = Object.values(RESOURCE_SERVERS).flatMap((r) => r.scopes.map((s) => `${r.identifier}/${s}`));

export const MOCK_CLIENTS = {
  cimdBase: 'mock-cimd-base',
  registrar: 'mock-dcr-registrar',
  mcpServer: 'mock-mcp-server',
};

let state;

function freshState() {
  return {
    users: new Map([['demo', { sub: 'a1b2c3d4-5678-90ab-cdef-000000000001', username: 'demo', password: 'Passw0rd!', email: 'demo@example.com' }]]),
    clients: new Map(
      [
        {
          ClientId: MOCK_CLIENTS.cimdBase,
          ClientName: 'cimd-base（CIMDポリシーの割り当て先）',
          ClientType: 'REGULAR',
          AllowedOAuthFlows: ['code'],
          AllowedOAuthScopes: ['openid', 'email', SCOPES.mcpInvoke, SCOPES.backendRead, SCOPES.backendWrite],
          CallbackURLs: [],
        },
        {
          ClientId: MOCK_CLIENTS.registrar,
          ClientSecret: 'mock-registrar-secret',
          ClientName: 'dcr-registrar（初期アクセストークン発行用）',
          ClientType: 'REGULAR',
          AllowedOAuthFlows: ['client_credentials'],
          AllowedOAuthScopes: [SCOPES.dcrRegister],
        },
        {
          ClientId: MOCK_CLIENTS.mcpServer,
          ClientSecret: 'mock-mcp-server-secret',
          ClientName: 'mcp-server（トークン交換を行う中継役）',
          ClientType: 'REGULAR',
          AllowedOAuthFlows: ['client_credentials'],
          AllowedOAuthScopes: [SCOPES.mcpInvoke, SCOPES.backendRead, SCOPES.backendWrite, SCOPES.backendAdmin],
          ExplicitAuthFlows: ['ALLOW_TOKEN_EXCHANGE_DELEGATION', 'ALLOW_TOKEN_EXCHANGE_IMPERSONATION'],
        },
      ].map((c) => [c.ClientId, c]),
    ),
    cimdPolicy: {
      CIMDPolicyId: 'mock-cimd-policy',
      PolicyName: 'trusted-ai-clients',
      ClientId: MOCK_CLIENTS.cimdBase,
      URLPatterns: [`${BASE_URL}/cimd/trusted/*`],
      CacheDuration: 300,
    },
    metadataUrls: new Map(),
    dcr: {
      EnableStatus: 'ENABLED',
      OpenDcrEnabled: true,
      OpenDcrGrantTypes: ['code'],
      AuthenticatedGrantTypes: ['code', 'client_credentials'],
      AllowedScopes: ALL_CUSTOM_SCOPES.filter((s) => s !== SCOPES.backendAdmin),
    },
    codes: new Map(),
    transactions: new Map(),
  };
}
state = freshState();

const wildcard = (p) => new RegExp(`^${p.replace(/[.+^${}()|[\]\\?]/g, '\\$&').replace(/\*/g, '.*')}$`);
const isLoopback = (u) => ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);

function redirectUriAllowed(registered, requested) {
  let req;
  try {
    req = new URL(requested);
  } catch {
    return false;
  }
  return registered.some((r) => {
    if (r === requested) return true;
    const reg = new URL(r);
    return isLoopback(reg) && isLoopback(req) && reg.protocol === 'http:' && reg.hostname === req.hostname && reg.pathname === req.pathname;
  });
}

async function resolveCimdClient(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return { error: 'invalid_client', description: 'client_id が URL として不正です' };
  }
  const record = (status) => {
    const prev = state.metadataUrls.get(url);
    state.metadataUrls.set(url, { URL: url, FirstSeen: prev?.FirstSeen ?? new Date().toISOString(), LastSeen: new Date().toISOString(), LastResult: status });
  };
  if (parsed.protocol !== 'https:' && !isLoopback(parsed)) {
    record('REJECTED_SCHEME');
    return { error: 'invalid_client', description: 'CIMD の client_id は HTTPS の URL である必要があります' };
  }
  const policy = state.cimdPolicy;
  if (!policy || !policy.URLPatterns.some((p) => wildcard(p).test(url))) {
    record('NO_MATCHING_POLICY');
    return { error: 'unauthorized_client', description: 'この URL に一致する CIMD ポリシーがありません（許可していないクライアント）' };
  }
  let doc;
  try {
    const res = await fetch(url, { headers: { Accept: 'application/json' } });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    doc = await res.json();
  } catch (err) {
    record('FETCH_FAILED');
    return { error: 'invalid_client', description: `メタデータドキュメントを取得できません: ${err.message}` };
  }
  if (doc.client_id !== url) {
    record('CLIENT_ID_MISMATCH');
    return { error: 'invalid_client', description: 'ドキュメント内の client_id が URL と一致しません' };
  }
  if (doc.token_endpoint_auth_method && doc.token_endpoint_auth_method !== 'none') {
    record('INVALID_AUTH_METHOD');
    return { error: 'invalid_client', description: 'CIMD クライアントは公開クライアント（none）である必要があります' };
  }
  record('ACCEPTED');
  const base = state.clients.get(policy.ClientId);
  const docScopes = (doc.scope ?? 'openid').split(' ').filter(Boolean);
  return {
    client: {
      ClientId: url,
      ClientName: doc.client_name ?? url,
      ClientType: 'CIMD',
      Public: true,
      CallbackURLs: doc.redirect_uris ?? [],
      AllowedOAuthFlows: base.AllowedOAuthFlows,
      AllowedOAuthScopes: base.AllowedOAuthScopes.filter((s) => docScopes.includes(s)),
      MappedAppClient: base.ClientId,
      metadata: doc,
    },
  };
}

async function resolveClient(clientId) {
  if (/^https?:\/\//.test(clientId ?? '')) return resolveCimdClient(clientId);
  const client = state.clients.get(clientId);
  if (!client) return { error: 'invalid_client', description: '不明な client_id です' };
  return { client };
}

function oauthError(res, status, error, description) {
  return res.status(status).json({ error, error_description: description });
}

function authenticateClient(req) {
  const h = req.headers.authorization;
  if (h?.startsWith('Basic ')) {
    const [id, secret] = Buffer.from(h.slice(6), 'base64').toString().split(':').map(decodeURIComponent);
    return { id, secret };
  }
  return { id: req.body.client_id, secret: req.body.client_secret };
}

async function issueUserTokens({ user, client, scopes, resource, withRefresh = true }) {
  const access = await signToken({
    sub: user.sub,
    iss: MOCK_ISSUER,
    client_id: client.ClientId,
    origin_jti: randomUUID(),
    token_use: 'access',
    scope: scopes.join(' '),
    auth_time: Math.floor(Date.now() / 1000),
    username: user.username,
    ...(resource ? { aud: resource } : {}),
  });
  const out = { access_token: access, token_type: 'Bearer', expires_in: 3600 };
  if (scopes.includes('openid')) {
    out.id_token = await signToken({ sub: user.sub, iss: MOCK_ISSUER, aud: client.ClientId, token_use: 'id', email: user.email, 'cognito:username': user.username });
  }
  if (withRefresh) out.refresh_token = `mock-refresh-${randomId(24)}`;
  return out;
}

class Raw {
  constructor(value) {
    this.value = value;
  }
}
const escape = (v) => (v instanceof Raw ? v.value : String(v).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`));
const html = (strings, ...values) => strings.reduce((acc, s, i) => acc + s + (i < values.length ? escape(values[i]) : ''), '');
const raw = (value) => new Raw(value);

function errorPage(res, error, description) {
  res.status(400).send(html`<!doctype html><meta charset="utf-8"><title>エラー</title>
<link rel="stylesheet" href="${raw(`${BASE_URL}/mock-login.css`)}"><main class="card"><div class="brand">模擬 Cognito マネージドログイン</div>
<h1 class="err">${error}</h1><p>${description}</p><p class="hint">リダイレクトせずにエラーを表示しています（client_id か redirect_uri が信頼できないため）。</p>
<script>window.opener&&window.opener.postMessage({type:'login-error',error:${raw(JSON.stringify(error).replace(/</g, '\\u003c'))},description:${raw(JSON.stringify(description).replace(/</g, '\\u003c'))}},location.origin)</script></main>`);
}

function redirectError(res, redirectUri, stateParam, error, description) {
  const u = new URL(redirectUri);
  u.searchParams.set('error', error);
  u.searchParams.set('error_description', description);
  if (stateParam) u.searchParams.set('state', stateParam);
  res.redirect(302, u.toString());
}

export function createMockCognitoRouter() {
  const r = express.Router();
  r.use(express.urlencoded({ extended: false }));
  r.use(express.json());

  const discovery = (_req, res) =>
    res.json({
      issuer: MOCK_ISSUER,
      authorization_endpoint: `${MOCK_ISSUER}/oauth2/authorize`,
      token_endpoint: `${MOCK_ISSUER}/oauth2/token`,
      jwks_uri: `${MOCK_ISSUER}/.well-known/jwks.json`,
      ...(state.dcr.EnableStatus === 'ENABLED' ? { registration_endpoint: `${MOCK_ISSUER}/oauth2/register` } : {}),
      client_id_metadata_document_supported: true,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'client_credentials', 'refresh_token', TOKEN_EXCHANGE_GRANT],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
      scopes_supported: ['openid', 'email', ...ALL_CUSTOM_SCOPES],
    });
  r.get('/.well-known/openid-configuration', discovery);
  r.get('/.well-known/oauth-authorization-server', discovery);
  r.get('/.well-known/jwks.json', (_req, res) => res.json(jwks));

  r.get('/oauth2/authorize', async (req, res) => {
    const q = req.query;
    const { client, error, description } = await resolveClient(q.client_id);
    if (error) return errorPage(res, error, description);
    if (!q.redirect_uri || !redirectUriAllowed(client.CallbackURLs ?? [], q.redirect_uri)) {
      return errorPage(res, 'invalid_request', 'redirect_uri がクライアントに登録されていません');
    }
    if (q.response_type !== 'code' || !client.AllowedOAuthFlows.includes('code')) {
      return redirectError(res, q.redirect_uri, q.state, 'unauthorized_client', 'このクライアントは認可コードフローを使えません');
    }
    if (client.Public && (!q.code_challenge || q.code_challenge_method !== 'S256')) {
      return redirectError(res, q.redirect_uri, q.state, 'invalid_request', '公開クライアントは PKCE（S256）が必須です');
    }
    const scopes = String(q.scope ?? 'openid').split(' ').filter(Boolean);
    const notAllowed = scopes.filter((s) => !client.AllowedOAuthScopes.includes(s));
    if (notAllowed.length) {
      return redirectError(res, q.redirect_uri, q.state, 'invalid_scope', `許可されていないスコープ: ${notAllowed.join(' ')}`);
    }
    if (q.resource && !RS_IDS.has(q.resource)) {
      return redirectError(res, q.redirect_uri, q.state, 'invalid_target', 'resource がリソースサーバーに一致しません');
    }
    const txn = randomId(16);
    state.transactions.set(txn, { client, scopes, redirectUri: q.redirect_uri, state: q.state, codeChallenge: q.code_challenge, resource: q.resource });
    const kind = { CIMD: 'CIMD（URL をクライアント ID として使用）', DCR: '動的クライアント登録（DCR）', REGULAR: '事前登録したアプリクライアント' }[client.ClientType];
    res.send(html`<!doctype html><meta charset="utf-8"><title>サインイン</title>
<link rel="stylesheet" href="${raw(`${BASE_URL}/mock-login.css`)}"><main class="card"><div class="brand">模擬 Cognito マネージドログイン</div>
<h1>サインイン</h1>
<div class="client"><b>${client.ClientName}</b> がアクセスを求めています
<dl><dt>種類</dt><dd>${kind}</dd><dt>client_id</dt><dd class="mono">${client.ClientId}</dd>${raw(client.MappedAppClient ? html`<dt>割り当て先</dt><dd class="mono">${client.MappedAppClient}</dd>` : '')}<dt>スコープ</dt><dd class="mono">${scopes.join(' ')}</dd></dl></div>
<form method="post" action="${MOCK_ISSUER}/login"><input type="hidden" name="txn" value="${txn}">
<label>ユーザー名<input name="username" value="demo" autocomplete="off"></label>
<label>パスワード<input name="password" type="password" value="Passw0rd!"></label>
<button type="submit">サインイン</button></form></main>`);
  });

  r.post('/login', (req, res) => {
    const txn = state.transactions.get(req.body.txn);
    if (!txn) return errorPage(res, 'invalid_request', 'サインインのセッションが見つかりません');
    const user = state.users.get(req.body.username);
    if (!user || user.password !== req.body.password) return errorPage(res, 'access_denied', 'ユーザー名またはパスワードが違います');
    state.transactions.delete(req.body.txn);
    const code = randomId(20);
    state.codes.set(code, { ...txn, user, expiresAt: Date.now() + 5 * 60 * 1000 });
    const u = new URL(txn.redirectUri);
    u.searchParams.set('code', code);
    if (txn.state) u.searchParams.set('state', txn.state);
    res.redirect(302, u.toString());
  });

  r.post('/oauth2/token', async (req, res) => {
    const grant = req.body.grant_type;
    const { id, secret } = authenticateClient(req);
    if (grant === 'authorization_code') return tokenFromCode(req, res, id, secret);
    if (grant === 'client_credentials') return tokenFromClientCredentials(req, res, id, secret);
    if (grant === TOKEN_EXCHANGE_GRANT) return tokenExchange(req, res, id, secret);
    return oauthError(res, 400, 'unsupported_grant_type', `未対応の grant_type: ${grant}`);
  });

  r.post('/oauth2/register', express.json({ type: '*/*' }), async (req, res) => {
    if (state.dcr.EnableStatus !== 'ENABLED') return res.status(404).json({ error: 'not_found' });
    const auth = req.headers.authorization;
    let mode = 'open';
    if (auth?.startsWith('Bearer ')) {
      try {
        const claims = await verifyToken(auth.slice(7), MOCK_ISSUER);
        if (!String(claims.scope ?? '').split(' ').includes(SCOPES.dcrRegister)) throw new Error('scope');
        mode = 'authenticated';
      } catch {
        return oauthError(res, 401, 'invalid_token', '初期アクセストークンが無効です');
      }
    } else if (!state.dcr.OpenDcrEnabled) {
      return oauthError(res, 401, 'invalid_token', 'オープン登録は無効です。初期アクセストークンが必要です');
    }
    const body = req.body ?? {};
    const grantTypes = body.grant_types ?? ['authorization_code'];
    if (grantTypes.includes('authorization_code') && grantTypes.includes('client_credentials')) {
      return oauthError(res, 400, 'invalid_client_metadata', 'authorization_code と client_credentials は同時に指定できません');
    }
    const flow = grantTypes.includes('client_credentials') ? 'client_credentials' : 'code';
    const permitted = mode === 'open' ? state.dcr.OpenDcrGrantTypes : state.dcr.AuthenticatedGrantTypes;
    if (!permitted.includes(flow)) {
      return oauthError(res, 400, 'invalid_client_metadata', `${mode === 'open' ? 'オープン' : '認証済み'}登録では ${grantTypes[0]} を使えません`);
    }
    const redirectUris = body.redirect_uris ?? [];
    if (flow === 'code') {
      if (!redirectUris.length) return oauthError(res, 400, 'invalid_redirect_uri', 'redirect_uris が必要です');
      const bad = redirectUris.find((u) => {
        try {
          const p = new URL(u);
          return !(p.protocol === 'https:' || (p.protocol === 'http:' && isLoopback(p)));
        } catch {
          return true;
        }
      });
      if (bad) return oauthError(res, 400, 'invalid_redirect_uri', `http はループバックのみ許可: ${bad}`);
    }
    const scopes = String(body.scope ?? (flow === 'code' ? 'openid' : '')).split(' ').filter(Boolean);
    const notAllowed = scopes.filter((s) => !STANDARD_SCOPES.has(s) && !state.dcr.AllowedScopes.includes(s));
    if (notAllowed.length) return oauthError(res, 400, 'invalid_client_metadata', `許可されていないスコープ: ${notAllowed.join(' ')}`);
    const method = body.token_endpoint_auth_method ?? 'client_secret_basic';
    if (!['none', 'client_secret_basic', 'client_secret_post'].includes(method)) {
      return oauthError(res, 400, 'invalid_client_metadata', `未対応の token_endpoint_auth_method: ${method}`);
    }
    const clientId = `dcr_${randomId(13)}`;
    const client = {
      ClientId: clientId,
      ClientName: body.client_name ?? clientId,
      ClientType: 'DCR',
      Public: method === 'none',
      ClientSecret: method === 'none' ? undefined : randomId(32),
      CallbackURLs: redirectUris,
      AllowedOAuthFlows: [flow],
      AllowedOAuthScopes: scopes,
      RegisteredVia: mode,
      CreationDate: new Date().toISOString(),
    };
    state.clients.set(clientId, client);
    res.status(201).json({
      client_id: clientId,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      client_name: client.ClientName,
      redirect_uris: redirectUris,
      grant_types: grantTypes,
      response_types: flow === 'code' ? ['code'] : [],
      scope: scopes.join(' '),
      token_endpoint_auth_method: method,
      ...(client.ClientSecret ? { client_secret: client.ClientSecret, client_secret_expires_at: 0 } : {}),
    });
  });

  return r;
}

async function tokenFromCode(req, res, id, secret) {
  const rec = state.codes.get(req.body.code);
  if (!rec || rec.expiresAt < Date.now()) return oauthError(res, 400, 'invalid_grant', '認可コードが無効または期限切れです');
  state.codes.delete(req.body.code);
  if (rec.client.ClientId !== id) return oauthError(res, 400, 'invalid_grant', 'client_id が認可リクエストと一致しません');
  if (!rec.client.Public && rec.client.ClientSecret !== secret) return oauthError(res, 401, 'invalid_client', 'クライアント認証に失敗しました');
  if (rec.redirectUri !== req.body.redirect_uri) return oauthError(res, 400, 'invalid_grant', 'redirect_uri が一致しません');
  if (rec.codeChallenge) {
    const expected = createHash('sha256').update(String(req.body.code_verifier ?? '')).digest('base64url');
    if (expected !== rec.codeChallenge) return oauthError(res, 400, 'invalid_grant', 'PKCE の検証に失敗しました');
  }
  res.json(await issueUserTokens({ user: rec.user, client: rec.client, scopes: rec.scopes, resource: rec.resource }));
}

async function tokenFromClientCredentials(req, res, id, secret) {
  const client = state.clients.get(id);
  if (!client || !client.ClientSecret || client.ClientSecret !== secret) return oauthError(res, 401, 'invalid_client', 'クライアント認証に失敗しました');
  if (!client.AllowedOAuthFlows.includes('client_credentials')) return oauthError(res, 400, 'unauthorized_client', 'client_credentials は許可されていません');
  const requested = String(req.body.scope ?? client.AllowedOAuthScopes.join(' ')).split(' ').filter(Boolean);
  const bad = requested.filter((s) => !client.AllowedOAuthScopes.includes(s));
  if (bad.length) return oauthError(res, 400, 'invalid_scope', `許可されていないスコープ: ${bad.join(' ')}`);
  const access = await signToken({ sub: client.ClientId, iss: MOCK_ISSUER, client_id: client.ClientId, token_use: 'access', scope: requested.join(' ') });
  res.json({ access_token: access, token_type: 'Bearer', expires_in: 3600 });
}

async function tokenExchange(req, res, id, secret) {
  const client = state.clients.get(id);
  if (!client || !client.ClientSecret || client.ClientSecret !== secret) return oauthError(res, 401, 'invalid_client', 'クライアント認証に失敗しました');
  const b = req.body;
  const delegation = Boolean(b.actor_token);
  const flow = delegation ? 'ALLOW_TOKEN_EXCHANGE_DELEGATION' : 'ALLOW_TOKEN_EXCHANGE_IMPERSONATION';
  if (!(client.ExplicitAuthFlows ?? []).includes(flow)) return oauthError(res, 400, 'unauthorized_client', `アプリクライアントに ${flow} がありません`);
  if (!TOKEN_TYPE[b.subject_token_type]) return oauthError(res, 400, 'invalid_request', 'subject_token_type が不正です');
  let subject;
  let actor;
  try {
    subject = await verifyToken(b.subject_token, MOCK_ISSUER);
  } catch (err) {
    return oauthError(res, 400, 'invalid_grant', `subject_token を検証できません: ${err.code ?? err.message}`);
  }
  if (delegation) {
    if (!TOKEN_TYPE[b.actor_token_type]) return oauthError(res, 400, 'invalid_request', 'actor_token_type が不正です');
    try {
      actor = await verifyToken(b.actor_token, MOCK_ISSUER);
    } catch (err) {
      return oauthError(res, 400, 'invalid_grant', `actor_token を検証できません: ${err.code ?? err.message}`);
    }
  }
  const audience = b.audience ?? b.resource;
  if (!audience || !RS_IDS.has(audience)) return oauthError(res, 400, 'invalid_target', 'audience が登録済みのリソースサーバーに一致しません');
  const subjectScopes = String(subject.scope ?? '').split(' ').filter(Boolean);
  const allowed = subjectScopes.filter((s) => client.AllowedOAuthScopes.includes(s) && s.startsWith(`${audience}/`));
  const requested = b.scope ? String(b.scope).split(' ').filter(Boolean) : allowed;
  const granted = requested.filter((s) => allowed.includes(s));
  if (!granted.length) {
    return oauthError(res, 400, 'invalid_scope', `要求したスコープ（${requested.join(' ')}）は元のトークンに含まれていません。スコープを広げる交換はできません`);
  }
  const now = Math.floor(Date.now() / 1000);
  const access = await signToken({
    sub: subject.sub,
    iss: MOCK_ISSUER,
    client_id: client.ClientId,
    token_use: 'access',
    scope: granted.join(' '),
    aud: audience,
    username: subject.username,
    ...(actor ? { act: { sub: actor.client_id ?? actor.sub } } : {}),
    exp: Math.min(now + 3600, subject.exp),
  });
  res.json({
    access_token: access,
    issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    token_type: 'Bearer',
    expires_in: Math.min(3600, subject.exp - now),
  });
}

export const mockCognitoAdmin = {
  describe() {
    return {
      issuer: MOCK_ISSUER,
      cimdPolicy: state.cimdPolicy,
      dcr: state.dcr,
      clients: [...state.clients.values()].map(({ ClientSecret, ...c }) => ({ ...c, HasSecret: Boolean(ClientSecret) })),
      metadataUrls: [...state.metadataUrls.values()],
    };
  },
  setOpenRegistration(enabled) {
    state.dcr.OpenDcrEnabled = Boolean(enabled);
    return state.dcr;
  },
  setCimdPatterns(patterns) {
    state.cimdPolicy.URLPatterns = patterns;
    return state.cimdPolicy;
  },
  listDcrClients() {
    return [...state.clients.values()].filter((c) => c.ClientType === 'DCR').map(({ ClientSecret, ...c }) => c);
  },
  deleteClient(clientId) {
    return state.clients.delete(clientId);
  },
  reset() {
    state = freshState();
  },
};
