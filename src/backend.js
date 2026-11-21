import express from 'express';
import { jwtVerify } from 'jose';
import { RESOURCE_SERVERS, SCOPES } from './config.js';

const AUDIENCE = RESOURCE_SERVERS.backend.identifier;

function analyze(claims, requiredScope) {
  const notes = [];
  const scopes = String(claims.scope ?? '').split(' ').filter(Boolean);
  const extra = scopes.filter((s) => s !== requiredScope);
  if (extra.length) {
    notes.push({ level: 'warn', text: `この操作に必要なのは ${requiredScope} だけですが、ほかに ${extra.length} 個のスコープ（${extra.join(', ')}）も受け取りました` });
  } else {
    notes.push({ level: 'ok', text: `必要なスコープ（${requiredScope}）だけを受け取りました` });
  }
  const aud = claims.aud === undefined ? [] : [].concat(claims.aud);
  if (!aud.length) notes.push({ level: 'warn', text: 'aud がありません。どの API 宛てのトークンか分かりません' });
  else notes.push({ level: 'ok', text: `aud=${aud.join(', ')}（この API 宛て）` });
  if (claims.act) notes.push({ level: 'ok', text: `act.sub=${claims.act.sub} がユーザーの代理で呼び出しています` });
  else notes.push({ level: 'info', text: 'act がないので、ユーザー本人の呼び出しか、中継者の呼び出しかを区別できません' });
  return notes;
}

export function createBackendRouter(getVerifier) {
  const r = express.Router();
  const handle = (requiredScope, action) => async (req, res) => {
    const auth = req.headers.authorization ?? '';
    if (!auth.startsWith('Bearer ')) return res.status(401).json({ error: 'invalid_token', error_description: 'Bearer トークンがありません' });
    const { jwks, issuer } = getVerifier();
    let claims;
    try {
      ({ payload: claims } = await jwtVerify(auth.slice(7), jwks, { issuer }));
    } catch (err) {
      return res.status(401).json({ error: 'invalid_token', error_description: `検証に失敗しました: ${err.code ?? err.message}` });
    }
    if (claims.token_use !== 'access') return res.status(401).json({ error: 'invalid_token', error_description: 'アクセストークンではありません' });
    const aud = claims.aud === undefined ? [] : [].concat(claims.aud);
    if (aud.length && !aud.includes(AUDIENCE)) {
      return res.status(401).json({ error: 'invalid_token', error_description: `aud=${aud.join(',')} はこの API（${AUDIENCE}）宛てではありません` });
    }
    const received = { sub: claims.sub, client_id: claims.client_id, aud: claims.aud ?? null, scope: claims.scope, act: claims.act ?? null };
    const analysis = analyze(claims, requiredScope);
    if (!String(claims.scope ?? '').split(' ').includes(requiredScope)) {
      return res.status(403).json({ error: 'insufficient_scope', error_description: `${requiredScope} が必要です`, received, analysis });
    }
    res.json({ ok: true, action, data: action === 'read' ? [{ orderId: 'ORD-1001', status: '発送済み' }, { orderId: 'ORD-1002', status: '準備中' }] : { orderId: 'ORD-1003', status: '作成済み' }, received, analysis });
  };
  r.get('/orders', handle(SCOPES.backendRead, 'read'));
  r.post('/orders', handle(SCOPES.backendWrite, 'write'));
  return r;
}
