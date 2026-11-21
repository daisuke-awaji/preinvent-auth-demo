import { decodeJwt, decodeProtectedHeader } from 'jose';

const JWT_RE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;

export const shorten = (token) => (typeof token === 'string' && token.length > 40 ? `${token.slice(0, 24)}…${token.slice(-8)}` : token);

export function decodeToken(token) {
  if (typeof token !== 'string' || !JWT_RE.test(token)) return null;
  try {
    return { header: decodeProtectedHeader(token), payload: decodeJwt(token) };
  } catch {
    return null;
  }
}

const SECRET_KEYS = new Set(['client_secret', 'password']);
const TOKEN_KEYS = new Set(['subject_token', 'actor_token', 'access_token', 'id_token', 'refresh_token', 'code', 'code_verifier']);

function redactValue(key, value) {
  if (SECRET_KEYS.has(key)) return '********';
  if (TOKEN_KEYS.has(key)) return shorten(value);
  return value;
}

function redactBody(body) {
  if (!body) return body;
  if (body instanceof URLSearchParams) {
    return Object.fromEntries([...body.entries()].map(([k, v]) => [k, redactValue(k, v)]));
  }
  if (typeof body === 'object') {
    return Object.fromEntries(Object.entries(body).map(([k, v]) => [k, redactValue(k, v)]));
  }
  return body;
}

function redactHeaders(headers = {}) {
  const out = {};
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === 'authorization') {
      const [scheme, cred] = String(v).split(' ');
      out[k] = scheme === 'Basic' ? 'Basic ********' : `${scheme} ${shorten(cred)}`;
    } else out[k] = v;
  }
  return out;
}

export class Trace {
  constructor(title) {
    this.title = title;
    this.steps = [];
    this.notes = [];
  }

  note(level, text) {
    this.notes.push({ level, text });
    return this;
  }

  tokens(label, tokenMap) {
    const decoded = {};
    for (const [k, v] of Object.entries(tokenMap)) {
      const d = decodeToken(v);
      if (d) decoded[k] = d;
    }
    this.steps.push({ kind: 'tokens', title: label, decoded });
  }

  async fetch(title, url, { method = 'GET', headers = {}, body, form, json } = {}) {
    const reqHeaders = { ...headers };
    let payload = body;
    let shownBody;
    if (form) {
      payload = new URLSearchParams(form);
      reqHeaders['Content-Type'] = 'application/x-www-form-urlencoded';
      shownBody = redactBody(payload);
    } else if (json !== undefined) {
      payload = JSON.stringify(json);
      reqHeaders['Content-Type'] = 'application/json';
      shownBody = redactBody(json);
    }
    const step = { kind: 'http', title, request: { method, url, headers: redactHeaders(reqHeaders), body: shownBody } };
    this.steps.push(step);
    const started = Date.now();
    try {
      const res = await fetch(url, { method, headers: reqHeaders, body: payload, redirect: 'manual' });
      const text = await res.text();
      let parsed = text;
      try {
        parsed = text ? JSON.parse(text) : null;
      } catch {
        parsed = text.length > 600 ? `${text.slice(0, 600)}…（${text.length} 文字, 省略）` : text;
      }
      step.response = { status: res.status, ms: Date.now() - started, body: parsed, location: res.headers.get('location') ?? undefined };
      const wwwAuth = res.headers.get('www-authenticate');
      if (wwwAuth) step.response.wwwAuthenticate = wwwAuth;
      const tokenFields = typeof parsed === 'object' && parsed ? ['access_token', 'id_token'].filter((k) => parsed[k]) : [];
      if (tokenFields.length) {
        step.decoded = Object.fromEntries(tokenFields.map((k) => [k, decodeToken(parsed[k])]));
        step.response.body = redactBody(parsed);
      }
      return { status: res.status, ok: res.ok, body: parsed, headers: res.headers };
    } catch (err) {
      step.response = { status: 0, ms: Date.now() - started, body: { error: 'network_error', message: err.message } };
      return { status: 0, ok: false, body: step.response.body };
    }
  }

  sdk(title, operation, input, output, error) {
    this.steps.push({
      kind: 'sdk',
      title,
      request: { method: 'SDK', url: operation, body: redactBody(input) },
      response: error
        ? { status: error.$metadata?.httpStatusCode ?? 'error', body: { name: error.name, message: error.message } }
        : { status: output?.$metadata?.httpStatusCode ?? 200, body: stripMetadata(output) },
    });
  }

  toJSON() {
    return { title: this.title, steps: this.steps, notes: this.notes };
  }
}

function stripMetadata(o) {
  if (!o || typeof o !== 'object') return o;
  const { $metadata, ...rest } = o;
  return rest;
}
