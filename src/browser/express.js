const STATUS_TEXT = { 200: 'OK', 201: 'Created', 204: 'No Content', 302: 'Found', 400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found', 500: 'Internal Server Error' };

function compile(path, prefix) {
  const keys = [];
  const src = path
    .replace(/\/$/, '')
    .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
    .replace(/:(\w+)/g, (_, k) => {
      keys.push(k);
      return '([^/]+)';
    });
  return { keys, re: new RegExp(prefix ? `^${src}(?=/|$)` : `^${src}/?$`) };
}

class Router {
  constructor() {
    this.stack = [];
  }

  use(first, ...rest) {
    const [path, handlers] = typeof first === 'string' ? [first, rest] : ['', [first, ...rest]];
    for (const handler of handlers) this.stack.push({ prefix: compile(path, true), handler });
    return this;
  }

  route(method, path, handlers) {
    this.stack.push({ method, path: compile(path, false), handlers });
    return this;
  }

  get(path, ...h) {
    return this.route('GET', path, h);
  }

  post(path, ...h) {
    return this.route('POST', path, h);
  }

  put(path, ...h) {
    return this.route('PUT', path, h);
  }

  delete(path, ...h) {
    return this.route('DELETE', path, h);
  }

  async handle(req, res) {
    for (const layer of this.stack) {
      if (res.finished) return true;
      if (layer.prefix) {
        const m = layer.prefix.re.exec(req.path);
        if (!m) continue;
        if (layer.handler instanceof Router) {
          const saved = req.path;
          req.path = req.path.slice(m[0].length) || '/';
          const done = await layer.handler.handle(req, res);
          req.path = saved;
          if (done) return true;
          continue;
        }
        let nextCalled = false;
        await layer.handler(req, res, () => (nextCalled = true));
        if (!nextCalled && !res.finished) return true;
        continue;
      }
      if (layer.method !== req.method) continue;
      const m = layer.path.re.exec(req.path);
      if (!m) continue;
      req.params = Object.fromEntries(layer.path.keys.map((k, i) => [k, decodeURIComponent(m[i + 1])]));
      for (const h of layer.handlers) {
        let nextCalled = false;
        await h(req, res, () => (nextCalled = true));
        if (!nextCalled) break;
      }
      if (res.finished) return true;
    }
    return res.finished;
  }
}

class Res {
  constructor() {
    this.statusCode = 200;
    this.headers = new Headers();
    this.body = null;
    this.finished = false;
  }

  status(code) {
    this.statusCode = code;
    return this;
  }

  set(name, value) {
    if (typeof name === 'object') Object.entries(name).forEach(([k, v]) => this.headers.set(k, v));
    else this.headers.set(name, value);
    return this;
  }

  get(name) {
    return this.headers.get(name);
  }

  type(t) {
    return this.set('Content-Type', t);
  }

  json(obj) {
    if (!this.headers.has('Content-Type')) this.type('application/json; charset=utf-8');
    return this.end(JSON.stringify(obj));
  }

  send(body) {
    if (body !== null && typeof body === 'object') return this.json(body);
    if (!this.headers.has('Content-Type')) this.type('text/html; charset=utf-8');
    return this.end(String(body ?? ''));
  }

  redirect(a, b) {
    const [status, url] = typeof a === 'number' ? [a, b] : [302, a];
    this.status(status).set('Location', url);
    return this.end(null);
  }

  end(body = null) {
    this.body = body;
    this.finished = true;
    return this;
  }

  toResponse() {
    const nullBody = [204, 304].includes(this.statusCode) || (this.statusCode >= 300 && this.statusCode < 400);
    return new Response(nullBody ? null : this.body, { status: this.statusCode, statusText: STATUS_TEXT[this.statusCode] ?? '', headers: this.headers });
  }
}

function parseBody(text, contentType) {
  if (!text) return {};
  if (contentType.includes('application/x-www-form-urlencoded')) return Object.fromEntries(new URLSearchParams(text));
  try {
    return JSON.parse(text);
  } catch {
    return {};
  }
}

export async function dispatch(router, request, { stripPrefix = '' } = {}) {
  const url = new URL(request.url);
  const headers = Object.fromEntries([...request.headers].map(([k, v]) => [k.toLowerCase(), v]));
  const text = ['GET', 'HEAD'].includes(request.method) ? '' : await request.text();
  const path = stripPrefix && url.pathname.startsWith(stripPrefix) ? url.pathname.slice(stripPrefix.length) || '/' : url.pathname;
  const req = {
    method: request.method,
    url: path + url.search,
    originalUrl: url.pathname + url.search,
    path,
    query: Object.fromEntries(url.searchParams),
    params: {},
    headers,
    body: parseBody(text, headers['content-type'] ?? ''),
    hostname: url.hostname,
    protocol: url.protocol.replace(':', ''),
    get: (name) => headers[name.toLowerCase()],
  };
  const res = new Res();
  try {
    const handled = await router.handle(req, res);
    if (!handled) res.status(404).json({ error: 'not_found', message: `${request.method} ${path}` });
  } catch (err) {
    res.status(err.status ?? 500).json({ error: err.name ?? 'Error', message: err.message });
  }
  return res.toResponse();
}

const noop = () => (_req, _res, next) => next();
function express() {
  return new Router();
}
express.Router = () => new Router();
express.json = noop;
express.urlencoded = noop;
express.static = noop;

export default express;
