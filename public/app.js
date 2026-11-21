import { mountArch, pulseArch, setArchTab } from './arch.js';

const $ = (sel) => document.querySelector(sel);
const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
let S = null;
let lastExchange = null;

const HL_KEYS = new Set([
  'client_id', 'scope', 'aud', 'act', 'error', 'error_description', 'message', 'client_id_metadata_document_supported',
  'registration_endpoint', 'issued_token_type', 'refresh_token', 'redirect_uris', 'token_endpoint_auth_method', 'decision',
]);

function jsonHtml(value) {
  if (value === undefined) return '';
  const text = typeof value === 'string' ? value : JSON.stringify(value, null, 2);
  return text
    .split('\n')
    .map((line) => {
      const m = /^(\s*)"([^"]+)":(.*)$/.exec(line);
      if (!m) return esc(line);
      const body = `<span class="k">"${esc(m[2])}"</span>:${esc(m[3])}`;
      return HL_KEYS.has(m[2]) ? `${m[1]}<span class="hl">${body}</span>` : `${m[1]}${body}`;
    })
    .join('\n');
}

const statusBadge = (code) => `<span class="status s${String(code)[0]}">${esc(code)}</span>`;

function toast(msg, isErr = false) {
  const t = $('#toast');
  t.textContent = msg;
  t.className = `toast${isErr ? ' err' : ''}`;
  t.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (t.hidden = true), isErr ? 6000 : 2500);
}

async function api(path, { method = 'GET', body } = {}) {
  const res = await fetch(path, { method, headers: body ? { 'Content-Type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.message ?? data.error ?? `HTTP ${res.status}`);
  return data;
}

async function busy(btn, fn) {
  btn.classList.add('busy');
  btn.disabled = true;
  try {
    return await fn();
  } catch (err) {
    toast(err.message, true);
  } finally {
    btn.classList.remove('busy');
    btn.disabled = false;
  }
}

function renderTokens(decoded) {
  return Object.entries(decoded ?? {})
    .filter(([, d]) => d)
    .map(([k, d]) => `<div class="jwt-box"><div class="label">${esc(k)}（デコード）</div><pre>${jsonHtml(d.payload)}</pre></div>`)
    .join('');
}

function renderTrace(trace) {
  $('#trace-time').textContent = new Date().toLocaleTimeString();
  const notes = trace.notes.map((n) => `<div class="note ${esc(n.level)}">${esc(n.text)}</div>`).join('');
  const steps = trace.steps
    .map((st, i) => {
      if (st.kind === 'tokens') {
        return `<details class="step" open><summary><span class="method">JWT</span>${esc(st.title)}</summary><div class="body">${renderTokens(st.decoded)}</div></details>`;
      }
      const open = i === trace.steps.length - 1 || st.decoded ? ' open' : '';
      const req = st.request ?? {};
      const resp = st.response ?? {};
      return `<details class="step"${open}>
        <summary><span class="method">${esc(req.method)}</span><span>${esc(st.title)}</span><span style="margin-left:auto">${resp.status !== undefined ? statusBadge(resp.status) : ''}</span></summary>
        <div class="body">
          <div class="url">${esc(req.url)}</div>
          ${req.headers && Object.keys(req.headers).length ? `<div class="label">REQUEST HEADERS</div><pre>${jsonHtml(req.headers)}</pre>` : ''}
          ${req.body !== undefined ? `<div class="label">REQUEST BODY</div><pre>${jsonHtml(req.body)}</pre>` : ''}
          ${resp.wwwAuthenticate ? `<div class="label">WWW-Authenticate</div><pre>${esc(resp.wwwAuthenticate)}</pre>` : ''}
          ${resp.location ? `<div class="label">LOCATION</div><pre>${esc(resp.location)}</pre>` : ''}
          ${resp.body !== undefined && resp.body !== null ? `<div class="label">RESPONSE${resp.ms !== undefined ? ` (${resp.ms} ms)` : ''}</div><pre>${jsonHtml(resp.body)}</pre>` : ''}
          ${renderTokens(st.decoded)}
        </div></details>`;
    })
    .join('');
  $('#trace').classList.remove('muted');
  pulseArch($('#arch'), trace);
  $('#trace').innerHTML = `<div class="trace-title">${esc(trace.title)}</div><div class="notes">${notes}</div>${steps}`;
}

const show = (data) => {
  if (data?.trace) renderTrace(data.trace);
  return data;
};

const userTokens = () => (S?.wallet ?? []).filter((w) => w.kind === 'cimd' || w.kind === 'dcr');
const wildcard = (p) => new RegExp(`^${p.replace(/[.+^${}()|[\]\\?]/g, '\\$&').replace(/\*/g, '.*')}$`);

function renderHeader() {
  document.querySelectorAll('#mode-switch button').forEach((b) => {
    b.classList.toggle('active', b.dataset.mode === S.mode);
    b.disabled = !S.availableModes.includes(b.dataset.mode);
    if (b.disabled) b.title = S.capabilities.staticSite ? 'GitHub Pages 版は模擬モードだけです（AWS モードはローカルで npm start）' : 'aws-config.json がありません（npm run setup:aws）';
  });
  $('#mode-label').textContent = S.label;
  $('#login-hint').textContent = S.loginHint;
  const errs = S.described?.errors ?? [];
  if (errs.length) toast(`AWS の状態を取得できませんでした: ${errs[0]}`, true);
}

function renderWallet() {
  const w = S.wallet;
  $('#wallet').classList.toggle('muted', !w.length);
  $('#wallet').innerHTML = w.length
    ? w
        .map(
          (x) => `<div class="chip"><b><span class="kind ${esc(x.kind)}">${esc(x.kind.toUpperCase())}</span>${esc(x.label)}</b>
          <span class="muted">client_id: <code>${esc(x.claims?.client_id)}</code></span><br>
          <span class="muted">scope: <code>${esc(x.claims?.scope)}</code>${x.claims?.aud ? ` aud: <code>${esc(x.claims.aud)}</code>` : ''}${x.claims?.act ? ` act: <code>${esc(JSON.stringify(x.claims.act))}</code>` : ''}</span></div>`,
        )
        .join('')
    : 'まだありません';
}

function renderTab1() {
  const policy = S.described?.cimdPolicy;
  $('#cimd-base').textContent = policy?.ClientId ?? S.clients.cimdBase;
  if (document.activeElement !== $('#cimd-patterns')) $('#cimd-patterns').value = (policy?.URLPatterns ?? []).join('\n');
  const patterns = policy?.URLPatterns ?? [];
  $('#cimd-docs').innerHTML = S.cimdDocs
    .map((d) => {
      const match = patterns.some((p) => wildcard(p).test(d.url));
      return `<div class="doc-card ${esc(d.key)}">
        <b>${esc(d.name)}</b>
        <code class="url">${esc(d.url)}</code>
        <span class="small">${match ? '<span class="state ok">CIMD ポリシーの URL パターンに一致</span>' : '<span class="state err">どの URL パターンにも一致しない</span>'}</span>
        <div class="row wrap">
          <button class="ghost" data-probe="${esc(d.key)}">メタデータと認可を確認</button>
          <button class="primary" data-login-cimd="${esc(d.key)}">この URL でログイン</button>
        </div></div>`;
    })
    .join('');
  const urls = S.described?.metadataUrls ?? [];
  $('#cimd-urls').innerHTML = urls.length ? urls.map((u) => `<div><code>${esc(u.URL)}</code> ${esc(u.LastResult ?? '')}</div>`).join('') : 'まだありません';

  const dcr = S.described?.dcr;
  const open = Boolean(dcr?.OpenDcrEnabled);
  $('#dcr-open-status').textContent = dcr ? (dcr.EnableStatus === 'DISABLED' ? 'DCR 無効' : open ? '有効' : '無効') : '不明';
  $('#dcr-open').checked = open;
  $('#dcr-open-wrap').classList.toggle('disabled', !S.capabilities.toggleOpenRegistration);
  $('#dcr-open-wrap').title = S.capabilities.toggleOpenRegistration ? 'オープン登録の切り替え' : 'AWS モードではコンソールの「MCP 認証」で切り替えます';
  $('#dcr-endpoint').textContent = `POST ${S.endpoints.register}`;
  $('#dcr-list').innerHTML = S.registrations.length
    ? S.registrations
        .map(
          (r) => `<div class="item"><div><code>${esc(r.clientId)}</code> <span class="small muted">${esc(r.clientName)}・${r.via === 'open' ? 'オープン登録' : '認証済み登録'}</span></div>
          <button class="primary" data-login-dcr="${esc(r.clientId)}" data-name="${esc(r.clientName)}">このクライアントでログイン</button></div>`,
        )
        .join('')
    : '<span class="muted small">まだありません</span>';
}

function renderTab2() {
  const sel = $('#target-client');
  const prev = sel.value;
  const users = userTokens();
  sel.innerHTML = users.length
    ? users.map((w) => `<option value="${esc(w.claims?.client_id)}">${esc(w.label)} — ${esc(w.claims?.client_id)}</option>`).join('')
    : '<option value="example-client-id">（タブ 01でログインしてください）</option>';
  if ([...sel.options].some((o) => o.value === prev)) sel.value = prev;
}

function renderTab3() {
  const sel = $('#subject-token');
  const prev = sel.value;
  const users = userTokens();
  sel.innerHTML = users.length
    ? users.map((w) => `<option value="${esc(w.id)}">${esc(w.label)}（scope ${String(w.claims?.scope ?? '').split(' ').length} 個）</option>`).join('')
    : '<option value="">（タブ 01でログインしてください）</option>';
  if ([...sel.options].some((o) => o.value === prev)) sel.value = prev;
  $('#mcp-client-id').textContent = S.clients.mcpServer;
  $('#exchanged-read').disabled = !lastExchange;
  $('#exchanged-write').disabled = !lastExchange;
}

async function refresh() {
  S = await api('api/state');
  renderHeader();
  renderWallet();
  renderTab1();
  renderTab2();
  renderTab3();
}

// ---- tabs / header
document.querySelectorAll('.tabs button').forEach((b) =>
  b.addEventListener('click', () => {
    document.querySelectorAll('.tabs button').forEach((x) => x.classList.toggle('active', x === b));
    document.querySelectorAll('.tab-panel').forEach((p) => p.classList.toggle('active', p.id === b.dataset.tab));
    setArchTab($('#arch'), b.dataset.tab);
    if (b.dataset.tab === 't2') loadPolicy(true);
  }),
);
document.querySelectorAll('#mode-switch button').forEach((b) =>
  b.addEventListener('click', () =>
    busy(b, async () => {
      await api('api/mode', { method: 'POST', body: { mode: b.dataset.mode } });
      lastExchange = null;
      $('#trace').innerHTML = '操作すると、HTTP のやり取りとデコードした JWT がここに出ます。';
      await refresh();
      await loadPolicy(true);
    }),
  ),
);
$('#reset').addEventListener('click', (e) =>
  busy(e.currentTarget, async () => {
    if (!confirm('ログイン済みトークンと（模擬モードでは）登録内容・ポリシーを初期化します。よろしいですか？')) return;
    await api('api/reset', { method: 'POST' });
    lastExchange = null;
    $('#matrix').innerHTML = 'タブ 01でログインしたクライアントが並びます。';
    $('#compare').innerHTML = '交換すると、ここに交換前後のトークンが並びます。';
    await refresh();
    await loadPolicy(true);
    toast('初期化しました');
  }),
);

// ---- login popup
function openLogin(client, kind, label) {
  const url = `api/login/start?${new URLSearchParams({ client, kind, label })}`;
  const win = window.open(url, `demo-login-${Date.now()}`, 'width=520,height=760');
  if (!win) toast('ポップアップがブロックされました。ブラウザで許可してください', true);
}
window.addEventListener('message', async (e) => {
  if (e.origin !== location.origin || !e.data?.type) return;
  if (e.data.traceId) {
    const trace = await fetch(`api/trace/${e.data.traceId}`).then((r) => r.json());
    renderTrace(trace);
  } else if (e.data.type === 'login-error') {
    renderTrace({ title: 'ログインできませんでした', steps: [], notes: [{ level: 'error', text: `${e.data.error}: ${e.data.description ?? ''}` }] });
  }
  if (e.data.type === 'login-complete') toast('ログインしました');
  await refresh();
});

// ---- tab 1
$('#cimd-docs').addEventListener('click', (e) => {
  const probe = e.target.closest('[data-probe]');
  const login = e.target.closest('[data-login-cimd]');
  if (probe) {
    busy(probe, async () => {
      show(await api('api/cimd/probe', { method: 'POST', body: { key: probe.dataset.probe } }));
      await refresh();
    });
  }
  if (login) {
    const doc = S.cimdDocs.find((d) => d.key === login.dataset.loginCimd);
    openLogin(doc.url, 'cimd', doc.name.replace(/（.*）/, ''));
  }
});
$('#cimd-save').addEventListener('click', (e) =>
  busy(e.currentTarget, async () => {
    show(await api('api/cimd/patterns', { method: 'POST', body: { patterns: $('#cimd-patterns').value.split('\n') } }));
    await refresh();
    toast('CIMD ポリシーを更新しました');
  }),
);
$('#dcr-register-open').addEventListener('click', (e) =>
  busy(e.currentTarget, async () => {
    show(await api('api/dcr/register', { method: 'POST', body: { withToken: false, clientName: $('#dcr-name').value } }));
    await refresh();
  }),
);
$('#dcr-register-auth').addEventListener('click', (e) =>
  busy(e.currentTarget, async () => {
    show(await api('api/dcr/register', { method: 'POST', body: { withToken: true, clientName: $('#dcr-name').value } }));
    await refresh();
  }),
);
$('#dcr-open').addEventListener('change', async (e) => {
  try {
    show(await api('api/dcr/open', { method: 'POST', body: { enabled: e.target.checked } }));
  } catch (err) {
    toast(err.message, true);
  }
  await refresh();
});
$('#dcr-list').addEventListener('click', (e) => {
  const b = e.target.closest('[data-login-dcr]');
  if (b) openLogin(b.dataset.loginDcr, 'dcr', `${b.dataset.name}`);
});
$('#dcr-refresh').addEventListener('click', (e) => busy(e.currentTarget, loadRemoteDcr));
async function loadRemoteDcr() {
  const data = show(await api('api/dcr/clients'));
  $('#dcr-remote').innerHTML = data.clients.length
    ? data.clients.map((c) => `<div class="item"><div><code>${esc(c.ClientId)}</code> <span class="small muted">${esc(c.ClientName)}</span></div><button class="ghost small" data-del="${esc(c.ClientId)}">削除</button></div>`).join('')
    : '<span class="muted small">DCR クライアントはありません</span>';
}
$('#dcr-remote').addEventListener('click', (e) => {
  const b = e.target.closest('[data-del]');
  if (!b) return;
  busy(b, async () => {
    show(await api(`api/dcr/clients/${encodeURIComponent(b.dataset.del)}`, { method: 'DELETE' }));
    await refresh();
    await loadRemoteDcr();
  });
});

// ---- tab 2
const P = 'bedrock-agentcore:InboundJwtClaim';
function preset(kind) {
  const allow = { Sid: 'AllowInvoke', Effect: 'Allow', Principal: '*', Action: 'bedrock-agentcore:InvokeGateway', Resource: S.gatewayArn };
  const denyClient = {
    Sid: 'DenyThisClient',
    Effect: 'Deny',
    Principal: '*',
    Action: 'bedrock-agentcore:InvokeGateway',
    Resource: S.gatewayArn,
    Condition: { StringEquals: { [`${P}/client_id`]: $('#target-client').value } },
  };
  const requireScope = {
    Sid: 'RequireMcpScope',
    Effect: 'Deny',
    Principal: '*',
    Action: 'bedrock-agentcore:InvokeGateway',
    Resource: S.gatewayArn,
    Condition: { Null: { [`${P}/iss`]: 'false' }, 'ForAllValues:StringNotEquals': { [`${P}/scope`]: S.scopes.mcpInvoke } },
  };
  const statements = { allow: [allow], 'deny-client': [allow, denyClient], 'deny-only': [denyClient], 'require-scope': [allow, requireScope] }[kind];
  return { Version: '2012-10-17', Statement: statements };
}
document.querySelectorAll('[data-preset]').forEach((b) =>
  b.addEventListener('click', () => {
    $('#policy').value = JSON.stringify(preset(b.dataset.preset), null, 2);
  }),
);
async function loadPolicy(quiet = false) {
  try {
    const { policy } = await api('api/gateway/policy');
    if (policy) $('#policy').value = JSON.stringify(policy, null, 2);
    else if (!$('#policy').value) $('#policy').value = JSON.stringify(preset('allow'), null, 2);
    if (!quiet) toast(policy ? '現在のポリシーを読み込みました' : 'リソースポリシーは未設定です（JWT 認証のみ）');
  } catch (err) {
    if (!quiet) toast(err.message, true);
  }
}
$('#policy-load').addEventListener('click', (e) => busy(e.currentTarget, () => loadPolicy(false)));
$('#policy-apply').addEventListener('click', (e) =>
  busy(e.currentTarget, async () => {
    let policy;
    try {
      policy = JSON.parse($('#policy').value);
    } catch (err) {
      throw new Error(`JSON が不正です: ${err.message}`);
    }
    show(await api('api/gateway/policy', { method: 'PUT', body: { policy } }));
    toast('ポリシーを適用しました');
  }),
);
$('#policy-delete').addEventListener('click', (e) =>
  busy(e.currentTarget, async () => {
    show(await api('api/gateway/policy', { method: 'DELETE' }));
    toast('ポリシーを削除しました');
  }),
);
$('#matrix-run').addEventListener('click', (e) =>
  busy(e.currentTarget, async () => {
    const data = show(await api('api/gateway/matrix', { method: 'POST' }));
    if (!data.rows.length) {
      $('#matrix').innerHTML = 'ログイン済みのクライアントがありません。タブ 01でログインしてください。';
      return;
    }
    $('#matrix').classList.remove('muted');
    $('#matrix').innerHTML = `<table><thead><tr><th>クライアント</th><th>client_id</th><th>結果</th>${S.capabilities.explainPolicy ? '<th>判定（模擬のみ表示）</th>' : ''}</tr></thead><tbody>${data.rows
      .map(
        (r) => `<tr><td><span class="kind ${esc(r.kind)}">${esc(r.kind.toUpperCase())}</span>${esc(r.label)}</td><td><code>${esc(r.clientId)}</code></td>
        <td>${statusBadge(r.status)} <span class="small muted">${esc(r.message).slice(0, 90)}</span></td>
        ${S.capabilities.explainPolicy ? `<td class="small">${esc(r.decision ?? 'ポリシーなし')}${r.decidedBy ? `（${esc(r.decidedBy)}）` : ''}</td>` : ''}</tr>`,
      )
      .join('')}</tbody></table>`;
  }),
);

// ---- tab 3
const subjectId = () => {
  const id = $('#subject-token').value;
  if (!id) throw new Error('タブ 01でログインしてトークンを用意してください');
  return id;
};
function setEdge(text, cls) {
  const edge = $('#flow-edge');
  edge.textContent = text;
  edge.className = `edge ${cls}`;
}
for (const op of ['read', 'write']) {
  $(`#forward-${op}`).addEventListener('click', (e) =>
    busy(e.currentTarget, async () => {
      const w = S.wallet.find((x) => x.id === subjectId());
      setEdge(`そのまま転送（scope ${String(w.claims?.scope ?? '').split(' ').length} 個）`, 'wide');
      show(await api('api/exchange/forward', { method: 'POST', body: { walletId: w.id, op } }));
    }),
  );
  $(`#exchanged-${op}`).addEventListener('click', (e) =>
    busy(e.currentTarget, async () => {
      show(await api('api/backend/call', { method: 'POST', body: { walletId: lastExchange.issuedId, op } }));
    }),
  );
}
$('#exchange').addEventListener('click', (e) =>
  busy(e.currentTarget, async () => {
    const id = subjectId();
    const data = show(await api('api/exchange/exchange', { method: 'POST', body: { walletId: id, scope: $('#ex-scope').value, withActor: $('#ex-actor').checked } }));
    await refresh();
    if (!data.walletId) {
      setEdge('交換は拒否されました', 'wide');
      return;
    }
    lastExchange = { subjectId: id, issuedId: data.walletId };
    renderCompare();
    renderTab3();
  }),
);
function renderCompare() {
  const before = S.wallet.find((w) => w.id === lastExchange.subjectId);
  const after = S.wallet.find((w) => w.id === lastExchange.issuedId);
  const b = before?.claims ?? {};
  const a = after?.claims ?? {};
  const fmt = (v) => (v === undefined || v === null ? '<span class="muted">（なし）</span>' : `<code>${esc(typeof v === 'object' ? JSON.stringify(v) : v)}</code>`);
  const ttl = (c) => (c.exp && c.iat ? `${Math.round((c.exp - c.iat) / 60)} 分` : undefined);
  const rows = [
    ['scope', b.scope, a.scope],
    ['aud', b.aud, a.aud],
    ['act', b.act, a.act],
    ['client_id', b.client_id, a.client_id],
    ['sub', b.sub, a.sub],
    ['有効期間', ttl(b), ttl(a)],
    ['refresh_token', before?.hasRefreshToken ? 'あり' : 'なし', after?.hasRefreshToken ? 'あり' : 'なし'],
  ];
  $('#compare').classList.remove('muted');
  $('#compare').innerHTML = `<div class="compare"><table><thead><tr><th>クレーム</th><th>交換前（ユーザーのトークン）</th><th>交換後（後段 API 用）</th></tr></thead><tbody>${rows
    .map(([k, x, y]) => `<tr class="${JSON.stringify(x) !== JSON.stringify(y) ? 'changed' : ''}"><th>${esc(k)}</th><td>${fmt(x)}</td><td>${fmt(y)}</td></tr>`)
    .join('')}</tbody></table></div>`;
  setEdge(`交換後（scope ${String(a.scope ?? '').split(' ').length} 個・aud=${a.aud}）`, 'narrow');
}

mountArch($('#arch'));
setArchTab($('#arch'), 't1');
refresh()
  .then(() => loadPolicy(true))
  .catch((err) => toast(err.message, true));
