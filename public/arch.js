const W = 170;
const H = 104;
const ICON = 'icons/aws/';

const NODES = [
  { id: 'client', x: 110, y: 210, icon: 'Client.svg', resource: true, title: 'AI クライアント', sub: 'Claude / ChatGPT など', tabs: ['t1', 't2', 't3'] },
  { id: 'cognito', x: 430, y: 100, icon: 'AmazonCognito.svg', title: 'Amazon Cognito', sub: 'CIMD・DCR・トークン交換', tabs: ['t1', 't2', 't3'] },
  { id: 'cf', x: 730, y: 100, icon: 'AmazonCloudFront.svg', title: 'Amazon CloudFront', sub: 'CIMD ドキュメントを公開', tabs: ['t1'] },
  { id: 's3', x: 970, y: 100, icon: 'AmazonSimpleStorageService.svg', title: 'Amazon S3', sub: 'client metadata JSON', tabs: ['t1'] },
  { id: 'gw', x: 430, y: 330, icon: 'AmazonBedrockAgentCore.svg', title: 'AgentCore Gateway', sub: 'JWT 認可＋リソースポリシー', tabs: ['t2'], badge: 'AWSIdentityAccessManagementPermissions.svg' },
  { id: 'mcp', x: 730, y: 330, icon: 'AWSLambda.svg', title: 'MCP サーバー', sub: 'Gateway のターゲット', tabs: ['t2', 't3'] },
  { id: 'api', x: 970, y: 330, icon: 'Server.svg', resource: true, title: '後段 API', sub: 'aud = demo-backend', tabs: ['t3'] },
];

const L = (n) => n.x - W / 2;
const R = (n) => n.x + W / 2;
const T = (n) => n.y - H / 2;
const B = (n) => n.y + H / 2;
const N = Object.fromEntries(NODES.map((n) => [n.id, n]));

const EDGES = [
  { id: 'auth', tab: 't1', d: `M${R(N.client)} ${N.client.y - 16} H300 V${N.cognito.y} H${L(N.cognito)}`, label: '認可 / DCR', lx: 248, ly: N.client.y - 26 },
  { id: 'cimd', tab: 't1', d: `M${R(N.cognito)} ${N.cognito.y} H${L(N.cf)}`, label: 'メタデータ取得', lx: (R(N.cognito) + L(N.cf)) / 2, ly: N.cognito.y - 10 },
  { id: 'oac', tab: 't1', d: `M${R(N.cf)} ${N.cf.y} H${L(N.s3)}`, label: 'OAC', lx: (R(N.cf) + L(N.s3)) / 2, ly: N.cf.y - 10 },
  { id: 'mcpcall', tab: 't2', d: `M${R(N.client)} ${N.client.y + 16} H300 V${N.gw.y} H${L(N.gw)}`, label: 'MCP＋JWT', lx: 248, ly: N.client.y + 38 },
  { id: 'jwks', tab: 't2', d: `M${N.gw.x - 30} ${T(N.gw)} V${B(N.cognito)}`, label: 'JWKS で検証', lx: N.gw.x - 20, ly: 245, anchor: 'start', dashed: true },
  { id: 'target', tab: 't2', d: `M${R(N.gw)} ${N.gw.y} H${L(N.mcp)}`, label: 'Allow のときだけ', lx: (R(N.gw) + L(N.mcp)) / 2, ly: N.gw.y - 10 },
  { id: 'exchange', tab: 't3', d: `M${N.mcp.x} ${T(N.mcp)} V215 H${N.cognito.x + 30} V${B(N.cognito)}`, label: 'トークン交換（RFC 8693）', lx: (N.mcp.x + N.cognito.x) / 2 + 15, ly: 205 },
  { id: 'downstream', tab: 't3', d: `M${R(N.mcp)} ${N.mcp.y} H${L(N.api)}`, label: '狭い権限', lx: (R(N.mcp) + L(N.api)) / 2, ly: N.mcp.y - 10 },
];

const CAPTIONS = {
  t1: 'AI クライアントは URL（CIMD）か動的に発行された ID（DCR）を client_id にして、事前登録なしで Cognito にログインします。CIMD では Cognito が CloudFront 上のメタデータを取りに行きます。',
  t2: 'Gateway は JWT を Cognito の JWKS で検証したあと、リソースポリシーの InboundJwtClaim 条件で client_id や scope を見て呼び出しを拒否できます。',
  t3: 'MCP サーバーはユーザーのトークンを Cognito でトークン交換し、後段 API 専用の狭いトークン（scope 1 つ・aud 付き・act 付き）で呼び出します。',
};

const esc = (v) => String(v).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

function nodeSvg(n) {
  return `<g class="node" data-node="${n.id}" data-tabs="${n.tabs.join(' ')}" transform="translate(${L(n)} ${T(n)})">
    <rect class="node-bg" width="${W}" height="${H}" rx="12"/>
    ${n.resource ? `<rect class="icon-tile" x="${W / 2 - 20}" y="12" width="40" height="40" rx="8"/><image href="${ICON}${n.icon}" x="${W / 2 - 14}" y="18" width="28" height="28"/>` : `<image href="${ICON}${n.icon}" x="${W / 2 - 20}" y="12" width="40" height="40" rx="8"/>`}
    ${n.badge ? `<g class="badge"><rect x="${W - 66}" y="-11" width="60" height="22" rx="11"/><image href="${ICON}${n.badge}" x="${W - 61}" y="-7" width="14" height="14"/><text x="${W - 43}" y="4">Policy</text></g>` : ''}
    <text class="node-title" x="${W / 2}" y="72">${esc(n.title)}</text>
    <text class="node-sub" x="${W / 2}" y="90">${esc(n.sub)}</text>
  </g>`;
}

function edgeSvg(e) {
  return `<g class="edge${e.dashed ? ' dashed' : ''}" data-edge="${e.id}" data-tab="${e.tab}">
    <path class="edge-base" d="${e.d}"/>
    <path class="edge-flow" d="${e.d}" marker-end="url(#arrow-${e.tab})"/>
    <text class="edge-label" x="${e.lx}" y="${e.ly}" text-anchor="${e.anchor ?? 'middle'}">${esc(e.label)}</text>
  </g>`;
}

export function mountArch(root) {
  const markers = ['t1', 't2', 't3']
    .map((t) => `<marker id="arrow-${t}" class="arrow-${t}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M0 0 L10 5 L0 10 z"/></marker>`)
    .join('');
  root.innerHTML = `
    <svg class="arch-svg" viewBox="0 0 1100 420" role="img" aria-label="AWS 構成図">
      <defs>${markers}
        <pattern id="arch-grid" width="24" height="24" patternUnits="userSpaceOnUse"><path d="M24 0H0V24" fill="none" class="grid-line"/></pattern>
      </defs>
      <rect width="1100" height="420" fill="url(#arch-grid)"/>
      <g class="group">
        <rect x="262" y="22" width="824" height="384" rx="14"/>
        <image href="${ICON}AWSCloudlogoDark.svg" x="262" y="22" width="28" height="28"/>
        <text x="298" y="41">AWS Cloud</text>
      </g>
      ${EDGES.map(edgeSvg).join('')}
      ${NODES.map(nodeSvg).join('')}
    </svg>
    <p class="arch-caption" id="arch-caption"></p>`;
  fitLabels(root);
  document.fonts?.ready.then(() => fitLabels(root));
}

function fitLabels(root) {
  root.querySelectorAll('.label-bg').forEach((el) => el.remove());
  for (const t of root.querySelectorAll('.edge-label')) {
    const b = t.getBBox();
    const bg = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
    bg.setAttribute('class', 'label-bg');
    bg.setAttribute('x', b.x - 6);
    bg.setAttribute('y', b.y - 2);
    bg.setAttribute('width', b.width + 12);
    bg.setAttribute('height', b.height + 4);
    bg.setAttribute('rx', 5);
    t.before(bg);
  }
}

export function setArchTab(root, tab) {
  root.dataset.tab = tab;
  root.querySelectorAll('[data-edge]').forEach((g) => g.classList.toggle('active', g.dataset.tab === tab));
  root.querySelectorAll('[data-node]').forEach((g) => g.classList.toggle('active', g.dataset.tabs.split(' ').includes(tab)));
  const cap = root.querySelector('#arch-caption');
  if (cap) cap.textContent = CAPTIONS[tab] ?? '';
}

function edgesForStep(step) {
  const url = String(step.request?.url ?? '');
  const body = step.request?.body ?? {};
  const status = step.response?.status;
  if (step.kind === 'sdk') return url.includes('ResourcePolicy') ? { nodes: ['gw'] } : { nodes: ['cognito'] };
  if (url.includes('/cimd/')) return { edges: ['cimd', 'oac'] };
  if (url.includes('/oauth2/register') || url.includes('/oauth2/authorize') || url.includes('openid-configuration')) return { edges: ['auth'] };
  if (url.includes('/oauth2/token')) {
    if (String(body.grant_type ?? '').includes('token-exchange')) return { edges: ['exchange'] };
    if (body.grant_type === 'client_credentials' && String(body.scope ?? '').includes('demo-mcp')) return { edges: ['exchange'] };
    return { edges: ['auth'] };
  }
  if (url.includes('/mock/gateway') || url.includes('gateway.bedrock-agentcore')) return { edges: status === 200 ? ['mcpcall', 'jwks', 'target'] : ['mcpcall', 'jwks'], deny: status === 403 ? ['gw'] : [] };
  if (url.includes('/backend/')) return { edges: ['downstream'], deny: status === 403 ? ['api'] : [] };
  return {};
}

export function pulseArch(root, trace) {
  const edges = new Set();
  const nodes = new Set();
  const deny = new Set();
  for (const st of trace?.steps ?? []) {
    const r = edgesForStep(st);
    (r.edges ?? []).forEach((e) => edges.add(e));
    (r.nodes ?? []).forEach((n) => nodes.add(n));
    (r.deny ?? []).forEach((n) => deny.add(n));
  }
  root.querySelectorAll('.pulse, .deny').forEach((el) => el.classList.remove('pulse', 'deny'));
  void root.offsetWidth;
  edges.forEach((id) => root.querySelector(`[data-edge="${id}"]`)?.classList.add('pulse'));
  nodes.forEach((id) => root.querySelector(`[data-node="${id}"]`)?.classList.add('pulse'));
  deny.forEach((id) => root.querySelector(`[data-node="${id}"]`)?.classList.add('deny'));
  clearTimeout(pulseArch.timer);
  pulseArch.timer = setTimeout(() => root.querySelectorAll('.pulse').forEach((el) => el.classList.remove('pulse')), 2600);
}
