import express from 'express';
import { verifyToken } from './keys.js';
import { MOCK_GATEWAY_ARN, MOCK_ISSUER } from './cognito.js';
import { SCOPES } from '../config.js';
import { evaluatePolicy, jwtClaimsToContext } from '../lib/policy-eval.js';

export const MOCK_GATEWAY_PATH = '/mock/gateway/mcp';

const authorizer = { discoveryUrl: `${MOCK_ISSUER}/.well-known/openid-configuration`, allowedScopes: [SCOPES.mcpInvoke] };
let resourcePolicy = null;
let lastEvaluation = null;

const TOOLS = [
  {
    name: 'demo-target___get_order_status',
    description: '注文ステータスを返すデモ用ツール',
    inputSchema: { type: 'object', properties: { orderId: { type: 'string' } }, required: ['orderId'] },
  },
];

function rpcResult(id, result) {
  return { jsonrpc: '2.0', id: id ?? null, result };
}

export function createMockGatewayRouter() {
  const r = express.Router();
  r.post('/', express.json(), async (req, res) => {
    const auth = req.headers.authorization ?? '';
    const wwwAuth = `Bearer resource_metadata="${req.protocol}://${req.get('host')}${MOCK_GATEWAY_PATH}/.well-known/oauth-protected-resource"`;
    if (!auth.startsWith('Bearer ')) {
      res.set('WWW-Authenticate', wwwAuth);
      return res.status(401).json({ message: 'Missing Bearer token' });
    }
    let claims;
    try {
      claims = await verifyToken(auth.slice(7), MOCK_ISSUER);
    } catch (err) {
      res.set('WWW-Authenticate', wwwAuth);
      return res.status(401).json({ message: `Invalid token: ${err.code ?? err.message}` });
    }
    const scopes = String(claims.scope ?? '').split(' ');
    if (!authorizer.allowedScopes.some((s) => scopes.includes(s))) {
      return res.status(403).json({ message: `JWT authorizer: allowedScopes（${authorizer.allowedScopes.join(', ')}）を満たしません` });
    }

    if (resourcePolicy) {
      const context = jwtClaimsToContext(claims);
      const evaluation = evaluatePolicy(resourcePolicy, { action: 'bedrock-agentcore:InvokeGateway', resource: MOCK_GATEWAY_ARN, context });
      lastEvaluation = { context, ...evaluation };
      if (evaluation.decision !== 'Allow') {
        return res.status(403).json({
          message:
            evaluation.decision === 'Deny'
              ? 'User is not authorized to perform: bedrock-agentcore:InvokeGateway with an explicit deny in a resource-based policy'
              : 'User is not authorized to perform: bedrock-agentcore:InvokeGateway because no resource-based policy allows the action',
          _demo: lastEvaluation,
        });
      }
    } else {
      lastEvaluation = { decision: 'Allow', decidedBy: null, statements: [], context: jwtClaimsToContext(claims), note: 'リソースポリシー未設定（JWT 認証のみ）' };
    }

    const { id, method, params } = req.body ?? {};
    if (method === 'initialize') {
      return res.json(rpcResult(id, { protocolVersion: '2025-11-25', capabilities: { tools: {} }, serverInfo: { name: 'mock-agentcore-gateway', version: '1.0.0' } }));
    }
    if (method === 'tools/list') return res.json({ ...rpcResult(id, { tools: TOOLS }), _demo: lastEvaluation });
    if (method === 'tools/call') {
      return res.json(rpcResult(id, { content: [{ type: 'text', text: `注文 ${params?.arguments?.orderId ?? '?'} は発送済みです（${claims.client_id} から呼び出し）` }] }));
    }
    return res.json({ jsonrpc: '2.0', id: id ?? null, error: { code: -32601, message: `Method not found: ${method}` } });
  });
  return r;
}

export const mockGatewayAdmin = {
  describe: () => ({ gatewayArn: MOCK_GATEWAY_ARN, authorizer, resourcePolicy, lastEvaluation }),
  putPolicy(policy) {
    resourcePolicy = policy;
  },
  deletePolicy() {
    resourcePolicy = null;
  },
  reset() {
    resourcePolicy = null;
    lastEvaluation = null;
  },
};
