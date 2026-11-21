import { createLocalJWKSet } from 'jose';
import { BASE_URL } from '../config.js';
import { jwks } from '../mock/keys.js';
import { MOCK_CLIENTS, MOCK_ISSUER, mockCognitoAdmin } from '../mock/cognito.js';
import { MOCK_GATEWAY_PATH, mockGatewayAdmin } from '../mock/gateway.js';
import { CIMD_DOCS } from './cimd-docs.js';

const localJwks = createLocalJWKSet(jwks);

export function createMockProvider() {
  return {
    mode: 'mock',
    label: '模擬モード（ローカル）',
    endpoints: {
      issuer: MOCK_ISSUER,
      discovery: `${MOCK_ISSUER}/.well-known/openid-configuration`,
      authorize: `${MOCK_ISSUER}/oauth2/authorize`,
      token: `${MOCK_ISSUER}/oauth2/token`,
      register: `${MOCK_ISSUER}/oauth2/register`,
      gateway: `${BASE_URL}${MOCK_GATEWAY_PATH}`,
    },
    clients: {
      cimdBase: MOCK_CLIENTS.cimdBase,
      registrar: { id: MOCK_CLIENTS.registrar, secret: 'mock-registrar-secret' },
      mcpServer: { id: MOCK_CLIENTS.mcpServer, secret: 'mock-mcp-server-secret' },
    },
    cimdDocs: CIMD_DOCS.map((d) => ({ ...d, url: `${BASE_URL}/cimd/${d.path}` })),
    gatewayArn: mockGatewayAdmin.describe().gatewayArn,
    capabilities: { toggleOpenRegistration: true, explainPolicy: true },
    verifier: () => ({ jwks: localJwks, issuer: MOCK_ISSUER }),

    async describe() {
      const c = mockCognitoAdmin.describe();
      return { cimdPolicy: c.cimdPolicy, dcr: c.dcr, metadataUrls: c.metadataUrls, clients: c.clients, gateway: mockGatewayAdmin.describe() };
    },
    async setOpenRegistration(enabled, trace) {
      const dcr = mockCognitoAdmin.setOpenRegistration(enabled);
      trace.sdk('オープン登録の切り替え（模擬）', 'UpdateUserPool (DcrConfiguration)', { DcrConfiguration: { OpenDcrEnabled: enabled } }, { DcrConfiguration: dcr });
    },
    async setCimdPatterns(patterns, trace) {
      const policy = mockCognitoAdmin.setCimdPatterns(patterns);
      trace.sdk('CIMD ポリシーの更新（模擬）', 'UpdateCIMDPolicy', { URLPatterns: patterns }, { CIMDPolicy: policy });
    },
    async listDcrClients(trace) {
      const clients = mockCognitoAdmin.listDcrClients();
      trace?.sdk('DCR クライアント一覧（模擬）', 'ListUserPoolClients', { ClientType: 'DCR' }, { UserPoolClients: clients });
      return clients.map((c) => ({ ClientId: c.ClientId, ClientName: c.ClientName }));
    },
    async deleteDcrClient(clientId, trace) {
      mockCognitoAdmin.deleteClient(clientId);
      trace.sdk('DCR クライアントの削除（模擬）', 'DeleteUserPoolClient', { ClientId: clientId }, {});
    },
    async getGatewayPolicy() {
      return mockGatewayAdmin.describe().resourcePolicy;
    },
    async putGatewayPolicy(policy, trace) {
      mockGatewayAdmin.putPolicy(policy);
      trace.sdk('Gateway リソースポリシーの適用（模擬）', 'PutResourcePolicy', { resourceArn: this.gatewayArn, policy }, { policy: '(applied)' });
    },
    async deleteGatewayPolicy(trace) {
      mockGatewayAdmin.deletePolicy();
      trace.sdk('Gateway リソースポリシーの削除（模擬）', 'DeleteResourcePolicy', { resourceArn: this.gatewayArn }, {});
    },
    async reset() {
      mockCognitoAdmin.reset();
      mockGatewayAdmin.reset();
    },
  };
}
