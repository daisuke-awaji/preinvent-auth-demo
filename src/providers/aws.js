import { createRemoteJWKSet } from 'jose';
import {
  CognitoIdentityProviderClient,
  DeleteUserPoolClientCommand,
  DescribeCIMDPolicyCommand,
  DescribeUserPoolCommand,
  ListClientMetadataURLsCommand,
  ListUserPoolClientsCommand,
  UpdateCIMDPolicyCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import {
  BedrockAgentCoreControlClient,
  DeleteResourcePolicyCommand,
  GetResourcePolicyCommand,
  PutResourcePolicyCommand,
} from '@aws-sdk/client-bedrock-agentcore-control';

async function call(trace, title, client, command) {
  const name = command.constructor.name.replace(/Command$/, '');
  try {
    const out = await client.send(command);
    trace?.sdk(title, name, command.input, out);
    return out;
  } catch (err) {
    trace?.sdk(title, name, command.input, null, err);
    throw err;
  }
}

export function createAwsProvider(cfg) {
  const cognito = new CognitoIdentityProviderClient({ region: cfg.region });
  const agentcore = new BedrockAgentCoreControlClient({ region: cfg.region });
  const issuer = `https://cognito-idp.${cfg.region}.amazonaws.com/${cfg.userPoolId}`;
  const domain = `https://${cfg.domain}`;
  const remoteJwks = createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`));

  return {
    mode: 'aws',
    label: `AWS モード（${cfg.region} / ${cfg.userPoolId}）`,
    endpoints: {
      issuer,
      discovery: `${issuer}/.well-known/openid-configuration`,
      authorize: `${domain}/oauth2/authorize`,
      token: `${domain}/oauth2/token`,
      register: `${domain}/oauth2/register`,
      gateway: cfg.gateway.url,
    },
    clients: cfg.clients,
    cimdDocs: cfg.cimdDocs,
    gatewayArn: cfg.gateway.arn,
    capabilities: { toggleOpenRegistration: false, explainPolicy: false },
    verifier: () => ({ jwks: remoteJwks, issuer }),

    async describe() {
      const [pool, policy, urls] = await Promise.allSettled([
        cognito.send(new DescribeUserPoolCommand({ UserPoolId: cfg.userPoolId })),
        cognito.send(new DescribeCIMDPolicyCommand({ UserPoolId: cfg.userPoolId, CIMDPolicyId: cfg.cimdPolicyId })),
        cognito.send(new ListClientMetadataURLsCommand({ UserPoolId: cfg.userPoolId, CIMDPolicyId: cfg.cimdPolicyId })),
      ]);
      const errors = [pool, policy, urls].filter((p) => p.status === 'rejected').map((p) => `${p.reason.name}: ${p.reason.message}`);
      return {
        cimdPolicy: policy.value?.CIMDPolicy ?? null,
        dcr: pool.value?.UserPool?.DcrConfiguration ?? null,
        metadataUrls: urls.value?.ClientMetadataURLs ?? [],
        gateway: { gatewayArn: cfg.gateway.arn, resourcePolicy: await this.getGatewayPolicy().catch(() => null) },
        errors,
      };
    },
    async setOpenRegistration() {
      throw new Error('AWS モードではオープン登録を切り替えません（UpdateUserPool は省略した設定をリセットするため）。コンソールの「MCP 認証」で切り替えてください');
    },
    async setCimdPatterns(patterns, trace) {
      await call(trace, 'CIMD ポリシーの更新', cognito, new UpdateCIMDPolicyCommand({
        UserPoolId: cfg.userPoolId,
        CIMDPolicyId: cfg.cimdPolicyId,
        ClientId: cfg.clients.cimdBase,
        URLPatterns: patterns,
      }));
    },
    async listDcrClients(trace) {
      const out = await call(trace, 'DCR クライアント一覧', cognito, new ListUserPoolClientsCommand({ UserPoolId: cfg.userPoolId, ClientType: 'DCR', MaxResults: 60 }));
      return (out.UserPoolClients ?? []).map((c) => ({ ClientId: c.ClientId, ClientName: c.ClientName }));
    },
    async deleteDcrClient(clientId, trace) {
      if (!clientId.startsWith('dcr_')) throw new Error('DCR クライアント（dcr_ で始まる ID）以外は削除しません');
      await call(trace, 'DCR クライアントの削除', cognito, new DeleteUserPoolClientCommand({ UserPoolId: cfg.userPoolId, ClientId: clientId }));
    },
    async getGatewayPolicy(trace) {
      try {
        const out = await call(trace, 'Gateway リソースポリシーの取得', agentcore, new GetResourcePolicyCommand({ resourceArn: cfg.gateway.arn }));
        return out.policy ? JSON.parse(out.policy) : null;
      } catch (err) {
        if (err.name === 'ResourceNotFoundException') return null;
        throw err;
      }
    },
    async putGatewayPolicy(policy, trace) {
      await call(trace, 'Gateway リソースポリシーの適用', agentcore, new PutResourcePolicyCommand({ resourceArn: cfg.gateway.arn, policy: JSON.stringify(policy) }));
    },
    async deleteGatewayPolicy(trace) {
      await call(trace, 'Gateway リソースポリシーの削除', agentcore, new DeleteResourcePolicyCommand({ resourceArn: cfg.gateway.arn }));
    },
    async reset() {},
  };
}
