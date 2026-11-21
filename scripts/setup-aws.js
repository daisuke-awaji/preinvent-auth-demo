import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import {
  AdminCreateUserCommand,
  AdminSetUserPasswordCommand,
  CognitoIdentityProviderClient,
  CreateCIMDPolicyCommand,
  CreateManagedLoginBrandingCommand,
  CreateResourceServerCommand,
  CreateUserPoolClientCommand,
  CreateUserPoolCommand,
  CreateUserPoolDomainCommand,
  UpdateUserPoolCommand,
} from '@aws-sdk/client-cognito-identity-provider';
import { BedrockAgentCoreControlClient, CreateGatewayCommand, GetGatewayCommand } from '@aws-sdk/client-bedrock-agentcore-control';
import { CreateRoleCommand, IAMClient, PutRolePolicyCommand } from '@aws-sdk/client-iam';
import { CreateBucketCommand, PutBucketPolicyCommand, PutObjectCommand, S3Client } from '@aws-sdk/client-s3';
import { CloudFrontClient, CreateDistributionCommand, CreateOriginAccessControlCommand } from '@aws-sdk/client-cloudfront';
import { GetCallerIdentityCommand, STSClient } from '@aws-sdk/client-sts';
import { AWS_CONFIG_PATH, REDIRECT_URI, RESOURCE_SERVERS, SCOPES } from '../src/config.js';
import { buildCimdDocument, CIMD_DOCS } from '../src/providers/cimd-docs.js';

const region = process.env.AWS_REGION ?? process.env.AWS_DEFAULT_REGION ?? 'ap-northeast-1';
const suffix = randomBytes(3).toString('hex');
const name = `preinvent-auth-demo-${suffix}`;
const tags = { Project: 'preinvent-auth-demo' };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (msg) => console.log(`[setup] ${msg}`);

if (existsSync(AWS_CONFIG_PATH)) {
  const prev = JSON.parse(readFileSync(AWS_CONFIG_PATH, 'utf8'));
  if (prev.complete) {
    console.error('aws-config.json が既にあります。作り直す場合は先に npm run teardown:aws を実行してください');
    process.exit(1);
  }
  console.error('前回のセットアップが途中で止まっています。npm run teardown:aws で片付けてから再実行してください');
  process.exit(1);
}

const cfg = { region, name, createdAt: new Date().toISOString(), complete: false };
const save = () => writeFileSync(AWS_CONFIG_PATH, `${JSON.stringify(cfg, null, 2)}\n`, { mode: 0o600 });

const cognito = new CognitoIdentityProviderClient({ region });
const agentcore = new BedrockAgentCoreControlClient({ region });
const iam = new IAMClient({ region });
const s3 = new S3Client({ region });
const cloudfront = new CloudFrontClient({ region: 'us-east-1' });
const sts = new STSClient({ region });

const poolSettings = {
  Policies: { PasswordPolicy: { MinimumLength: 12, RequireLowercase: true, RequireUppercase: true, RequireNumbers: true, RequireSymbols: true } },
  AdminCreateUserConfig: { AllowAdminCreateUserOnly: true },
  DeletionProtection: 'INACTIVE',
  UserPoolTier: 'ESSENTIALS',
  UserPoolTags: tags,
};

async function main() {
  const { Account } = await sts.send(new GetCallerIdentityCommand({}));
  cfg.account = Account;
  log(`アカウント ${Account} / リージョン ${region} に作成します（名前: ${name}）`);
  save();

  const { UserPool } = await cognito.send(new CreateUserPoolCommand({ PoolName: name, ...poolSettings }));
  cfg.userPoolId = UserPool.Id;
  save();
  log(`ユーザープール ${UserPool.Id}（Essentials）`);

  for (const rs of Object.values(RESOURCE_SERVERS)) {
    await cognito.send(new CreateResourceServerCommand({
      UserPoolId: cfg.userPoolId,
      Identifier: rs.identifier,
      Name: rs.name,
      Scopes: rs.scopes.map((s) => ({ ScopeName: s, ScopeDescription: `${rs.identifier} ${s}` })),
    }));
  }
  log('リソースサーバー demo-mcp / demo-backend');

  const domainPrefix = `preinvent-demo-${suffix}`;
  await cognito.send(new CreateUserPoolDomainCommand({ UserPoolId: cfg.userPoolId, Domain: domainPrefix, ManagedLoginVersion: 2 }));
  cfg.domainPrefix = domainPrefix;
  cfg.domain = `${domainPrefix}.auth.${region}.amazoncognito.com`;
  save();
  log(`ドメイン ${cfg.domain}（マネージドログイン）`);

  await cognito.send(new UpdateUserPoolCommand({
    UserPoolId: cfg.userPoolId,
    ...poolSettings,
    DcrConfiguration: {
      EnableStatus: 'ENABLED',
      OpenDcrEnabled: true,
      OpenDcrGrantTypes: ['code'],
      AuthenticatedGrantTypes: ['code'],
      AllowedScopes: [SCOPES.mcpInvoke, SCOPES.backendRead, SCOPES.backendWrite],
    },
  }));
  log('DCR を有効化（オープン登録: 有効, 認可コードのみ）');

  const userScopes = ['openid', 'email', SCOPES.mcpInvoke, SCOPES.backendRead, SCOPES.backendWrite];
  const cimdBase = await cognito.send(new CreateUserPoolClientCommand({
    UserPoolId: cfg.userPoolId,
    ClientName: 'cimd-base',
    GenerateSecret: false,
    AllowedOAuthFlows: ['code'],
    AllowedOAuthFlowsUserPoolClient: true,
    AllowedOAuthScopes: userScopes,
    CallbackURLs: [REDIRECT_URI],
    SupportedIdentityProviders: ['COGNITO'],
    ExplicitAuthFlows: ['ALLOW_REFRESH_TOKEN_AUTH'],
  }));
  const registrar = await cognito.send(new CreateUserPoolClientCommand({
    UserPoolId: cfg.userPoolId,
    ClientName: 'dcr-registrar',
    GenerateSecret: true,
    AllowedOAuthFlows: ['client_credentials'],
    AllowedOAuthFlowsUserPoolClient: true,
    AllowedOAuthScopes: [SCOPES.dcrRegister],
  }));
  const mcpServer = await cognito.send(new CreateUserPoolClientCommand({
    UserPoolId: cfg.userPoolId,
    ClientName: 'mcp-server',
    GenerateSecret: true,
    AllowedOAuthFlows: ['client_credentials'],
    AllowedOAuthFlowsUserPoolClient: true,
    AllowedOAuthScopes: [SCOPES.mcpInvoke, SCOPES.backendRead, SCOPES.backendWrite, SCOPES.backendAdmin],
    ExplicitAuthFlows: ['ALLOW_TOKEN_EXCHANGE_DELEGATION', 'ALLOW_TOKEN_EXCHANGE_IMPERSONATION', 'ALLOW_REFRESH_TOKEN_AUTH'],
  }));
  cfg.clients = {
    cimdBase: cimdBase.UserPoolClient.ClientId,
    registrar: { id: registrar.UserPoolClient.ClientId, secret: registrar.UserPoolClient.ClientSecret },
    mcpServer: { id: mcpServer.UserPoolClient.ClientId, secret: mcpServer.UserPoolClient.ClientSecret },
  };
  save();
  log('アプリクライアント cimd-base / dcr-registrar / mcp-server');

  await cognito.send(new CreateManagedLoginBrandingCommand({ UserPoolId: cfg.userPoolId, ClientId: cfg.clients.cimdBase, UseCognitoProvidedValues: true }));

  const password = `Demo-${randomBytes(6).toString('hex')}-Aa1!`;
  await cognito.send(new AdminCreateUserCommand({
    UserPoolId: cfg.userPoolId,
    Username: 'demo',
    MessageAction: 'SUPPRESS',
    UserAttributes: [{ Name: 'email', Value: 'demo@example.com' }, { Name: 'email_verified', Value: 'true' }],
  }));
  await cognito.send(new AdminSetUserPasswordCommand({ UserPoolId: cfg.userPoolId, Username: 'demo', Password: password, Permanent: true }));
  cfg.user = { username: 'demo', password };
  save();
  log('テストユーザー demo');

  const bucket = `${name}-cimd-${Account}`;
  await s3.send(new CreateBucketCommand({ Bucket: bucket, ...(region === 'us-east-1' ? {} : { CreateBucketConfiguration: { LocationConstraint: region } }) }));
  cfg.cimdBucket = bucket;
  save();
  const oac = await cloudfront.send(new CreateOriginAccessControlCommand({
    OriginAccessControlConfig: { Name: `${name}-oac`, OriginAccessControlOriginType: 's3', SigningBehavior: 'always', SigningProtocol: 'sigv4' },
  }));
  cfg.oacId = oac.OriginAccessControl.Id;
  save();
  const dist = await cloudfront.send(new CreateDistributionCommand({
    DistributionConfig: {
      CallerReference: name,
      Comment: `${name} CIMD documents`,
      Enabled: true,
      Origins: {
        Quantity: 1,
        Items: [{ Id: 's3', DomainName: `${bucket}.s3.${region}.amazonaws.com`, OriginAccessControlId: cfg.oacId, S3OriginConfig: { OriginAccessIdentity: '' } }],
      },
      DefaultCacheBehavior: {
        TargetOriginId: 's3',
        ViewerProtocolPolicy: 'https-only',
        CachePolicyId: '4135ea2d-6df8-44a3-9df3-4b5a84be39ad',
        AllowedMethods: { Quantity: 2, Items: ['GET', 'HEAD'] },
      },
      PriceClass: 'PriceClass_100',
    },
  }));
  cfg.distributionId = dist.Distribution.Id;
  cfg.distributionDomain = dist.Distribution.DomainName;
  save();
  log(`CloudFront ${cfg.distributionDomain}（CIMD ドキュメントの公開用）`);

  await s3.send(new PutBucketPolicyCommand({
    Bucket: bucket,
    Policy: JSON.stringify({
      Version: '2012-10-17',
      Statement: [{
        Sid: 'AllowCloudFrontRead',
        Effect: 'Allow',
        Principal: { Service: 'cloudfront.amazonaws.com' },
        Action: 's3:GetObject',
        Resource: `arn:aws:s3:::${bucket}/*`,
        Condition: { StringEquals: { 'AWS:SourceArn': dist.Distribution.ARN } },
      }],
    }),
  }));
  cfg.cimdDocs = [];
  for (const d of CIMD_DOCS) {
    const url = `https://${cfg.distributionDomain}/cimd/${d.path}`;
    await s3.send(new PutObjectCommand({ Bucket: bucket, Key: `cimd/${d.path}`, Body: JSON.stringify(buildCimdDocument(url, d.name), null, 2), ContentType: 'application/json' }));
    cfg.cimdDocs.push({ key: d.key, name: d.name, path: d.path, url });
  }
  save();

  const policy = await cognito.send(new CreateCIMDPolicyCommand({
    UserPoolId: cfg.userPoolId,
    ClientId: cfg.clients.cimdBase,
    PolicyName: 'trusted-ai-clients',
    URLPatterns: [`https://${cfg.distributionDomain}/cimd/trusted/*`],
  }));
  cfg.cimdPolicyId = policy.CIMDPolicy.CIMDPolicyId;
  save();
  log(`CIMD ポリシー ${cfg.cimdPolicyId}（https://${cfg.distributionDomain}/cimd/trusted/* を cimd-base に割り当て）`);

  const roleName = `${name}-gateway`;
  const role = await iam.send(new CreateRoleCommand({
    RoleName: roleName,
    AssumeRolePolicyDocument: JSON.stringify({
      Version: '2012-10-17',
      Statement: [{ Effect: 'Allow', Principal: { Service: 'bedrock-agentcore.amazonaws.com' }, Action: 'sts:AssumeRole', Condition: { StringEquals: { 'aws:SourceAccount': Account } } }],
    }),
    Tags: Object.entries(tags).map(([Key, Value]) => ({ Key, Value })),
  }));
  cfg.gatewayRoleName = roleName;
  save();
  await iam.send(new PutRolePolicyCommand({
    RoleName: roleName,
    PolicyName: 'gateway-minimal',
    PolicyDocument: JSON.stringify({ Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 'bedrock-agentcore:GetWorkloadAccessToken', Resource: '*' }] }),
  }));
  log(`IAM ロール ${roleName}（IAM の反映を待っています）`);
  await sleep(12000);

  const issuer = `https://cognito-idp.${region}.amazonaws.com/${cfg.userPoolId}`;
  const gw = await agentcore.send(new CreateGatewayCommand({
    name,
    description: 'pre:Invent auth demo (JWT condition keys)',
    roleArn: role.Role.Arn,
    protocolType: 'MCP',
    authorizerType: 'CUSTOM_JWT',
    authorizerConfiguration: { customJWTAuthorizer: { discoveryUrl: `${issuer}/.well-known/openid-configuration`, allowedScopes: [SCOPES.mcpInvoke] } },
    tags,
  }));
  cfg.gateway = { id: gw.gatewayId, arn: gw.gatewayArn, url: gw.gatewayUrl };
  save();
  log(`AgentCore Gateway ${gw.gatewayId} を作成中…`);
  for (let i = 0; i < 60; i++) {
    const g = await agentcore.send(new GetGatewayCommand({ gatewayIdentifier: gw.gatewayId }));
    cfg.gateway.url = g.gatewayUrl ?? cfg.gateway.url;
    if (g.status === 'READY') break;
    if (String(g.status).includes('FAIL')) throw new Error(`Gateway の作成に失敗しました: ${g.statusReasons?.join(', ')}`);
    await sleep(5000);
  }
  save();
  log(`Gateway URL ${cfg.gateway.url}`);

  log('CloudFront から CIMD ドキュメントを取得できるまで待っています（数分かかることがあります）');
  for (let i = 0; i < 90; i++) {
    const res = await fetch(cfg.cimdDocs[0].url).catch(() => null);
    if (res?.ok) break;
    await sleep(10000);
  }

  cfg.complete = true;
  save();
  log('完了しました。aws-config.json を作成しました（秘密情報を含むので共有しないでください）');
  log(`テストユーザー: demo / ${password}`);
  log('npm start で起動し、画面右上で「AWS」に切り替えてください');
}

main().catch((err) => {
  console.error(`[setup] 失敗しました: ${err.name}: ${err.message}`);
  console.error('[setup] 作成済みのリソースは npm run teardown:aws で削除できます');
  process.exit(1);
});
