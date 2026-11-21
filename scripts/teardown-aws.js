import { existsSync, readFileSync, rmSync } from 'node:fs';
import { CognitoIdentityProviderClient, DeleteUserPoolCommand, DeleteUserPoolDomainCommand } from '@aws-sdk/client-cognito-identity-provider';
import { BedrockAgentCoreControlClient, DeleteGatewayCommand, GetGatewayCommand } from '@aws-sdk/client-bedrock-agentcore-control';
import { DeleteRoleCommand, DeleteRolePolicyCommand, IAMClient, ListRolePoliciesCommand } from '@aws-sdk/client-iam';
import { DeleteBucketCommand, DeleteObjectsCommand, ListObjectsV2Command, S3Client } from '@aws-sdk/client-s3';
import {
  CloudFrontClient,
  DeleteDistributionCommand,
  DeleteOriginAccessControlCommand,
  GetDistributionCommand,
  GetDistributionConfigCommand,
  GetOriginAccessControlCommand,
  UpdateDistributionCommand,
} from '@aws-sdk/client-cloudfront';
import { AWS_CONFIG_PATH } from '../src/config.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const log = (msg) => console.log(`[teardown] ${msg}`);

if (!existsSync(AWS_CONFIG_PATH)) {
  console.error('aws-config.json がありません。削除するリソースが分かりません');
  process.exit(1);
}
const cfg = JSON.parse(readFileSync(AWS_CONFIG_PATH, 'utf8'));
const { region } = cfg;
const cognito = new CognitoIdentityProviderClient({ region });
const agentcore = new BedrockAgentCoreControlClient({ region });
const iam = new IAMClient({ region });
const s3 = new S3Client({ region });
const cloudfront = new CloudFrontClient({ region: 'us-east-1' });
const failures = [];

async function step(label, fn) {
  try {
    await fn();
    log(`削除: ${label}`);
  } catch (err) {
    if (['ResourceNotFoundException', 'NoSuchEntityException', 'NoSuchBucket', 'NoSuchDistribution', 'NoSuchOriginAccessControl'].includes(err.name)) {
      log(`なし: ${label}`);
      return;
    }
    failures.push(`${label}: ${err.name}: ${err.message}`);
    console.error(`[teardown] 失敗: ${label}: ${err.name}: ${err.message}`);
  }
}

async function main() {
  log(`アカウント ${cfg.account} / リージョン ${region} の ${cfg.name} を削除します`);

  if (cfg.gateway?.id) {
    await step(`AgentCore Gateway ${cfg.gateway.id}`, async () => {
      await agentcore.send(new DeleteGatewayCommand({ gatewayIdentifier: cfg.gateway.id }));
      for (let i = 0; i < 60; i++) {
        try {
          await agentcore.send(new GetGatewayCommand({ gatewayIdentifier: cfg.gateway.id }));
        } catch (err) {
          if (err.name === 'ResourceNotFoundException') return;
          throw err;
        }
        await sleep(5000);
      }
    });
  }
  if (cfg.gatewayRoleName) {
    await step(`IAM ロール ${cfg.gatewayRoleName}`, async () => {
      const { PolicyNames = [] } = await iam.send(new ListRolePoliciesCommand({ RoleName: cfg.gatewayRoleName }));
      for (const PolicyName of PolicyNames) await iam.send(new DeleteRolePolicyCommand({ RoleName: cfg.gatewayRoleName, PolicyName }));
      await iam.send(new DeleteRoleCommand({ RoleName: cfg.gatewayRoleName }));
    });
  }
  if (cfg.userPoolId) {
    if (cfg.domainPrefix) {
      await step(`ドメイン ${cfg.domainPrefix}`, () => cognito.send(new DeleteUserPoolDomainCommand({ UserPoolId: cfg.userPoolId, Domain: cfg.domainPrefix })));
    }
    await step(`ユーザープール ${cfg.userPoolId}（アプリクライアント・DCR クライアント・CIMD ポリシーを含む）`, () => cognito.send(new DeleteUserPoolCommand({ UserPoolId: cfg.userPoolId })));
  }
  if (cfg.distributionId) {
    await step(`CloudFront ${cfg.distributionId}`, async () => {
      const current = await cloudfront.send(new GetDistributionConfigCommand({ Id: cfg.distributionId }));
      let etag = current.ETag;
      if (current.DistributionConfig.Enabled) {
        const updated = await cloudfront.send(new UpdateDistributionCommand({ Id: cfg.distributionId, IfMatch: etag, DistributionConfig: { ...current.DistributionConfig, Enabled: false } }));
        etag = updated.ETag;
        log('CloudFront を無効化しました。デプロイ完了を待っています（5〜15分ほど）');
      }
      for (let i = 0; i < 120; i++) {
        const d = await cloudfront.send(new GetDistributionCommand({ Id: cfg.distributionId }));
        etag = d.ETag;
        if (d.Distribution.Status === 'Deployed') break;
        await sleep(15000);
      }
      await cloudfront.send(new DeleteDistributionCommand({ Id: cfg.distributionId, IfMatch: etag }));
    });
  }
  if (cfg.oacId) {
    await step(`Origin Access Control ${cfg.oacId}`, async () => {
      const oac = await cloudfront.send(new GetOriginAccessControlCommand({ Id: cfg.oacId }));
      await cloudfront.send(new DeleteOriginAccessControlCommand({ Id: cfg.oacId, IfMatch: oac.ETag }));
    });
  }
  if (cfg.cimdBucket) {
    await step(`S3 バケット ${cfg.cimdBucket}`, async () => {
      const { Contents = [] } = await s3.send(new ListObjectsV2Command({ Bucket: cfg.cimdBucket }));
      if (Contents.length) await s3.send(new DeleteObjectsCommand({ Bucket: cfg.cimdBucket, Delete: { Objects: Contents.map(({ Key }) => ({ Key })) } }));
      await s3.send(new DeleteBucketCommand({ Bucket: cfg.cimdBucket }));
    });
  }

  if (failures.length) {
    console.error(`[teardown] ${failures.length} 件削除できませんでした。aws-config.json は残します。原因を解消して再実行してください`);
    process.exit(1);
  }
  rmSync(AWS_CONFIG_PATH);
  log('完了しました。aws-config.json を削除しました');
}

main().catch((err) => {
  console.error(`[teardown] 失敗しました: ${err.name}: ${err.message}`);
  process.exit(1);
});
