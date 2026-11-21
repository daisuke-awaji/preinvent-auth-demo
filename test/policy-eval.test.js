import { test } from 'node:test';
import assert from 'node:assert/strict';
import { evaluatePolicy, jwtClaimsToContext } from '../src/lib/policy-eval.js';

const ARN = 'arn:aws:bedrock-agentcore:ap-northeast-1:111122223333:gateway/gw-1';
const req = (claims) => ({ action: 'bedrock-agentcore:InvokeGateway', resource: ARN, context: jwtClaimsToContext(claims) });
const allow = { Effect: 'Allow', Principal: '*', Action: 'bedrock-agentcore:InvokeGateway', Resource: ARN };

test('implicit deny without Allow', () => {
  const policy = { Statement: [{ Effect: 'Deny', Principal: '*', Action: '*', Resource: '*', Condition: { StringEquals: { 'bedrock-agentcore:InboundJwtClaim/client_id': 'bad' } } }] };
  assert.equal(evaluatePolicy(policy, req({ client_id: 'good' })).decision, 'ImplicitDeny');
  assert.equal(evaluatePolicy(policy, req({ client_id: 'bad' })).decision, 'Deny');
});

test('ForAllValues:StringNotEquals on scope denies tokens lacking the scope (and empty scope)', () => {
  const policy = {
    Statement: [
      allow,
      {
        Effect: 'Deny',
        Principal: '*',
        Action: 'bedrock-agentcore:InvokeGateway',
        Resource: '*',
        Condition: { Null: { 'bedrock-agentcore:InboundJwtClaim/iss': 'false' }, 'ForAllValues:StringNotEquals': { 'bedrock-agentcore:InboundJwtClaim/scope': 'demo-mcp/invoke' } },
      },
    ],
  };
  assert.equal(evaluatePolicy(policy, req({ iss: 'x', scope: 'openid demo-mcp/invoke' })).decision, 'Allow');
  assert.equal(evaluatePolicy(policy, req({ iss: 'x', scope: 'openid' })).decision, 'Deny');
  assert.equal(evaluatePolicy(policy, req({ iss: 'x' })).decision, 'Deny');
});

test('ForAnyValue on aud, StringLike, IfExists and absent keys', () => {
  const p1 = { Statement: [{ ...allow, Condition: { 'ForAnyValue:StringEquals': { 'bedrock-agentcore:InboundJwtClaim/aud': 'demo-mcp' } } }] };
  assert.equal(evaluatePolicy(p1, req({ aud: ['a', 'demo-mcp'] })).decision, 'Allow');
  assert.equal(evaluatePolicy(p1, req({})).decision, 'ImplicitDeny');
  const p2 = { Statement: [{ ...allow, Condition: { StringLike: { 'bedrock-agentcore:InboundJwtClaim/client_id': 'https://trusted.example/*' } } }] };
  assert.equal(evaluatePolicy(p2, req({ client_id: 'https://trusted.example/c.json' })).decision, 'Allow');
  assert.equal(evaluatePolicy(p2, req({ client_id: 'dcr_x' })).decision, 'ImplicitDeny');
  const p3 = { Statement: [{ ...allow, Condition: { StringEqualsIfExists: { 'bedrock-agentcore:InboundJwtClaim/sub': 'u1' } } }] };
  assert.equal(evaluatePolicy(p3, req({})).decision, 'Allow');
  const p4 = { Statement: [{ ...allow, Condition: { StringNotEquals: { 'bedrock-agentcore:InboundJwtClaim/sub': 'u1' } } }] };
  assert.equal(evaluatePolicy(p4, req({})).decision, 'Allow');
});

test('non-wildcard principal never matches JWT callers', () => {
  const policy = { Statement: [{ ...allow, Principal: { AWS: 'arn:aws:iam::111122223333:root' } }] };
  assert.equal(evaluatePolicy(policy, req({ client_id: 'x' })).decision, 'ImplicitDeny');
});
