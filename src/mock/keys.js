import { randomUUID, randomBytes } from 'node:crypto';
import { SignJWT, exportJWK, generateKeyPair, jwtVerify, createLocalJWKSet } from 'jose';

const kid = `mock-${randomBytes(4).toString('hex')}`;
const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
const publicJwk = { ...(await exportJWK(publicKey)), kid, alg: 'RS256', use: 'sig' };
export const jwks = { keys: [publicJwk] };
const localJwks = createLocalJWKSet(jwks);

export async function signToken(claims, ttlSeconds = 3600) {
  const now = Math.floor(Date.now() / 1000);
  const exp = claims.exp ?? now + ttlSeconds;
  const { exp: _ignored, ...rest } = claims;
  return new SignJWT({ ...rest, jti: randomUUID() })
    .setProtectedHeader({ alg: 'RS256', kid, typ: 'JWT' })
    .setIssuedAt(now)
    .setExpirationTime(exp)
    .sign(privateKey);
}

export async function verifyToken(token, issuer) {
  const { payload } = await jwtVerify(token, localJwks, { issuer });
  return payload;
}

export const randomId = (bytes = 13) => randomBytes(bytes).toString('base64url').replace(/[-_]/g, 'x').toLowerCase();
