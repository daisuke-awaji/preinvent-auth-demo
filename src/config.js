import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

export const ROOT_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const AWS_CONFIG_PATH = path.join(ROOT_DIR, 'aws-config.json');

export const PORT = Number(process.env.PORT ?? 3000);
export const BASE_URL = process.env.BASE_URL ?? `http://localhost:${PORT}`;
export const REDIRECT_URI = `${BASE_URL}/callback`;

export const SCOPES = {
  mcpInvoke: 'demo-mcp/invoke',
  backendRead: 'demo-backend/read',
  backendWrite: 'demo-backend/write',
  backendAdmin: 'demo-backend/admin',
  dcrRegister: 'aws.cognito/dcr/register',
};
export const RESOURCE_SERVERS = {
  mcp: { identifier: 'demo-mcp', name: 'Demo MCP server', scopes: ['invoke'] },
  backend: { identifier: 'demo-backend', name: 'Demo backend API', scopes: ['read', 'write', 'admin'] },
};
export const USER_LOGIN_SCOPE = ['openid', SCOPES.mcpInvoke, SCOPES.backendRead, SCOPES.backendWrite].join(' ');

export function loadAwsConfig() {
  if (!existsSync(AWS_CONFIG_PATH)) return null;
  return JSON.parse(readFileSync(AWS_CONFIG_PATH, 'utf8'));
}

export const INITIAL_MODE = process.env.DEMO_MODE === 'aws' ? 'aws' : 'mock';
