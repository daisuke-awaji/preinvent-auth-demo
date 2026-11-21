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
