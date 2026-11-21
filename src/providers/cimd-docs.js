import { REDIRECT_URI, USER_LOGIN_SCOPE } from '../config.js';

export const CIMD_DOCS = [
  { key: 'trusted', path: 'trusted/demo-ai-client.json', name: 'Demo AI Client（許可済みのAIクライアント）' },
  { key: 'untrusted', path: 'untrusted/unknown-agent.json', name: 'Unknown Agent（未許可のAIクライアント）' },
];

export function buildCimdDocument(url, name, redirectUri = REDIRECT_URI) {
  return {
    client_id: url,
    client_name: name,
    client_uri: 'https://github.com/',
    redirect_uris: [redirectUri],
    grant_types: ['authorization_code'],
    response_types: ['code'],
    token_endpoint_auth_method: 'none',
    scope: USER_LOGIN_SCOPE,
  };
}
