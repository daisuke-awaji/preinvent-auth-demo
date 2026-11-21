export { RESOURCE_SERVERS, SCOPES, USER_LOGIN_SCOPE } from '../constants.js';

const base = new URL('./', document.baseURI);
export const BASE_URL = base.href.replace(/\/$/, '');
export const BASE_PATH = base.pathname.replace(/\/$/, '');
export const REDIRECT_URI = `${BASE_URL}/callback`;
export const INITIAL_MODE = 'mock';
export const loadAwsConfig = () => null;
