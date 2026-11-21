import express from 'express';
import path from 'node:path';
import { BASE_URL, INITIAL_MODE, PORT, ROOT_DIR, loadAwsConfig } from './config.js';
import { createMockCognitoRouter, MOCK_PREFIX } from './mock/cognito.js';
import { createMockGatewayRouter, MOCK_GATEWAY_PATH } from './mock/gateway.js';
import { createBackendRouter } from './backend.js';
import { createMockProvider } from './providers/mock.js';
import { createAwsProvider } from './providers/aws.js';
import { createAppRouter } from './routes.js';

export function createServer() {
  const providers = { mock: createMockProvider() };
  const awsConfig = loadAwsConfig();
  if (awsConfig) providers.aws = createAwsProvider(awsConfig);

  const app = express();
  app.disable('x-powered-by');
  const appRouter = createAppRouter({ providers, initialMode: INITIAL_MODE });
  app.use(MOCK_PREFIX, createMockCognitoRouter());
  app.use(MOCK_GATEWAY_PATH, createMockGatewayRouter());
  app.use('/backend', createBackendRouter(() => providers[appRouter.currentMode()].verifier()));
  app.use(appRouter);
  app.use(express.static(path.join(ROOT_DIR, 'public')));
  return { app, providers };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const { app, providers } = createServer();
  app.listen(PORT, '127.0.0.1', () => {
    console.log(`pre:Invent auth demo: ${BASE_URL}`);
    console.log(`modes: ${Object.keys(providers).join(', ')}${providers.aws ? '' : '（aws-config.json がないため AWS モードは無効）'}`);
  });
}
