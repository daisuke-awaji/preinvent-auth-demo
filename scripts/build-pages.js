import { cpSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from 'esbuild';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const src = (...p) => path.join(root, 'src', ...p);
const out = path.join(root, 'dist');

const browserShims = {
  name: 'browser-shims',
  setup(b) {
    b.onResolve({ filter: /^express$/ }, () => ({ path: src('browser', 'express.js') }));
    b.onResolve({ filter: /^node:crypto$/ }, () => ({ path: src('browser', 'crypto.js') }));
    b.onResolve({ filter: /config\.js$/ }, (args) => {
      const resolved = path.resolve(args.resolveDir, args.path);
      return resolved === src('config.js') ? { path: src('browser', 'config.js') } : undefined;
    });
  },
};

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });
cpSync(path.join(root, 'public'), out, { recursive: true });

const common = { bundle: true, format: 'esm', platform: 'browser', target: 'es2022', minify: true, sourcemap: true, logLevel: 'info', legalComments: 'none' };
await build({ ...common, entryPoints: [src('browser', 'entry.js')], outfile: path.join(out, 'app.js'), plugins: [browserShims], inject: [src('browser', 'buffer-global.js')] });
await build({ ...common, entryPoints: [src('browser', 'sw.js')], outfile: path.join(out, 'sw.js'), format: 'iife' });
writeFileSync(path.join(out, '.nojekyll'), '');
console.log(`built ${path.relative(root, out)}/`);
