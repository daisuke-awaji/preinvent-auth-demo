import express from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const base = process.env.PAGES_BASE ?? '/preinvent-auth-demo';
const port = Number(process.env.PORT ?? 4000);
const app = express();
app.use(base, express.static(path.join(root, 'dist')));
app.get('/', (_req, res) => res.redirect(`${base}/`));
app.listen(port, '127.0.0.1', () => console.log(`GitHub Pages preview (static only): http://localhost:${port}${base}/`));
