import { build } from 'esbuild';
import { mkdir, copyFile } from 'node:fs/promises';
await mkdir('dist/accounts/web', { recursive: true });
await build({ entryPoints: ['accounts-web/app.ts'], bundle: true, format: 'esm', platform: 'browser', target: 'es2022', minify: true, outfile: 'dist/accounts/web/app.js' });
for (const file of ['index.html', 'style.css']) await copyFile(`accounts-web/${file}`, `dist/accounts/web/${file}`);
await copyFile('deploy/accounts-function.mjs', 'dist/accounts/index.mjs');
console.log('Built account sign-in and consent pages.');
