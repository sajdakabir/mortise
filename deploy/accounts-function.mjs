// Neon runs the existing Rust API behind this small Fetch adapter. All account
// authorization, signatures, nonce checks and database writes remain in Rust.
import { spawn } from 'node:child_process';
import { readFile, mkdir, copyFile, chmod } from 'node:fs/promises';

let starting;
const backend = 'http://127.0.0.1:8788';
async function startBackend() {
  if (!process.env.DATABASE_URL || !process.env.MORTISE_OIDC_CLIENT_ID) throw new Error('Account configuration missing');
  let binary = process.env.MORTISE_ACCOUNTS_BINARY;
  if (!binary) {
    await mkdir('/run/mortise', { recursive: true });
    binary = '/run/mortise/accounts';
    await copyFile(new URL('./bin/mortise-accounts', import.meta.url), binary);
    await chmod(binary, 0o700);
  }
  const child = spawn(binary, [], { stdio: ['ignore', 'ignore', 'pipe'], env: {
    ...process.env, MORTISE_ACCOUNTS_BIND: '127.0.0.1:8788',
    ...(process.env.MORTISE_ACCOUNTS_BINARY ? {} : { SSL_CERT_FILE: new URL('./bin/ca-certificates.crt', import.meta.url).pathname }),
  }});
  // Avoid forwarding arbitrary provider/DB error details into hosted logs.
  child.stderr.resume();
  let exited = false;
  child.on('error', () => { exited = true; starting = undefined; });
  child.on('exit', () => { exited = true; starting = undefined; });
  const deadline = Date.now() + 25_000;
  while (!exited && Date.now() < deadline) {
    try { if ((await fetch(`${backend}/health`, { signal: AbortSignal.timeout(1000) })).ok) return; } catch {}
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  child.kill();
  throw new Error('Account service did not start');
}

function headers(type = 'application/json') {
  const authOrigin = new URL(process.env.NEON_AUTH_BASE_URL).origin;
  return { 'content-type': type, 'cache-control': 'no-store', 'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
    'content-security-policy': `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self' ${authOrigin}; frame-src ${authOrigin}; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`,
  };
}
const assets = new Map([
  ['/auth/sign-in', ['index.html', 'text/html; charset=utf-8']],
  ['/auth/consent', ['index.html', 'text/html; charset=utf-8']],
  ['/auth/app.js', ['app.js', 'text/javascript; charset=utf-8']],
  ['/auth/style.css', ['style.css', 'text/css; charset=utf-8']],
]);
export default {
  async fetch(request) {
    try {
      const url = new URL(request.url);
      if (request.method === 'GET' && url.pathname === '/auth/config') {
        return Response.json({ authUrl: process.env.NEON_AUTH_BASE_URL }, { headers: headers() });
      }
      if (request.method === 'GET' && assets.has(url.pathname)) {
        const [file, type] = assets.get(url.pathname);
        return new Response(await readFile(new URL(`./web/${file}`, import.meta.url)), { headers: headers(type) });
      }
      if (!(url.pathname === '/health' || url.pathname === '/join' || url.pathname === '/join.js' || url.pathname.startsWith('/v1/'))) {
        return new Response('Not found', { status: 404, headers: headers('text/plain') });
      }
      // Bound the body before buffering at the Node/Rust boundary.
      const chunks = []; let size = 0;
      if (request.body) {
        const reader = request.body.getReader();
        while (true) {
          const { value, done } = await reader.read(); if (done) break;
          size += value.byteLength;
          if (size > 32 * 1024) { await reader.cancel(); return new Response('Request too large', { status: 413 }); }
          chunks.push(Buffer.from(value));
        }
      }
      starting ??= startBackend().catch(error => { starting = undefined; throw error; });
      await starting;
      const forwarded = new Headers();
      for (const key of ['authorization', 'x-mortise-proof', 'content-type']) {
        if (request.headers.has(key)) forwarded.set(key, request.headers.get(key));
      }
      const result = await fetch(backend + url.pathname + url.search, { method: request.method,
        headers: forwarded, body: ['GET', 'HEAD'].includes(request.method) ? undefined : Buffer.concat(chunks),
        redirect: 'manual', signal: AbortSignal.timeout(35_000),
      });
      return new Response(result.body, { status: result.status, headers: result.headers });
    } catch {
      return Response.json({ code: 'unavailable', message: 'Account service is temporarily unavailable.' }, { status: 503, headers: { 'cache-control': 'no-store' } });
    }
  },
};
