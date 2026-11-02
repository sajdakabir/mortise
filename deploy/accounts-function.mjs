// Neon loads the existing Rust API through Node-API. All account
// authorization, signatures, nonce checks and database writes remain in Rust.
import { createRequire } from 'node:module';
import { readFile } from 'node:fs/promises';
const require = createRequire(import.meta.url);
let native;
function api() {
  if (!native) {
    const local = process.env.MORTISE_ACCOUNTS_NATIVE;
    if (!local) process.env.SSL_CERT_FILE ??= new URL('./bin/ca-certificates.crt', import.meta.url).pathname;
    native = require(local ?? new URL('./bin/accounts.node', import.meta.url).pathname);
  }
  return native;
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
      const forwarded = new Headers();
      for (const key of ['authorization', 'x-mortise-proof', 'content-type']) {
        if (request.headers.has(key)) forwarded.set(key, request.headers.get(key));
      }
      const result = await api().handleRequest(request.method, url.pathname + url.search,
        Object.fromEntries(forwarded), Buffer.concat(chunks));
      return new Response(result.body, { status: result.status, headers: result.headers });
    } catch (error) {
      console.error('accounts: request failed', { type: error?.name, code: error?.code });
      return Response.json({ code: 'unavailable', message: 'Account service is temporarily unavailable.' }, { status: 503, headers: { 'cache-control': 'no-store' } });
    }
  },
};
