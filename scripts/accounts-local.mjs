import { createServer } from 'node:http';
import { resolve } from 'node:path';
process.env.MORTISE_ACCOUNTS_BINARY = resolve('target/debug/mortise-accounts');
const { default: app } = await import('../dist/accounts/index.mjs');
createServer(async (req, res) => {
  try {
    const request = new Request(`http://127.0.0.1:8789${req.url}`, { method: req.method, headers: req.headers,
      ...(['GET', 'HEAD'].includes(req.method) ? {} : { body: req, duplex: 'half' }) });
    const response = await app.fetch(request);
    res.writeHead(response.status, Object.fromEntries(response.headers));
    res.end(Buffer.from(await response.arrayBuffer()));
  } catch { res.writeHead(503); res.end('Service unavailable'); }
}).listen(8789, '127.0.0.1', () => console.log('Account app: http://127.0.0.1:8789/auth/sign-in'));
