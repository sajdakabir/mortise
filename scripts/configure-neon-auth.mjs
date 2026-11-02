// Run after deploying a branch. Only public OAuth configuration is stored in
// the env file. The native client has PKCE and never receives a client secret.
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
const base = process.env.NEON_FUNCTION_ACCOUNTS_BASE_URL?.replace(/\/$/, '');
if (!base || !process.env.NEON_BRANCH) throw new Error('Run neon deploy and load its .env.local first.');
const link = JSON.parse(readFileSync('.neon', 'utf8'));
if (link.branch !== process.env.NEON_BRANCH) throw new Error('Neon branch and local environment differ. Pull the current branch environment first.');
function neon(args, json = false) {
  return execFileSync('neon', [...args, '--project-id', link.projectId, '--branch', link.branch, ...(json ? ['-o', 'json'] : [])], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] });
}
const domains = JSON.parse(neon(['neon-auth', 'domain', 'list'], true));
if (!domains.some(d => d.domain === base)) neon(['neon-auth', 'domain', 'add', base]);
const current = JSON.parse(neon(['neon-auth', 'config', 'oauth-server', 'get'], true));
if (current.enabled && current.login_page !== `${base}/auth/sign-in`) throw new Error('An existing OAuth login page is configured. Review it before changing providers.');
const resources = [...new Set([...(current.resources ?? []).map(r => r.identifier), base])];
if (!current.enabled || current.consent_page !== `${base}/auth/consent` || resources.length !== current.resources?.length) {
  neon(['neon-auth', 'config', 'oauth-server', 'update', '--enabled', '--login-page', `${base}/auth/sign-in`, '--consent-page', `${base}/auth/consent`, '--resources', ...resources]);
}
const listed = JSON.parse(neon(['neon-auth', 'oauth-client', 'list'], true));
const clients = Array.isArray(listed) ? listed : listed.clients;
if (!Array.isArray(clients)) throw new Error('Unexpected OAuth client list; no client was changed.');
let client = clients.find(c => c.client_name === 'Mortise desktop' || c.name === 'Mortise desktop');
if (!client) client = JSON.parse(neon(['neon-auth', 'oauth-client', 'create', '--name', 'Mortise desktop', '--type', 'public', '--redirect-uris', 'http://127.0.0.1:39817/callback', '--resources', base], true));
if (client.type !== 'public' || client.disabled || client.skip_consent ||
    client.redirect_uris?.length !== 1 || client.redirect_uris[0] !== 'http://127.0.0.1:39817/callback' ||
    client.resources?.length !== 1 || client.resources[0] !== base) {
  throw new Error('Existing desktop client differs from the expected public, consent-required configuration. Review it before deploying.');
}
const id = client.client_id;
if (!id || typeof id !== 'string') throw new Error('Neon did not return a public client ID.');
const values = { MORTISE_OIDC_CLIENT_ID: id, MORTISE_OIDC_CALLBACK_PORT: '39817', MORTISE_OIDC_RESOURCE: base, MORTISE_ACCOUNTS_URL: base };
let content = readFileSync('.env.local', 'utf8');
for (const [key, value] of Object.entries(values)) {
  content = content.replace(new RegExp(`^${key}=.*\\n?`, 'gm'), '');
  content += `\n${key}=${JSON.stringify(value)}\n`;
}
writeFileSync('.env.local', content, { mode: 0o600 });
console.log('Configured branch-specific public desktop client, consent pages and loopback callback. Run neon deploy --env .env.local.');
