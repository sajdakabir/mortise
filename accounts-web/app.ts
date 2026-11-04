import { createAuthClient } from '@neon/auth';
import type { createAuthClient as createBetterAuthClient } from 'better-auth/client';
import type { emailOTPClient } from 'better-auth/client/plugins';
import type { oauthProviderClient } from '@better-auth/oauth-provider/client';

// @neon/auth 0.8.2 installs these plugins, but its array type loses their
// inferred methods with Better Auth 1.7.15. Keep the Neon runtime (it forwards
// the signed OAuth query); recover only the supported plugin method types.
type ManagedClient = ReturnType<typeof createBetterAuthClient<{
  plugins: [ReturnType<typeof emailOTPClient>, ReturnType<typeof oauthProviderClient>]
}>>;

const el = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const message = (text: string) => { el('message').textContent = text; };
let busy = false;
async function action(work: () => Promise<void>) {
  if (busy) return;
  busy = true;
  document.querySelectorAll('button').forEach(b => b.disabled = true);
  message('');
  try { await work(); } catch { message('That request could not be completed. Please try again.'); }
  finally { busy = false; document.querySelectorAll('button').forEach(b => b.disabled = false); }
}

async function main() {
  const response = await fetch('/auth/config', { cache: 'no-store' });
  if (!response.ok) throw new Error('Configuration unavailable');
  const { authUrl } = await response.json();
  const auth = createAuthClient(authUrl) as unknown as ManagedClient;
  const params = new URLSearchParams(location.search);
  const oauth = params.has('oauth_query') || params.has('client_id');
  // The SDK preserves and forwards Neon's signed authorization query. Never
  // construct a consent/return URL from untrusted callback parameters here.
  async function resume() {
    const { data, error } = await auth.getSession();
    if (error) { message('Unable to check your session. Please retry.'); return; }
    if (!data?.user) { el('login').hidden = false; return; }
    if (location.pathname === '/auth/consent') {
      const { data: client, error: clientError } = await auth.oauth2.publicClient({ query: { client_id: params.get('client_id') ?? '' } });
      if (clientError || !client) { message('This sign-in request expired. Start again from Mortise.'); return; }
      el('heading').textContent = 'Approve this sign-in';
      el('intro').textContent = `Signed in as ${data.user.email}.`;
      el('client-name').textContent = client.client_name ?? 'Unknown application';
      el('scopes').textContent = params.get('scope') ?? 'Profile and email';
      el('resource').textContent = params.get('resource') ?? 'Mortise account service';
      el('redirects').textContent = (client.redirect_uris ?? []).map((uri: string) => new URL(uri).host).join(', ');
      el('consent').hidden = false;
      return;
    }
    if (oauth) {
      const { error } = await auth.oauth2.continue({ selected: true });
      if (error) message('This sign-in link expired. Return to Mortise and try again.');
      return;
    }
    el('login').hidden = true;
    el('session').hidden = false;
    el('heading').textContent = 'You’re signed in';
    el('signed-in').textContent = data.user.email;
  }
  el('email-form').addEventListener('submit', event => {
    event.preventDefault();
    void action(async () => {
      const email = el<HTMLInputElement>('email').value.trim();
      const { error } = await auth.emailOtp.sendVerificationOtp({ email, type: 'sign-in' });
      if (error) { message('Unable to send a code. Check your address and try again.'); return; }
      el('email-form').hidden = true; el('code-form').hidden = false;
      message('Check your email for a sign-in code.'); el('code').focus();
    });
  });
  el('code-form').addEventListener('submit', event => {
    event.preventDefault();
    void action(async () => {
      const { error } = await auth.signIn.emailOtp({ email: el<HTMLInputElement>('email').value.trim(), otp: el<HTMLInputElement>('code').value.trim() });
      el<HTMLInputElement>('code').value = '';
      if (error) { message('That code was invalid or expired. Please try again.'); return; }
      el('login').hidden = true;
      await resume();
    });
  });
  el('change-email').onclick = () => { el('email-form').hidden = false; el('code-form').hidden = true; el<HTMLInputElement>('code').value = ''; message(''); el('email').focus(); };
  for (const [id, accept] of [['allow', true], ['deny', false]] as const) {
    el(id).onclick = () => void action(async () => {
      const { error } = await auth.oauth2.consent({ accept });
      if (error) message('This request expired. Return to Mortise and start again.');
    });
  }
  el('sign-out').onclick = () => void action(async () => {
    const { error } = await auth.signOut();
    if (error) { message('Sign-out failed. Please retry.'); return; }
    el('session').hidden = true; el('heading').textContent = 'Sign in to Mortise';
    el('login').hidden = false; el('email-form').hidden = false; el('code-form').hidden = true;
  });
  await resume();
}
main().catch(() => message('Account sign-in is temporarily unavailable. Please try again shortly.'));
