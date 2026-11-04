# Neon account service

Mortise keeps its encrypted vault on the Mac. Neon stores account identities,
public device certificates, hashed sessions, teams and invitations. It never
receives saved passwords, `.env` values, recovery keys or private device keys.
Billing is not implemented.

The existing Rust account API runs inside a Neon Function. A small Node Fetch
adapter serves the sign-in pages and passes bounded API requests to the Rust
router through a Node-API module.
Postgres uses a pool of at most five TLS-verified connections per instance.
The `mortise_accounts` schema is separate from Neon's managed `neon_auth` schema.
Account mutations use a transaction-scoped advisory lock to preserve the
existing serialized trust checks across instances; this is a deliberate
throughput limit for the initial service.

## Prerequisites

- Node 22 (`nvm use`), Rust 1.88+ for the hosting module, Docker for the Linux
  API build, and the Neon CLI. The container build pins Rust 1.93.
- `neon login` completed in the browser.
- A Neon project in a Functions-supported region. This project uses Singapore.

The supplied project is `long-bird-76198696` in organization
`org-super-meadow-88252650`. The requested deployment branch is `production`.

```sh
neon init -y --no-agent-setup --org-id org-super-meadow-88252650 --project-id long-bird-76198696 --branch production --services postgres,auth
npm ci
npm --prefix ui ci
npm run build
npm run build:api:linux
neon deploy --env .env.local
npm run db:migrate
node --env-file=.env.local scripts/configure-neon-auth.mjs
neon deploy --env .env.local
```

The first deployment exposes the sign-in pages; protected API calls stay
unavailable until the database migration and public OAuth client are configured.
Setup uses an explicit branch on every Auth command. Re-running it reuses the
client and domain; it refuses to replace another configured login page.
After switching an existing branch, run the Auth configuration script before
deploying. Neon refreshes its own environment variables but retains custom
ones; deployment rejects a resource URL left over from another branch.
Neon may take time to apply OAuth changes; if client creation reports that the
provider is not enabled immediately after enabling it, rerun setup once the
public discovery endpoint is ready.

`.env.local`, `.neon`, generated binaries and locally installed agent skills are
ignored by Git. `neon deploy` pulls credentials directly into `.env.local`.
Do not copy database variables into Vite or the landing page. No client secret
is required: the desktop uses authorization code + PKCE, a one-time nonce,
and a registered `http://127.0.0.1:39817/callback` redirect.

The browser page uses email codes, then asks the user to approve the desktop
sign-in. The server independently verifies issuer, audience, nonce, expiry,
signature and verified email. Providers may return email/profile claims only
from their UserInfo endpoint. In that case the desktop sends the short-lived
provider access token with the device-signed login completion request. The
service checks `at_hash` when present, fetches UserInfo without following
redirects, and requires its subject to equal the verified ID token's subject.
Only a verified email is accepted. Both provider tokens are discarded after
sign-in; neither is written to Postgres, the Keychain, logs or the webview.
Providers with verified email already in the ID token remain compatible.
Later devices still require approval from a trusted device. Team membership does not itself release encrypted vault keys.

## Local testing

```sh
neon checkout mortise-integration --create
npm run db:migrate
npm run test:postgres
npm run dev:accounts
```

The local account site is `http://127.0.0.1:8789/auth/sign-in`; no child process or
extra listening port is needed. The Postgres test creates synthetic accounts on the
isolated branch and verifies simultaneous enrollment, trusted-device approval,
nonce replay rejection, invitation approval, membership isolation and revocation.
Test branches expire after seven days under `neon.ts`.

For a real browser/desktop protocol test, deploy/configure that test branch and run:

```sh
cargo build -p mortise-accounts --example neon_smoke --features client --locked
node --env-file=.env.local -e 'const {spawnSync}=require("node:child_process"); const r=spawnSync("target/debug/examples/neon_smoke",[],{stdio:"inherit"}); process.exit(r.status ?? 1)'
```

Open the printed URL and complete the sign-in. The example never opens your
vault, stores no private key or session token on disk, and invalidates its API
session after checking the protected dashboard. It is restricted to the
`mortise-integration` branch.

For the real desktop app, set `MORTISE_ACCOUNTS_URL` to the production Function
URL when running `cargo tauri dev`. Release builds bake in the GitHub Actions
repository variable of the same name. Account sign-in never unlocks the vault.

Production API for this project:
`https://br-morning-haze-azdlvfr6-accounts.compute.c-3.ap-southeast-1.aws.neon.tech`

```sh
MORTISE_ACCOUNTS_URL=https://br-morning-haze-azdlvfr6-accounts.compute.c-3.ap-southeast-1.aws.neon.tech cargo tauri dev
```

Only the public API URL is passed to the desktop; database credentials stay in
the account service environment.

## Hosting limits

Neon's Free plan currently includes Postgres, Auth and a limited Functions
allowance. This is suitable for initial testing; it has no uptime SLA. Check
[current quotas](https://neon.com/docs/introduction/plans) before public launch.
The Function URL is public; device signatures authenticate API requests but
are not a replacement for edge abuse protection. A public launch also needs
rate limiting/edge protection and production email delivery configured per
[Neon's checklist](https://neon.com/docs/auth/production-checklist).

The landing page can remain on Vercel. Its
[Hobby plan](https://vercel.com/docs/plans/hobby) is restricted to personal,
non-commercial use; do not rely on it as the free commercial API host.

## Fresh local onboarding without deleting credentials

Debug builds can use an isolated app identifier. This separates the vault,
Keychain entries, account session and browser pairings, and skips the legacy
TruePassword import. Release builds always use the normal identifier.

Stop the existing Mortise app and dev server, then use a new identifier:

```sh
export MORTISE_DEV_APP_ID=com.mortise.onboarding-test
cargo build -p mortise-proxy --locked
MORTISE_ACCOUNTS_URL=https://br-morning-haze-azdlvfr6-accounts.compute.c-3.ap-southeast-1.aws.neon.tech \
  cargo tauri dev --config '{"identifier":"com.mortise.onboarding-test"}'
```

The environment variable and Tauri identifier must match or startup is refused.
Build the proxy with the same variable so browser connections reach this profile.
A new identifier gives another empty local profile. This does **not** delete a
hosted account or clear the browser's provider session. Use a separate test email
for a brand-new hosted signup, or explicitly reset that account separately.

To return to the original profile, stop this test app, unset
`MORTISE_DEV_APP_ID`, rebuild `mortise-proxy`, and run `cargo tauri dev` without
the identifier override. Your original local data remains in place.
