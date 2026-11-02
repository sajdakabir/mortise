# Accounts, trusted devices and teams

This service stores account identities, device public certificates, hashed
sessions, teams and invitation status. It has no vault-content, password, `.env`,
master-key or private-key storage API. Billing is outside this milestone.

## Boundaries

- Account identity is the configured OIDC issuer plus subject, not an email
  address. Require a verified email; never merge accounts on email alone.
- Desktop sign-in uses the system browser, authorization code + PKCE, a random
  state, an OIDC nonce and a loopback callback. The server verifies ID tokens
  independently against its configured issuer/client ID and login nonce.
- The first device bootstraps a new account. Later devices stay pending until
  an already trusted device signs their approval. An account login/reset alone
  cannot replace existing trusted devices or unlock a local vault.
- Every authenticated API request proves possession of its enrolled device key
  and binds method, path, body, session, timestamp and a single-use nonce.
- Team membership is account metadata, not a project decryption key. Joining a
  team does not grant access to every project or bypass the encrypted vault ACL.
- Team invitations are expiring, single-use capabilities stored as hashes.
  The link secret lives in the URL fragment. A recipient requests membership;
  a trusted owner/admin explicitly approves that exact account.
- Removing a trusted device invalidates its account sessions. Removing a team
  member does not erase downloaded data or perform project-key rotation; those
  require the existing vault protocol and its remaining readiness work.

References: [native OAuth](https://www.rfc-editor.org/rfc/rfc8252.html),
[OAuth security BCP](https://www.rfc-editor.org/rfc/rfc9700.html),
[OIDC ID-token validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation).

## Run the account service

Register a **public native client** with an OIDC provider. Enable authorization
code with PKCE (S256), scopes `openid email profile`, and verified email claims.
No client secret belongs in the desktop app. The provider must support a
loopback redirect `http://127.0.0.1:<ephemeral-port>/callback` per RFC 8252.
Providers that require a fixed callback port need an adapter before use.
Discovery and JWKS endpoints must be reachable without redirects; HTTPS is
required except for loopback development. The client and server use the same
issuer/client ID published at `/v1/auth/config`.

```sh
export MORTISE_OIDC_ISSUER=https://your-provider.example/your-tenant
export MORTISE_OIDC_CLIENT_ID=your-public-native-client-id
export MORTISE_ACCOUNTS_DB=/path/to/private/accounts.sqlite
cargo run -p mortise-accounts --release
```

The default listener is `127.0.0.1:8788`; override `MORTISE_ACCOUNTS_BIND` when
deploying behind a TLS reverse proxy. Put IP/request rate limits at that proxy,
especially on `/v1/auth/start` and `/v1/auth/finish`. The service limits pending
logins, request bodies, OIDC response sizes and network timeouts, but is not an
internet-facing abuse-prevention service. Restrict database/backups to the
service account. The database rejects files belonging to another application.
Never point it at a local vault file. No provider or hosted endpoint is created
by this PR.

For local development, launch the app with:

```sh
MORTISE_ACCOUNTS_URL=http://127.0.0.1:8788 cargo tauri dev
```

For release builds, set `MORTISE_ACCOUNTS_URL` at **compile time**. The release
workflow reads the GitHub repository variable of that name. Environment
overrides only work in debug builds; an invitation cannot choose a different
account service. If unset, the app says accounts are unavailable and keeps all
local vault features usable. API response bodies and tokens must not be logged
by deployment infrastructure. The invite landing page has no third-party code,
does not send its fragment to the service, and only opens Mortise after a click.

## Desktop flow

Settings → Account & teams → Continue in browser signs in or registers an
account. The local vault must already exist and be unlocked so its device key
can sign requests. Provider sign-in never unlocks the vault. Sessions live for
eight hours; only token hashes reach SQLite and the desktop token lives in
macOS Keychain. Signing out clears the local session even offline; remote
invalidation is best effort if connectivity or the unlocked device is absent.
Unsigned development builds can still show macOS Keychain approval prompts.

On a second Mac, sign in to the same account, then open **Devices** on the first
Mac. Compare the full displayed fingerprint and approve that exact certificate.
Revocation ends that device's account sessions and prevents re-enrolling its
same key. At least one trusted device must remain. Losing every trusted device
currently has no account recovery path; an identity-provider reset is not a
device-trust reset. It also does not restore a vault or transfer its keys.

Create a team, choose **Invite people**, and copy a link. An optional email
restriction requires that verified address; links expire in seven days and
can be revoked. The recipient opens Mortise, reviews the team and requests to
join. A team owner/admin reviews the recipient's account and approves or
declines. Owners can invite admins; admins can invite members. Members cannot
approve requests or change membership. Approval appears while the recipient's
account dialog remains open. Links are delivered by the user, not emailed by
the service.

Team membership does **not** yet provision encrypted project vaults or replace
the project's existing invite protocol. Project ACL/key distribution still
needs the work in [product-readiness.md](product-readiness.md). No billing,
ownership transfer, session renewal, all-devices-lost recovery, or account
deletion is implemented here.

## Validation

```sh
cargo test -p mortise-accounts --all-features --locked
cargo test -p mortise-app --lib --locked
npm --prefix ui run check
npm --prefix ui test
```

The account tests use isolated databases and synthetic identities. A temporary
OIDC HTTP fixture exercises discovery, PKCE verification, the loopback callback,
both ID-token verifiers, device-signed login and an authenticated team request.
Negative cases cover issuer/audience/nonce/signature/expiry, unverified email,
cross-account access, request replay, pending/revoked devices, invitation expiry
and explicit approval. Browser tests use fake IPC, never a person's real vault.
