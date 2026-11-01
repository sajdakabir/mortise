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
