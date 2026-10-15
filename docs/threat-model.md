# TruePassword — Threat Model

Status: draft, M0. Nothing in this repo should be implemented until this document
is reviewed and agreed. Every later design decision gets checked against it.

## 1. What we are protecting

| Asset | Sensitivity | Where it lives |
|---|---|---|
| Item secrets (passwords, TOTP seeds, API keys, notes, card numbers) | Critical | Encrypted at rest locally; ciphertext on relay |
| Master password | Critical | User's head only. Never stored, never transmitted |
| Account key | Critical | Recovery kit + local keychain |
| Identity keys (Ed25519 sign, X25519 kex) | Critical | Wrapped under MUK, local only |
| Device keys | High | Per-device, wrapped locally |
| Item metadata (titles, URLs, folders, timestamps) | Medium | **Plaintext in the local DB by design**; encrypted on relay |
| Sync metadata (who syncs with whom, when, sizes) | Medium | **Visible to the relay.** Minimized, not eliminated |
| Agent Guard index | High | In-memory only, HMACs not plaintext |

Note the deliberate weak points, all conscious trades rather than oversights,
and all of which must be stated in user-facing docs:

1. Metadata is held decrypted in memory while the vault is locked, so search
   works without a password prompt.
2. The local database file leaks item counts, blob sizes and timestamps, because
   it is plain SQLite rather than SQLCipher (spec §4.2).
3. The relay learns a social graph.

## 2. Trust boundaries

```
┌─ user's Mac ──────────────────────────────────────────┐
│                                                        │
│  ┌── TruePassword.app (Tauri) ──┐                      │
│  │  Rust core: keys, crypto     │ ← trusted            │
│  │  ────────── IPC ──────────   │                      │
│  │  webview (Svelte UI)         │ ← semi-trusted       │
│  └──────────────────────────────┘                      │
│            ↕ unix socket (paired, sealed)              │
│  mortise-proxy                   ← semi-trusted       │
│            ↕ native messaging                          │
│  ┌── browser ───────────────────┐                      │
│  │  background worker            │ ← semi-trusted      │
│  │  content script               │ ← UNTRUSTED         │
│  │  web page                     │ ← HOSTILE           │
│  └───────────────────────────────┘                     │
└────────────────────────────────────────────────────────┘
             ↕ TLS
        relay + key directory       ← UNTRUSTED (ours, but assumed hostile)
```

The relay is ours and we still treat it as hostile. That is the whole point of
the design: compromising it, or compelling us, must not yield plaintext.

## 3. Adversaries we defend against

### A1 — Compromised relay, or legal compulsion against us
**Capability:** full read/write of everything stored server-side, plus live traffic.
**Must not achieve:** any plaintext secret, any ability to forge an accepted change.
**Defence:** all payloads sealed client-side; every change Ed25519-signed and
hash-chained, so server-injected or reordered changes are rejected by clients.
**Residual:** the relay still learns metadata — peer graph, timing, blob sizes,
change frequency. Minimize; do not claim to eliminate.

### A2 — Network attacker
**Capability:** intercept/modify traffic between client and relay.
**Defence:** TLS, plus the same signature/hash-chain verification as A1 — so even
a TLS break degrades to A1 rather than to compromise.

### A3 — Malicious key directory (**the hard one**)
**Capability:** we run the directory. If it serves a wrong X25519 public key for
a recipient, the sender seals to an attacker and E2EE buys nothing.
**This is inherent to server-brokered key discovery.** Anytype has it too.
**Defence, both required:**
1. Invite links embed the recipient's public key directly (TOFU) so the common
   sharing path never consults the directory.
2. Signal-style fingerprints surfaced in the UI for out-of-band verification.
**Residual:** a user who ignores fingerprints and relies on directory lookup is
exposed to us. Accept and document.

### A4 — Offline attacker holding the encrypted vault
**Capability:** stolen laptop, leaked backup, or exfiltrated relay blobs; unlimited
offline guessing.
**Defence:** Argon2id with high memory cost, **plus** the 256-bit account key. The
account key is what makes this attack useless — password-only would leave a
human-chosen secret as the only barrier. All sensitive fields are individually
encrypted, so the file yields nothing readable without the keys.
**Residual, two parts:**
1. An attacker with both the vault file *and* the account key is back to
   brute-forcing the master password alone. Keep Argon2 parameters aggressive.
2. Because the store is plain SQLite rather than SQLCipher (spec §4.2), the file
   reveals how many items exist, the table shape, and individual blob sizes.
   Minor, but real, and not something to claim otherwise.

### A5 — Malicious web page
**Capability:** full control of page content, scripts, and DOM; may impersonate a
login form or a known site's layout.
**Must not achieve:** any credential for an origin it does not control.
**Defence:** credential matching is bound to the **real origin** reported by the
browser, never to page content or window titles. This is the reason we ship a
browser extension instead of macOS synthetic typing.

### A6 — Compromised browser extension
**Capability:** whatever the extension can do.
**Defence:** limit blast radius. The extension never holds the vault and never
holds a long-lived unlock. It requests one credential for one origin at a time;
the app authorizes per request and can require interaction.

### A7 — Malicious update / supply chain
**Capability:** total compromise of every user. The highest-impact attack on us.
**Defence:** signed updates with a key not stored in CI, notarization, pinned and
audited dependencies, and reproducible builds so releases can be independently
verified.

### A8 — Removed share member
**Capability:** retains anything they synced before removal.
**Defence:** key rotation gives **forward** secrecy only.
**Residual, and it is not fixable by cryptography:** past data is theirs forever.
The revoke UI must say so plainly and prompt to rotate the actual credentials.

### A9 — Other local apps (non-root)
**Capability:** read the clipboard, observe window titles, attempt to connect to
our unix socket.
**Defence:** clipboard auto-clear with a short timer; socket requires a paired
association key so an arbitrary local process cannot impersonate the extension;
keychain items scoped with access control.

## 4. Explicit non-goals

Listing these is as important as the defences. We do **not** defend against:

- **A compromised OS, or root-level malware.** If the attacker is root or has
  injected into our process, they win. No user-space password manager survives this.
- **Keyloggers capturing the master password.** Partially mitigated by biometric
  unlock after first unlock; not solved.
- **A user losing both master password and account key.** The data is
  unrecoverable. This is the design working correctly, not a bug.
- **A share recipient copying data they can legitimately read.** Out of scope.
- **Hiding sync metadata from the relay.** Minimized only.
- **Physical coercion.**
- **Memory-scraping a running, unlocked app.** We use `zeroize`/`secrecy` and
  avoid plaintext on disk, but a webview and a GC'd JS heap make guarantees
  impossible. Best-effort, honestly labelled.
- **Agent Guard stopping a determined user.** It is a guardrail against accidents,
  not a security control. Marketing it as the latter would be false.

## 5. Agent Guard specific

Agent Guard inverts the usual privacy posture: to detect secrets in what the user
types, it must inspect what the user types. Because we scan **any text field on
any site**, this is the most scrutinized component we will ship.

Binding constraints:

- Detection runs entirely on-device. No text, no match events, no telemetry
  leaves the machine — ever, including in crash reports.
- Matched content is never logged, not even at debug level.
- The known-secret index holds `HMAC(scan_key, value)`, never plaintext, and
  exists only in memory while unlocked.
- `<input type="password">` is excluded. A user typing a password into a login
  form is not a leak.
- Per-site disable must exist.

## 6. Open questions

- Per-device keypairs signed by the identity key (recommended) vs. one identity
  key copied to every device. Per-device lets a stolen laptop be revoked without
  re-keying everything. **Leaning per-device — decide before M1.**
- Passkey (WebAuthn) private key storage: schema slot reserved now, mechanism
  deferred. Affects the item model, so do not defer the schema.
- Whether the relay should support anonymous/blind fetch to reduce the metadata
  in A1.
