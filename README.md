# Mortise

A local-first password manager for macOS. The vault is encrypted on your machine
and stays there; sync is optional, and the relay that carries it only ever holds
ciphertext it has no key for.

> **mor·tise** /ˈmɔːtɪs/ *n.*
> a recess cut into one piece of material so that another seats inside it,
> joining the two without a fastening.

**Not shipped yet.** The vault, sync, the browser extension and import from other
managers all work. There is no signed build to download, which means no Touch ID
and no Chrome Web Store listing until there is. Everything is in the open while
it gets there. Owners and invited testers can use the manual
[macOS test-build path](TESTING.md) in the meantime.

## Why

Every mainstream password manager asks you to trust a server with the thing you
are least able to afford to lose. Most of them have earned that trust so far.
"So far" is doing a lot of work in that sentence.

Mortise holds three things:

- **Passwords**, in a vault that is a file on your Mac.
- **Developer secrets** — `.env` values and API keys, shared with a team without
  a server ever holding a key that opens them.
- **Agent Guard**, which recognises one of your own secrets on its way into a
  chat box and intervenes before it is published. *(In design.)*

## How it works

**The vault is a file on your Mac.** Encrypted with a key derived from your
master password and a 256-bit account key that is generated once and never
transmitted. Lose both and the data is gone — that is the design working, not a
bug.

```
master password   typed, never stored
account key       256-bit, never sent
                  ↓  Argon2id, then HKDF
MUK               unwraps the two below
DB_KEY            every secret in the vault
META_KEY          titles and URLs
```

**Sync is optional, and blind.** Devices exchange signed, encrypted changes
through a relay. Every change is sealed before it leaves and hash-chained on
arrival, so a relay that is compromised — or compelled — can withhold data but
cannot read or forge it.

**The extension runs on no page until you ask.** Most managers request access to
every site you visit, forever. This one asks the browser for the page only when
you invoke it, and the origin it matches against comes from the browser rather
than from the page, so a lookalike site cannot claim to be your bank.

## What this does not protect you from

Stated plainly, because a security tool that is vague about its limits is worse
than one with fewer features:

- **Losing both your master password and your account key.** There is no reset
  link. That is the cost of nobody else holding a key, and it is not recoverable
  by us or by anyone.
- **Someone you shared with keeping a copy.** Revoking rotates the keys going
  forward. It cannot reach back into what they already synced.
- **A file that leaks its own shape.** The local database is plain SQLite in its
  structure, with encrypted fields, so an attacker holding the file learns how
  many items exist and roughly how often you use them — never what they say.

The full version is in [docs/threat-model.md](docs/threat-model.md).

## Build it

Needs Rust 1.85+, Node 20.19+ and Xcode command line tools.

```bash
npm --prefix ui install
cargo tauri dev
```

### The keychain prompt, and how to stop it

A dev build asks for your login keychain password on most runs. The account
key's keychain item trusts the application that created it, and an unsigned
binary is identified there by its code-directory hash — which `cargo` changes
on every rebuild. "Always Allow" pins that one hash and the next build
invalidates it.

A *signed* binary is matched on its certificate instead, which does not change
when the code does. One self-signed certificate, created once, fixes it:

> Keychain Access → Certificate Assistant → Create a Certificate…
> Name `Mortise Dev`, Identity Type **Self Signed Root**, Certificate Type
> **Code Signing**.

`cargo` is already configured to sign dev builds with it (see
`.cargo/config.toml` and `scripts/dev-sign-and-run.sh`). The first run
afterwards still prompts once, because the stored item has never seen this
signed application — click **Always Allow** there and it stays allowed across
every rebuild after it.

Without the certificate nothing changes and the build runs unsigned, so a
fresh checkout needs no setup.

To produce a `.app` and `.dmg`:

```bash
cargo tauri build
```

Unsigned, Gatekeeper will refuse the result on any Mac but the one that built
it — fine for local testing, not for sending to anyone. See
[docs/releasing.md](docs/releasing.md) for signing and notarisation.

### The browser extension

The app writes its own native messaging host manifest on startup, so there is no
install script to run. Load `extension/` as an unpacked extension in Chrome,
Brave, Edge, Arc, Dia, Vivaldi or Opera, then pair it from the extension popup —
the app will ask you to approve the browser in its own window. That approval is
what stops anything else on this Mac from reading your vault.

### Some sample data

`sample-data.csv` has 21 rows — logins, API keys and env secrets — for filling
an empty vault with something worth looking at. Settings → Import.

## Layout

| Crate | What it is |
|---|---|
| `mortise-crypto` | The cryptographic core. No Tauri, no UI, no network. |
| `mortise-vault` | Local encrypted store. SQLite, no network. |
| `mortise-macos` | Keychain integration. The only crate here that uses `unsafe`. |
| `mortise-app` | The Tauri desktop app and its IPC surface. |
| `mortise-proxy` | Native messaging bridge to the browser extension. |
| `mortise-sync` | Client side of sync. Moves signed ciphertext to and from a relay. |
| `mortise-relay` | The relay. Stores signed ciphertext it cannot read. |

`ui/` is the Svelte 5 frontend, `extension/` the browser extension, `web/` the
landing page.

All crypto and all storage stay in the Rust process. The webview is treated as
untrusted: it receives DTOs over a small explicit IPC surface and never sees a
key.

## Reading the security design

- [Threat model](docs/threat-model.md) — what is defended, what is not, and who
  the adversary is assumed to be.
- [Cryptographic specification](docs/crypto-spec.md) — the key hierarchy, the
  primitives, and the exact inputs to every derivation.

Both are written to be checkable rather than reassuring. If something in them is
wrong, that is worth an issue more than anything else here.

## Licence

AGPL-3.0-or-later.
