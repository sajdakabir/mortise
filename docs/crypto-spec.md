# TruePassword — Cryptographic Specification v1

Status: draft, M0. Read [threat-model.md](threat-model.md) first; every choice
here traces to an adversary listed there.

Rule for implementers: **no primitive, parameter, or encoding outside this
document.** If something is needed that is not here, amend this file first.

## 1. Primitives

| Purpose | Algorithm | Notes |
|---|---|---|
| Password KDF | Argon2id | m = 64 MiB, t = 3, p = 4. Parameters stored per-vault so they can be raised later |
| Key derivation | HKDF-SHA-256 | Domain-separated by `info` string. Never reuse an `info` |
| AEAD | XChaCha20-Poly1305 | 192-bit nonce, so **random nonces are safe**. This is why XChaCha and not ChaCha |
| Signing | Ed25519 | |
| Key agreement / sealing | HPKE (RFC 9180) | DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20-Poly1305. Standardized; do not hand-roll NaCl box |
| Hashing / change chain | BLAKE3 | |
| Guard index | HMAC-SHA-256 | |
| Randomness | OS CSPRNG (`getrandom`) | Never a userspace PRNG for key material |

Rust crates: `argon2`, `hkdf`, `chacha20poly1305`, `ed25519-dalek`, `hpke`,
`blake3`, `hmac`, `sha2`, `zeroize`, `subtle`, `getrandom`.

`hpke` supplies the X25519 keypair, so `x25519-dalek` is not a separate
dependency. `secrecy` is not used either: `SecretBytes<N>` in `secret.rs` covers
the fixed-size key material this crate handles, with constant-time comparison
that `secrecy` does not provide.

All `info` strings are prefixed `truepass/v1/` so a future v2 cannot collide.

## 2. Key hierarchy

```
  master password (MP)                 account key (AK)
  user's head, never stored            256-bit CSPRNG, recovery kit
          │                                     │
          └──── Argon2id(MP, S_user) ───┐       │
                                        ▼       ▼
                    MUK = HKDF(ikm = stretch ‖ AK,
                               salt = S_user,
                               info = "truepass/v1/muk")
                                        │
        ┌───────────────────────────────┼───────────────────────────┐
        ▼                               ▼                           ▼
   identity keys                   DB_KEY (SQLCipher)          guard scan_key
   Ed25519 + X25519                                            (memory only)
   wrapped under MUK
        │
        └── signs ──> per-device keypairs (one per machine)
                             │
                             └── HPKE-unwraps ──> Vault Key VK@epoch
                                                        │
                                                        └── wraps ──> Item Key
                                                                          │
                                                                          └── seals item payload
```

### 2.1 Derivation, exactly

```
S_user      = 128-bit random, generated at account creation, stored with vault
stretch     = Argon2id(password = MP, salt = S_user, m = 64MiB, t = 3, p = 4) -> 32 B
MUK         = HKDF-SHA256(ikm = stretch ‖ AK, salt = S_user,
                          info = "truepass/v1/muk") -> 32 B
DB_KEY      = HKDF-SHA256(ikm = MUK, info = "truepass/v1/dbkey")   -> 32 B
scan_key    = HKDF-SHA256(ikm = MUK, info = "truepass/v1/guard-index") -> 32 B
```

`MUK` is never written to disk. `AK` is written to the macOS keychain with an
access-control ACL so the app can offer Touch ID unlock without re-entering it;
the master password is still required on cold start unless biometric unlock is
explicitly enabled.

### 2.2 Why the account key exists

Without `AK`, adversary **A4** (offline attacker holding the vault) faces only a
human-chosen password behind Argon2id. With a 256-bit `AK` the offline attack is
dead regardless of password quality. The cost is a recovery kit the user must not
lose — see §7.

### 2.3 Per-device keys

Each device generates its own Ed25519 + X25519 pair. The identity key signs a
device certificate binding the device pubkeys to the account. Vault keys are
sealed **to device keys**, not to the identity key.

This means a lost laptop is revoked by removing one device cert and rotating,
without re-keying the identity or forcing every other device to re-enroll.

## 3. Vault and item encryption

```
VK@n   = 256-bit random             n = key epoch, incremented on every revocation
per member device d:
  wrapped_VK[d] = HPKE_Seal(pk_kex(d), VK@n, info = "truepass/v1/vaultkey")

IK     = 256-bit random, per item version
sealed_IK  = XChaCha20P1305(key = VK@n, nonce = random_24B, pt = IK)
ciphertext = XChaCha20P1305(key = IK, nonce = random_24B,
                            pt  = payload_bytes,
                            aad = vault_id ‖ item_id ‖ version ‖ epoch)
```

**The AAD is not optional.** Binding each ciphertext to its own identity stops an
attacker with write access to the relay (A1) from swapping one item's blob for
another's — moving your low-value ciphertext into a high-value item's slot.

Per-item keys exist so a single credential can be shared without the whole vault,
and so rotation is cheap.

## 4. Local storage

SQLite, encrypted whole-file with SQLCipher under `DB_KEY`. Inside it, each item
row **still** stores the sealed blob from §3 rather than plaintext.

Two layers, two reasons:
- SQLCipher protects metadata at rest against A4.
- Per-item sealing is what lets sync ship rows verbatim and lets sharing work at
  item granularity. It is not defence-in-depth theatre; it is load-bearing.

Item metadata (title, URL, folder, timestamps) is stored **decrypted** inside the
SQLCipher file, so search works while the vault is locked. Consequence: "locked"
protects secrets, not metadata, against a live process. Stated in the threat model.

## 5. Change log and sync

Every mutation is an immutable, signed, hash-chained change.

```
change = {
  id:          BLAKE3(canonical(change_without_sig)),
  vault_id, epoch,
  parents:     [change_id, ...],        # DAG, not a line
  hlc:         hybrid logical clock,
  author:      device_id,
  payload:     ciphertext from §3,
  sig:         Ed25519(device_sk_sign, id),
}
```

Clients **reject** any change whose signature fails, whose author is not in the
ACL at that epoch, or whose parents are unknown. This is what makes a hostile
relay (A1) unable to forge or reorder history.

Merge: last-write-wins per field, ordered by HLC, ties broken by `device_id`.

Deliberately **not** Automerge. A vault needs no collaborative text merging, and
the dependency works against the "light" goal. The hash-linked signed log gives
versioning and point-in-time recovery for free — which is exactly the
Infisical-style feature the dev-secrets layer needs later.

### 5.1 Canonical encoding

`canonical(...)` is **not** CBOR. This spec originally said "canonical CBOR";
that was a mistake. `ciborium` gives no canonical-output guarantee — map key
ordering in particular is unpinned — and for a hash-linked log that is not
cosmetic: two devices could encode the same logical change to different bytes,
compute different ids, and fork the DAG permanently.

Instead the encoding removes the failure mode by construction:

- no maps, so there is no key ordering to get wrong
- no self-description, so there is no tag or length representation to choose
- fixed field order, written explicitly per type
- explicit `u32` length prefixes, so concatenation is unambiguous
- fixed-width big-endian integers
- a leading one-byte type tag, so a signature over one struct can never be
  replayed as a signature over another

Type tags are permanent. Renumbering one silently invalidates every signature
ever produced over that type.

Payload bytes are opaque to this crate: serialization of item contents belongs
to the layer above, which keeps the crypto core free of a serde format.

## 6. ACL and revocation

The ACL is its own append-only signed log, mirroring the role any-sync gives its
consensus node. Operations: `add_member`, `remove_member`, `change_role`,
`rotate_key`. Only signatures from `owner` or `admin` are accepted.

Revocation sequence:
1. Append `remove_member(pk)`, signed.
2. Increment epoch, generate `VK@n+1`.
3. Re-wrap `VK@n+1` for every remaining member device.
4. All subsequent changes use the new epoch.

**Forward secrecy only.** The removed member keeps anything they already synced.
Cryptography cannot fix this. The UI must say so and offer to rotate the
underlying credentials — see A8.

### Sharing and key discovery

The default path embeds the recipient's X25519 public key **in the invite link**,
so sealing never consults our directory. Directory lookup is a fallback, and
carries the A3 risk. Fingerprints are shown in the UI for out-of-band checking.

## 7. Recovery

Recovery kit contains the account key (base32, grouped, plus QR) and the account
identifier. **Both master password and account key are required** — the kit alone
is not a bypass, and neither is the password alone.

Losing both means the data is gone. There is no escrow, no reset, no support
path. This must be shown at onboarding, not buried.

## 8. Agent Guard index

```
scan_key = HKDF-SHA256(MUK, info = "truepass/v1/guard-index")
index    = { HMAC-SHA256(scan_key, normalize(secret)) -> item_id }
```

`normalize` trims whitespace and surrounding quotes only — no case folding, since
secrets are case-sensitive. The index lives in memory while unlocked and is
zeroized on lock. Dumping it reveals nothing without `MUK`.

Scanning tokenizes input on whitespace and common delimiters, HMACs each token,
and checks the set: O(tokens), no plaintext comparison anywhere.

Known limitation: whole-token matching misses a secret split across lines or
concatenated with other text. The Tier-2 pattern pass is the backstop.

## 9. Implementation rules

- All crypto in `truepass-crypto`, a standalone crate with **no** dependency on
  Tauri, the UI, or the network. It must be testable in isolation.
- Known-answer tests for every derivation in §2.1. Fixed vectors, committed.
- Property tests: seal/open round-trips, AAD tampering is rejected, signature
  forgery is rejected, epoch rollback is rejected.
- `SecretBox`/`Zeroizing` for every key. Never `String` for key material.
- The webview never receives a key. `reveal_item(id)` returns one secret, for one
  item, and the UI holds it only as long as it is displayed.
- No `unsafe` in the crypto crate without a written justification in review.

## 10. Unresolved

- Passkey (WebAuthn) private keys: reserve the item-schema slot in M1; mechanism
  deferred. Do not defer the schema — retrofitting the item model later is
  expensive.
- Argon2 parameters need measuring on the oldest Mac we intend to support before
  they are frozen.
- Whether `AK` in the keychain weakens A4 more than biometric unlock is worth.
  Measure the real-world threat before deciding; default to storing it, since a
  user who disables biometrics gets the stronger posture anyway.
