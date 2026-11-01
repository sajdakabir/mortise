# Mortise — Cryptographic Specification v1

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
| Key agreement / sealing | HPKE (RFC 9180) | DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20-Poly1305. Standardized; do not hand-roll NaCl box. Auth mode for vault keys (§3), AuthPSK mode for join requests (§6.4) |
| Hashing / change chain | BLAKE3 | Plain hash for ids and the change chain; `derive_key` mode (context string = `info`) for fingerprints (§6.5); keyed mode for environment item ids (§6.7) |
| Guard index | HMAC-SHA-256 | |
| Randomness | OS CSPRNG (`getrandom`) | Never a userspace PRNG for key material |

Rust crates: `argon2`, `hkdf`, `chacha20poly1305`, `ed25519-dalek`, `hpke`,
`blake3`, `hmac`, `sha2`, `zeroize`, `subtle`, `getrandom`.

`hpke` supplies the X25519 keypair, so `x25519-dalek` is not a separate
dependency. `secrecy` is not used either: `SecretBytes<N>` in `secret.rs` covers
the fixed-size key material this crate handles, with constant-time comparison
that `secrecy` does not provide.

All `info` strings are prefixed `truepass/v1/` so a future v2 cannot collide.
The complete registry — adding one is a spec change:

| String | Used as | Section |
|---|---|---|
| `truepass/v1/muk`, `dbkey`, `guard-index`, `metakey` | HKDF info | §2.1 |
| `truepass/v1/identity`, `truepass/v1/device` | AEAD AAD wrapping keys under the MUK | §2 |
| `truepass/v1/vaultkey` | HPKE info, vault-key wrapping | §3 |
| `truepass/v1/invite-mailbox`, `truepass/v1/invite-psk` | HKDF info from an invite secret | §6.4 |
| `truepass/v1/join-request` | HPKE info, join requests | §6.4 |
| `truepass/v1/fingerprint` | BLAKE3 `derive_key` context | §6.5 |
| `truepass/v1/env-item-id` | HKDF info from `VK@0` | §6.7 |

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
META_KEY    = HKDF-SHA256(ikm = MUK, info = "truepass/v1/metakey") -> 32 B
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

A device certificate travels as exactly 185 bytes:

```
cert = canonical ‖ signature
canonical = 0x01 (tag DeviceCert) ‖ identity_pub(32) ‖ device_id(16)
            ‖ device_sign_pub(32) ‖ device_kex_pub(32) ‖ issued_at_ms(u64 BE)
signature = Ed25519(identity_sk, BLAKE3(canonical))          (64 bytes)
```

A decoder rejects anything that is not 185 bytes, whose tag is not `0x01`,
whose `device_id` is not `BLAKE3(device_sign_pub)[..16]`, or whose signature
does not verify under `identity_pub`. A certificate that verifies proves only
that *some* identity vouches for the device; which identity it should be is the
fingerprint check of §6.5.

One device id serves every vault on a machine: a project vault (§6.1) copies the
device keys of the personal vault rather than minting new ones, so membership,
which is per device (§6), names the same device in every vault it belongs to.

## 3. Vault and item encryption

```
VK@n   = 256-bit random             n = key epoch, incremented on every revocation
per member device d, sealed by an admin device s:
  wrapped_VK[d] = HPKE_Seal_Auth(sk_kex(s), pk_kex(d), VK@n,
                                 info = "truepass/v1/vaultkey",
                                 aad  = vault_id ‖ epoch ‖ device_id(s))
  stored as:  0x02 ‖ device_id(s) ‖ epoch ‖ encapped ‖ ciphertext

IK     = 256-bit random, per item version
sealed_IK  = XChaCha20P1305(key = VK@n, nonce = random_24B, pt = IK)
ciphertext = XChaCha20P1305(key = IK, nonce = random_24B,
                            pt  = payload_bytes,
                            aad = vault_id ‖ item_id ‖ version ‖ epoch)
```

**Wrapped keys are authenticated (HPKE Auth mode).** Earlier builds used Base
mode, which gives confidentiality but no sender authentication: a wrapped key
that opened proved only that somebody knew the recipient's public key, which is
public. Anyone able to write where a device reads its wrapped keys — a hostile
relay, or a member revoked after it synced the ACL — could substitute a vault
key of their choosing. Auth mode binds the seal to the sealing device's X25519
key; the recipient authenticates against it and accepts the key only if that
device is a current admin or owner in the ACL (whose device key an admin's
signed `AddMember` attests). Neither a relay nor a revoked member holds an
admin's device key, so neither can forge an accepted substitute. The sender id
travels in the blob and is bound into the AAD, so it cannot be relabelled.

The wrapped-key format is versioned: a leading `0x02` and a `format` column mark
an authenticated blob. A vault written in the old Base-mode format is read once
on the legacy path and re-sealed to the opening device in Auth mode, in place,
on its next unlock — so no vault is stranded. Every device re-seals the keys it
receives to itself, so in steady state a key is always authenticated by the
device that stored it.

Authenticated wrapping closes the substitution hole, and §6 carries the ACL
entries and re-wrapped keys that make a revocation take effect on every device,
not just the one that issued it.

**The AAD is not optional.** Binding each ciphertext to its own identity stops an
attacker with write access to the relay (A1) from swapping one item's blob for
another's — moving your low-value ciphertext into a high-value item's slot.

Per-item keys exist so a single credential can be shared without the whole vault,
and so rotation is cheap.

## 4. Local storage

Plain SQLite. **Not SQLCipher** — this reverses the original decision; see §4.2.

Nothing sensitive is in a plaintext column. Each item carries three encrypted
blobs, under three different keys, because they have three different jobs:

| Blob | Key | Why that key |
|---|---|---|
| `ciphertext` + `sealed_item_key` | item key, wrapped under the vault key | the secret; decrypted one item at a time, on demand |
| `sealed_meta` | vault key | canonical metadata; syncs, and shared-vault members must be able to read it |
| `search_cache.sealed` | `META_KEY` (account-scoped) | local cache; must stay readable while locked, must never leave this machine |

Plaintext columns are limited to ids, version and epoch counters, item kind, and
timestamps.

### 4.1 Why metadata needs two keys

The vault key is dropped on lock and is shared with other vault members. Neither
property suits a search cache, which has to survive locking (so the menu-bar
search works without a password prompt) and must never be readable by anyone
else. So canonical metadata is sealed under the vault key and a local cache is
sealed under `META_KEY`, derived from the MUK.

The cache is derived data: safe to drop, rebuildable from the canonical blobs on
the next unlock. That is also the repair path when sync pulls items this device
has never seen.

Consequence, unchanged from before: **"locked" protects secrets, not metadata**,
against a process that is still running. Full sign-out drops `META_KEY` too.

### 4.2 Why not SQLCipher

On macOS, SQLCipher means either vendoring OpenSSL into the binary or requiring
brew's OpenSSL on every build machine. Both work against the explicit "keep it
light" product goal, and both add a second crypto stack to audit beside the one
in `mortise-crypto`.

What SQLCipher actually buys is metadata-at-rest encryption, and the table above
already provides that through the audited XChaCha20-Poly1305 path.

What is given up, stated plainly: the file is not opaque. An attacker holding it
at rest learns the row count, the table shape, and blob sizes. They do not learn
titles, URLs, usernames, or any secret. Recorded against A4 in the threat model.

This forecloses nothing. The two layers compose: adding SQLCipher later is one
`PRAGMA key` and changes no schema. It becomes optional defence-in-depth rather
than the thing holding the roof up. `DB_KEY` (§2.1) is still derived and
currently unused, reserved for exactly that.

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

| Tag | Type | Section |
|---|---|---|
| `0x01` | device certificate | §2.3 |
| `0x02` | change | §5 |
| `0x03` | ACL entry | §6 |
| `0x04` | invite | §6.4 |
| `0x05` | join request (plaintext) | §6.4 |

`lp(x)` below means `u32 BE length ‖ x`, the `bytes` field of this encoding.

Payload bytes are opaque to this crate: serialization of item contents belongs
to the layer above, which keeps the crypto core free of a serde format.

## 6. ACL and revocation

The ACL is its own append-only signed log, mirroring the role any-sync gives its
consensus node. Operations: `add_member`, `remove_member`, `change_role`,
`rotate_key`. Only signatures from `owner` or `admin` are accepted.

Revocation sequence:
1. Append `remove_member(pk)`, signed.
2. Increment epoch, generate `VK@n+1`.
3. Re-wrap `VK@n+1` (Auth mode, §3) for every remaining member device.
4. All subsequent changes use the new epoch.

Steps 1 and 2 are committed together through the two-phase protocol of §6.3:
`VK@n+1` exists only in memory until the relay has accepted both entries, so a
revocation that loses a race leaves no orphaned key behind.

**It travels on sync.** The ACL is its own signed log, carried over the relay
the same way changes are: entries are pushed and pulled, ordered by their strict
sequence number, and each is verified on apply. The re-wrapped keys from step 3
travel too, addressed to each remaining device, which authenticates one against
the ACL (the sealer must be a current admin) and re-seals it to itself. So a
removal and rotation reach every device on its next sync — not only the one that
issued them — and the relay is additionally told to stop serving the removed
device. Until a peer syncs it still trusts that device; propagation is as prompt
as sync, not instant.

**Forward secrecy only.** The removed member keeps anything they already synced.
Cryptography cannot fix this. The UI must say so and offer to rotate the
underlying credentials — see A8. Rotation does not re-seal existing items under
the new key: it protects what is written afterwards, nothing more, and
re-sealing what the removed device already holds would buy nothing.

Membership is **per device** (`add_member` names a device key, not an account).
Someone with two Macs is two members, each granted on its own.

### 6.1 Project vaults

A project that is shared is its own vault: its own vault id, ACL, key epochs,
change log, DAG heads and relay cursor, in its own file. Nothing about one vault's
membership can leak into another's, because no table is shared between them.

A project vault file carries copies of the account row (salt, Argon2 parameters)
and of the identity and device keys, still sealed under the MUK. It therefore
unlocks with the MUK the personal vault's unlock already derived — no second
Argon2 run, no second password — and it signs with the same device key (§2.3).
Its own vault keys are generated per vault and sealed to that device (§3).

The project's definition — name, description, environments, member labels —
lives in the project vault's change log as ordinary sealed changes (§6.6), so it
syncs to members exactly like secrets do. A project that has never been shared
is unchanged: its definition is sealed under `META_KEY` (§4.1) and its items
carry the project's name as a label inside the personal vault. Sharing one
promotes it: a project vault is created, each item is re-sealed into it (§6.7
gives environment secrets their deterministic ids), and the originals are
deleted from the personal vault through the change log, so the deletion syncs to
the account's other devices.

### 6.2 The genesis owner

The genesis ACL names one owner device that no entry introduces. Every replay
starts from it, so it is stored explicitly with the vault — signing key and
X25519 key — rather than inferred from the set of trusted devices:

- the device that creates a vault records itself;
- a device joining someone else's project pins the owner keys carried in the
  invite (§6.4);
- a device enrolled into the same account copies them from the enrolment
  bundle.

Removing the genesis owner is legal when another owner remains (`acl.rs`), and
after it the owner's device is no longer trusted for changes; the stored genesis
keys are used for nothing but replay, so the ACL still replays.

### 6.3 Committing an ACL change

The ACL is a strict sequence, so two admins editing it at once cannot both win.
They must not silently fork either. A change is therefore committed in two
phases against the relay, which serializes:

1. **Pull** the ACL to the relay's head.
2. **Build and sign** the entries against that head without applying them. A
   revocation builds `remove_member` and `rotate_key` together, holding the new
   epoch's key in memory only.
3. **Push.** The relay accepts entry `n` only if it holds entry `n − 1` and the
   entry's `prev` equals that entry's id (entry 1: only if it holds none). It
   answers per entry: *accepted*, *duplicate* (the same id is already stored at
   that sequence number) or *conflict*.
4. **Apply** locally, and store the new key, only for entries the relay
   accepted (or already held). On conflict, pull again, re-check the intent
   against the new ACL — the member may already be gone, the role already set —
   and re-issue once. A second conflict fails the operation with "someone else
   changed membership"; nothing was applied locally.

The relay's acceptance is not trusted for safety — clients verify every entry on
apply, and a relay can only refuse — but an honest relay is what turns
concurrent edits into a visible conflict instead of a fork.

**Fork detection.** A client pulling the ACL asks for entries from its own head
onward, including the head itself, and requires the relay's entry at that
sequence number to have the same id as its local head. A mismatch means the
relay is serving a different history (or the client's own entries were never
accepted): the pull stops with an error and applies nothing. A relay can still
withhold a suffix of the log; that is the "as prompt as sync" residual of A8.

### 6.4 Invites and joining

Joining someone else's project takes one link from the owner and one click from
the owner. The link carries everything the joiner must trust, and a secret that
authenticates the joiner's answer.

```
secret      = 32 random bytes
mailbox_id  = HKDF-SHA256(ikm = secret, info = "truepass/v1/invite-mailbox")[..16]
psk         = HKDF-SHA256(ikm = secret, info = "truepass/v1/invite-psk")      -> 32 B

invite = 0x04 ‖ vault_id(16) ‖ lp(relay_url) ‖ lp(inviter_cert)
         ‖ lp(inviter_name) ‖ lp(project_name)
         ‖ owner_sign_pub(32) ‖ owner_kex_pub(32)
         ‖ secret(32) ‖ expires_at_ms(u64 BE)
link   = "mortise://join#" ‖ base64url_nopad(invite ‖ BLAKE3(invite)[..4])
```

`inviter_cert` is the inviting device's certificate (§2.3); `owner_*` are the
genesis owner's device keys (§6.2), which differ from the inviter's when an admin
invites. The four-byte checksum only catches a link damaged in copying.

The invite is not signed. It travels over whatever channel the owner picks, and
anyone able to alter it there can replace a signature along with everything
else. What protects the joiner is the fingerprint (§6.5) of the inviter's
identity, shown before anything is sent. What protects the owner is that nothing
is granted without their explicit action.

A decoder refuses: a bad checksum or tag; a relay URL that is not `https://`, or
`http://` to a loopback address (the rule the relay setting uses); a person's
name over 64 bytes, a project name over 128, or a URL over 2048; an empty name,
or one containing control characters or Unicode bidi overrides (both let a name
render as something it is not, beside a fingerprint someone is comparing); a
certificate (`lp` of exactly 185 bytes) that does not verify; trailing bytes; an
expired invite.

**Mailbox.** On creating an invite the inviter registers `mailbox_id` with the
relay, authenticated as a device of the vault, with an expiry of at most seven
days. The relay keeps at most one request per mailbox: the first post is stored,
any later one refused. The mailbox is deleted on expiry or when the inviter
closes it. The relay sees the mailbox id, never the secret.

**Join request.** The joiner posts one sealed request to the mailbox:

```
pt      = 0x05 ‖ lp(joiner_cert) ‖ lp(joiner_name)
ct      = HPKE AuthPSK Seal(skS = joiner device X25519, pkR = inviter_cert.device_kex,
                            info   = "truepass/v1/join-request",
                            psk    = psk, psk_id = mailbox_id,
                            aad    = vault_id ‖ mailbox_id,
                            pt)
request = 0x01 ‖ joiner_kex_pub(32) ‖ encapped(32) ‖ ct
```

The inviter opens it with its device key, the psk derived from the secret it
kept, and the sender key in the request, then requires the plaintext tag, a
joiner certificate that verifies, and that certificate's device X25519 key to
equal the sender key. So:

- the relay cannot fabricate a request, or alter one, because it does not hold
  the psk, which only the link carries;
- a request cannot be replayed into another invite, because each has its own
  psk and both ids are in the AAD;
- the request proves possession of the joiner device's X25519 key, and the
  certificate proves which identity vouches for that device.

Anyone holding the link can produce a valid request — it is a bearer secret. So
nothing is granted automatically. The owner's app shows the requester's
identity fingerprint first, their self-chosen name beside it, and a role picker.
**Only on Grant** does it:

1. pull the ACL and commit `add_member(joiner device, role)` (§6.3);
2. seal every epoch's vault key to the joiner device (Auth mode, §3) and deliver
   them over the relay — every epoch, so history opens;
3. write the joiner's member label (§6.6), recording their name and certificate;
4. claim the vault on the relay if it was never synced, authorize the joiner
   device there, and push.

**The joiner** creates the project vault locally with no vault key ("waiting for
access"), pins `owner_sign_pub`/`owner_kex_pub` as the genesis owner (§6.2),
and syncs in order: the ACL, replayed from the pinned owner and required to
contain an `add_member` of its own device before it considers itself a member;
then keys, each accepted only if sealed by a device that ACL makes an admin or
owner (§3); then changes, verified as always (§5). A relay that serves another
ACL or a key of its own choosing cannot make either verify from the pinned owner.

### 6.5 Fingerprints

```
fp      = BLAKE3 derive_key(context = "truepass/v1/fingerprint", identity_pub), 60-byte XOF output
group_i = u40_be(fp[5i .. 5i+5]) mod 100000            for i = 0..11
shown   = the twelve groups as zero-padded 5-digit numbers, space separated
```

Sixty digits, about 199 bits; the modulo bias is below 2⁻²³ per group. The
fingerprint covers the **identity** key only: one person's devices share it,
and the device certificate (§2.3) is what binds a device to that identity.

Display names are self-chosen, recorded by whoever grants access, and synced.
They can impersonate anyone. The fingerprint is the authority, and the UI shows
it beside every name it shows.

### 6.6 Project manifest

A project vault's definition is three kinds of mutation in its change log,
sealed under the vault key like any change (§5):

| Mutation | Merge |
|---|---|
| `set_info { name, description }` | last-write-wins on the pair, ordered by `(HLC, device_id)` |
| `add_environment { name }` | add-only set, compared ASCII-case-insensitively; the earliest add by `(HLC, device_id)` keeps its spelling and sets the order |
| `set_member_label { device_id, name, cert }` | last-write-wins per device |

A member label is applied only if its author is the labelled device or an
admin/owner, and only if `cert` verifies and certifies a device whose signing key
equals the ACL's. Like every change, manifest changes from a viewer or a
non-member are refused on ingest (§6), and refused locally before they are made.
Each device materializes the result into a local row sealed under `META_KEY`, so
the project list draws while locked, as the search cache does (§4.1).

### 6.7 Environment item ids

```
env_id_key = HKDF-SHA256(ikm = VK@0, info = "truepass/v1/env-item-id")
item_id    = BLAKE3 keyed(env_id_key, vault_id ‖ lp(lower_ascii(environment)) ‖ lp(KEY))[..16]
```

Deterministic, so two members who create the same `KEY` in the same environment
write the same item and last-write-wins converges, instead of leaving two items
that an `.env` export would emit twice. `KEY` is case-sensitive, as environment
variables are; the environment name is not, matching §6.6.

Keyed, rather than a plain hash of the name, so that an id in the local file or
on the relay does not let someone without the vault key confirm a guess like
`STRIPE_SECRET_KEY` — titles stay unreadable at rest (A4). The key comes from the
vault's first epoch, which every member receives (§6.4), so it never changes
under rotation.

### 6.8 Delivering wrapped keys

The relay stores a delivered key per `(vault, recipient, epoch, pusher)`, where
the pusher is the authenticated device that sent it. One member therefore cannot
overwrite a key another device delivered, which would otherwise be a cheap
denial of service. The recipient tries every candidate for an epoch and keeps
the first that authenticates as sealed by a current admin or owner (§3).

### 6.9 Leaving and removal

A member may remove itself: `remove_member` authored by the removed device is
legal at any role. Leaving cannot rotate the key — a member cannot — so the first
admin or owner device to sync that finds a `remove_member` with no `rotate_key`
after it commits the rotation itself (§6.3) and re-wraps for those who remain.
Until then the departed device can still open what it is sent, and an offline
device keeps working locally until it next syncs.

A device that pulls its own `remove_member`, or that the relay refuses after it
had been a member, marks the vault **access removed**: it stops syncing it and
keeps the local copy, read-only. It is not deleted — the person has seen it all
already, and deleting it would only destroy their own notes on it.

### Key discovery

Mortise runs no key directory. The inviter's keys reach the joiner inside the
link, and the joiner's come back through the mailbox, authenticated by the
link's secret (§6.4). Each side is shown the other's fingerprint (§6.5) for
checking out of band; the owner sees it before granting anything.

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

- All crypto in `mortise-crypto`, a standalone crate with **no** dependency on
  Tauri, the UI, or the network. It must be testable in isolation.
- Known-answer tests for every derivation in §2.1. Fixed vectors, committed.
- Property tests: seal/open round-trips, AAD tampering is rejected, signature
  forgery is rejected, epoch rollback is rejected.
- `SecretBox`/`Zeroizing` for every key. Never `String` for key material.
- The webview never receives a key. `reveal_item(id)` returns one secret, for one
  item, and the UI holds it only as long as it is displayed.
- No `unsafe` in the crypto crate without a written justification in review.

## 10. Unresolved

- Passkey (WebAuthn) private keys: mechanism deferred. Note that there is no
  item schema *in this crate* to reserve a slot in — payloads are opaque bytes
  here by design (§5.1), so the schema question lands in M2 with the vault
  layer, not M1. It still must not slip past M2: retrofitting the item model
  later is expensive.
- **Argon2 parameters: measured, not yet frozen.** Unlock cost (password stretch
  + MUK derivation), best of 3, release build, Apple M4:

  | Parameters | Unlock |
  |---|---|
  | OWASP floor — 19 MiB, t=2, p=1 | 13.5 ms |
  | Current default — 64 MiB, t=3, p=4 | 69.5 ms |
  | 128 MiB, t=4, p=4 | 197 ms |

  69.5 ms is imperceptible, which means the current default is leaving offline
  resistance (A4) on the table. A password manager should be spending closer to
  half a second on its *slowest* supported machine.

  The gap in this data is that an M4 is the fastest Apple Silicon there is. An
  older Intel Mac is plausibly 3–5x slower, which would put 128 MiB / t=4 in the
  0.6–1 s range there — an estimate, not a measurement. Re-run
  `cargo run --release --example bench_kdf` on the oldest target before
  deciding. Raising the default is a one-constant change plus its pinned test.
- Whether `AK` in the keychain weakens A4 more than biometric unlock is worth.
  Measure the real-world threat before deciding; default to storing it, since a
  user who disables biometrics gets the stronger posture anyway.
