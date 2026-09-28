//! Agent Guard known-secret index: spec §8.
//!
//! Tier 1 of detection. Because we hold the user's actual secrets, we can match
//! exactly rather than guessing with regex — near-zero false positives, which
//! is the difference between a guard people leave on and one they disable in
//! week one.
//!
//! The index never holds plaintext. Each entry is `HMAC(scan_key, secret)`, so
//! dumping it reveals nothing without the MUK. It lives in memory only while
//! the vault is unlocked and is zeroized on lock.
//!
//! Scanning tokenizes, HMACs each token, and checks the set: O(tokens), with no
//! plaintext comparison anywhere in the path.
//!
//! **Known limitation** (spec §8): whole-token matching misses a secret split
//! across lines or concatenated with other text. The Tier-2 pattern pass, which
//! lives above this crate, is the backstop.

use std::collections::HashMap;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::item::ItemId;
use crate::secret::Key32;

/// Shortest secret the index will store or match.
///
/// Matching a 4-character value would fire on ordinary prose constantly. Short
/// secrets are not protected by Tier 1; that is a deliberate false-positive
/// trade, not an oversight.
pub const MIN_SECRET_LEN: usize = 8;

/// Characters that end a token.
///
/// Deliberately excludes `-`, `_`, `.`, `/`, `:` and `+`: those appear *inside*
/// real secrets (`sk-ant-...`, base64) and splitting on them would fragment
/// every token we care about.
const DELIMITERS: &[char] = &[
    ' ', '\t', '\n', '\r', '"', '\'', '`', ',', ';', '(', ')', '[', ']', '{', '}', '<', '>', '|',
    '&', '\\',
];

/// A hit: a token in the scanned text that matches a stored secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuardMatch {
    /// The vault item whose secret was matched.
    pub item: ItemId,
    /// Byte offset of the match within the scanned text.
    pub start: usize,
    /// Byte length of the matched token.
    pub len: usize,
}

/// An in-memory index of the user's secrets, keyed by HMAC.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct GuardIndex {
    scan_key: Key32,
    #[zeroize(skip)]
    entries: HashMap<[u8; 32], ItemId>,
}

impl GuardIndex {
    /// Build an empty index under the guard scan key.
    ///
    /// The key comes from `kdf::derive_guard_key`, never from the MUK directly.
    pub fn new(scan_key: Key32) -> Self {
        Self {
            scan_key,
            entries: HashMap::new(),
        }
    }

    /// Number of indexed secrets.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the index holds nothing.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Index one secret against the item it belongs to.
    ///
    /// Returns `false` if the value was too short to index.
    ///
    /// Two items sharing a secret collapse to one entry, last write winning.
    /// That is acceptable here: the guard's job is to warn that *a* stored
    /// secret is leaving the machine, not to enumerate every item holding it.
    pub fn insert(&mut self, secret: &str, item: ItemId) -> bool {
        let normalized = normalize(secret);
        if normalized.len() < MIN_SECRET_LEN {
            return false;
        }
        self.entries.insert(self.tag(normalized), item);
        true
    }

    /// Remove a secret from the index.
    pub fn remove(&mut self, secret: &str) -> bool {
        let normalized = normalize(secret);
        self.entries.remove(&self.tag(normalized)).is_some()
    }

    /// Drop every entry. Call on vault lock.
    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Whether this exact value is a known secret.
    pub fn lookup(&self, candidate: &str) -> Option<ItemId> {
        let normalized = normalize(candidate);
        if normalized.len() < MIN_SECRET_LEN {
            return None;
        }
        self.entries.get(&self.tag(normalized)).copied()
    }

    /// Scan text and report every token that matches a stored secret.
    pub fn scan(&self, text: &str) -> Vec<GuardMatch> {
        let mut hits = Vec::new();

        for (start, token) in tokenize(text) {
            for (offset, candidate) in candidates(token) {
                if candidate.len() < MIN_SECRET_LEN {
                    continue;
                }
                if let Some(item) = self.entries.get(&self.tag(candidate)) {
                    hits.push(GuardMatch {
                        item: *item,
                        start: start + offset,
                        len: candidate.len(),
                    });
                    break;
                }
            }
        }

        hits
    }

    fn tag(&self, value: &str) -> [u8; 32] {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(self.scan_key.expose())
            .expect("HMAC accepts any key length");
        mac.update(value.as_bytes());
        mac.finalize().into_bytes().into()
    }
}

impl core::fmt::Debug for GuardIndex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "GuardIndex({} entries, redacted)", self.entries.len())
    }
}

/// Trim whitespace and one layer of surrounding quotes.
///
/// No case folding: secrets are case-sensitive, and folding would create
/// collisions between values that are genuinely different.
fn normalize(value: &str) -> &str {
    let trimmed = value.trim();
    let bytes = trimmed.as_bytes();

    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if first == last && (first == b'"' || first == b'\'' || first == b'`') {
            return &trimmed[1..trimmed.len() - 1];
        }
    }
    trimmed
}

/// Split text into tokens, keeping each token's byte offset.
fn tokenize(text: &str) -> impl Iterator<Item = (usize, &str)> {
    text.split_inclusive(DELIMITERS)
        .scan(0usize, |offset, raw| {
            let start = *offset;
            *offset += raw.len();
            let token = raw.trim_end_matches(DELIMITERS);
            Some((start, token))
        })
}

/// Candidate values for one token, each with its offset inside the token.
///
/// A token may itself be an assignment (`API_KEY=sk-ant-...`), so the part
/// after the first `=` is also a candidate. `=` is not a delimiter, because
/// splitting on it would strip base64 padding off real secrets.
fn candidates(token: &str) -> impl Iterator<Item = (usize, &str)> {
    let whole = normalize(token);
    let whole_offset = whole.as_ptr() as usize - token.as_ptr() as usize;

    let after_eq = token.find('=').and_then(|i| {
        let rest = normalize(&token[i + 1..]);
        if rest.is_empty() {
            None
        } else {
            Some((rest.as_ptr() as usize - token.as_ptr() as usize, rest))
        }
    });

    core::iter::once((whole_offset, whole)).chain(after_eq)
}
