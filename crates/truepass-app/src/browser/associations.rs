//! Paired browsers.
//!
//! Stored as one JSON blob in the keychain rather than in the vault database,
//! for a practical reason: the extension asks whether a credential exists for a
//! page *before* the user has unlocked anything, so this has to be readable
//! while the vault is locked. Keychain, device-unlocked, never synced.

use std::collections::BTreeMap;

use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use truepass_macos::{Error as KeychainError, Protection};

use super::protocol::{Request, proof_payload};

const SERVICE: &str = "com.truepassword.desktop";
const ACCOUNT: &str = "browser-associations";

/// One paired browser.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Association {
    /// Opaque id the extension sends back.
    pub id: String,
    /// Browser name, for the settings list.
    pub name: String,
    /// Proof key, hex.
    pub key: String,
}

type Store = BTreeMap<String, Association>;

/// In-memory copy of the store, filled on first use.
///
/// Every proof check used to read the keychain, which put a keychain call on
/// the hot path of every autofill. Two things make that worse than merely
/// wasteful:
///
/// 1. macOS re-authorises a keychain item when the reading binary's signature
///    changes. In a development build `cargo` re-signs on every rebuild, so
///    each request raised a password prompt — and the app *blocks* while it is
///    up, so the extension timed out waiting for a reply.
/// 2. Even signed, it is a synchronous read per request for data that cannot
///    change without this process being the one to change it.
///
/// Caching costs nothing in safety: the process already holds the vault keys
/// in memory, so an attacker who can read this process has far more than a
/// pairing key. Writes go through [`save`], which updates both.
static CACHE: std::sync::Mutex<Option<Store>> = std::sync::Mutex::new(None);

fn load() -> Store {
    if let Ok(cache) = CACHE.lock()
        && let Some(store) = cache.as_ref()
    {
        return store.clone();
    }

    match truepass_macos::load(SERVICE, ACCOUNT, "") {
        // A read that succeeded is the truth, empty or not, so cache it.
        Ok(found) => {
            let store: Store = found
                .and_then(|bytes| serde_json::from_slice(&bytes).ok())
                .unwrap_or_default();
            if let Ok(mut cache) = CACHE.lock() {
                *cache = Some(store.clone());
            }
            store
        }
        // A read that *failed* is not evidence that nothing is paired, and
        // caching it would turn one dismissed authorisation prompt into every
        // browser appearing unpaired for as long as the app runs. Fall back to
        // empty for this call only, and try the keychain again next time.
        Err(_) => Store::new(),
    }
}

fn save(store: &Store) -> Result<(), KeychainError> {
    let json = serde_json::to_vec(store).unwrap_or_else(|_| b"{}".to_vec());
    truepass_macos::store(SERVICE, ACCOUNT, &json, Protection::DeviceUnlocked)?;
    if let Ok(mut cache) = CACHE.lock() {
        *cache = Some(store.clone());
    }
    Ok(())
}

/// Drop the cached copy, so the next read goes back to the keychain.
fn invalidate() {
    if let Ok(mut cache) = CACHE.lock() {
        *cache = None;
    }
}

/// Read the store once so later lookups never touch the keychain.
///
/// Called at startup, off the main thread. The point is *where* the keychain
/// read happens, not whether: if the first read lands on a browser request,
/// any prompt macOS raises blocks the app while the extension sits waiting,
/// and autofill looks broken rather than merely slow. Doing it at launch puts
/// the prompt in front of someone who is already looking at the app.
pub fn warm() {
    let _ = load();
}

/// Every paired browser.
pub fn list() -> Vec<Association> {
    load().into_values().collect()
}

/// Pair a new browser and persist it.
pub fn create(name: &str) -> Result<Association, KeychainError> {
    let id = hex(&truepass_crypto::rand::bytes::<16>().unwrap_or([0; 16]));
    let key = hex(&truepass_crypto::rand::bytes::<32>().unwrap_or([0; 32]));

    let association = Association {
        id: id.clone(),
        name: name.to_string(),
        key,
    };

    let mut store = load();
    store.insert(id, association.clone());
    save(&store)?;
    Ok(association)
}

/// Unpair one browser.
pub fn remove(id: &str) -> Result<(), KeychainError> {
    let mut store = load();
    store.remove(id);
    save(&store)
}

/// Unpair everything. Called on sign-out.
pub fn clear() {
    let _ = truepass_macos::delete(SERVICE, ACCOUNT);
    invalidate();
}

/// Whether a request carries a valid proof from a paired browser.
///
/// Returns the association on success so the caller can say which browser
/// asked.
pub fn verify(request: &Request) -> Option<Association> {
    let (id, proof) = match request {
        Request::Logins { id, proof, .. } => (id, proof),
        Request::Credential { id, proof, .. } => (id, proof),
        Request::Capture { id, proof, .. } => (id, proof),
        Request::Status | Request::Associate { .. } => return None,
    };

    let association = load().get(id)?.clone();
    if verify_proof(&association.key, request, proof) {
        Some(association)
    } else {
        None
    }
}

/// Check a proof against a key, without touching the keychain.
///
/// Split out from [`verify`] so the cryptographic half can be tested directly
/// rather than through keychain state.
///
/// Comparison is constant-time. A proof check that leaks timing is one an
/// attacker can grind down a byte at a time, and this one sits in front of
/// every stored password.
pub fn verify_proof(key_hex: &str, request: &Request, proof_hex: &str) -> bool {
    let Some(key) = unhex(key_hex) else {
        return false;
    };
    let Some(payload) = proof_payload(request) else {
        return false;
    };
    let Some(presented) = unhex(proof_hex) else {
        return false;
    };

    let expected = compute_proof_raw(&key, &payload);
    presented.len() == expected.len() && bool::from(presented.ct_eq(&expected[..]))
}

/// The proof a client should send for `request`, given its key.
///
/// Public so the extension's behaviour can be reproduced exactly in tests.
pub fn compute_proof(key_hex: &str, request: &Request) -> Option<String> {
    let key = unhex(key_hex)?;
    let payload = proof_payload(request)?;
    Some(hex(&compute_proof_raw(&key, &payload)))
}

fn compute_proof_raw(key: &[u8], payload: &[u8]) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(payload);
    mac.finalize().into_bytes().into()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(core::str::from_utf8(c).ok()?, 16).ok())
        .collect()
}
