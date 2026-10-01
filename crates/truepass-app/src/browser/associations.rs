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

fn load() -> Store {
    match truepass_macos::load(SERVICE, ACCOUNT, "") {
        Ok(Some(bytes)) => serde_json::from_slice(&bytes).unwrap_or_default(),
        _ => Store::new(),
    }
}

fn save(store: &Store) -> Result<(), KeychainError> {
    let json = serde_json::to_vec(store).unwrap_or_else(|_| b"{}".to_vec());
    truepass_macos::store(SERVICE, ACCOUNT, &json, Protection::DeviceUnlocked)
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
}

/// Whether a request carries a valid proof from a paired browser.
///
/// Returns the association on success so the caller can say which browser
/// asked.
pub fn verify(request: &Request) -> Option<Association> {
    let (id, proof) = match request {
        Request::Logins { id, proof, .. } => (id, proof),
        Request::Credential { id, proof, .. } => (id, proof),
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
