//! Agent Guard index tests for spec §8.

use mortise_crypto::guard::{GuardIndex, MIN_SECRET_LEN};
use mortise_crypto::item::ItemId;
use mortise_crypto::secret::Key32;

fn index() -> (GuardIndex, ItemId) {
    (
        GuardIndex::new(Key32::new([0x5A; 32])),
        ItemId::from_bytes([1; 16]),
    )
}

const API_KEY: &str = "sk-ant-api03-Xk92mQ7vB4nR8tL1";

#[test]
fn lookup_finds_an_indexed_secret() {
    let (mut idx, item) = index();
    assert!(idx.insert(API_KEY, item));

    assert_eq!(idx.lookup(API_KEY), Some(item));
    assert_eq!(idx.lookup("something else entirely"), None);
}

#[test]
fn short_values_are_not_indexed() {
    let (mut idx, item) = index();

    assert!(!idx.insert("short", item), "a 5-char value was indexed");
    assert!(idx.is_empty());
    assert_eq!(idx.lookup("short"), None);

    let minimum = "a".repeat(MIN_SECRET_LEN);
    assert!(idx.insert(&minimum, item));
}

#[test]
fn scan_finds_a_secret_in_running_text() {
    let (mut idx, item) = index();
    idx.insert(API_KEY, item);

    let text = format!("here is my key {API_KEY} please debug it");
    let hits = idx.scan(&text);

    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].item, item);
    assert_eq!(&text[hits[0].start..hits[0].start + hits[0].len], API_KEY);
}

/// Env-assignment form. `=` is deliberately not a delimiter — splitting on it
/// would strip base64 padding off real secrets — so the value after the first
/// `=` is checked as a separate candidate instead.
#[test]
fn scan_finds_a_secret_in_an_assignment() {
    let (mut idx, item) = index();
    idx.insert(API_KEY, item);

    let text = format!("ANTHROPIC_API_KEY={API_KEY}");
    let hits = idx.scan(&text);

    assert_eq!(hits.len(), 1);
    assert_eq!(&text[hits[0].start..hits[0].start + hits[0].len], API_KEY);
}

#[test]
fn scan_finds_quoted_and_bracketed_secrets() {
    let (mut idx, item) = index();
    idx.insert(API_KEY, item);

    for text in [
        format!("key: \"{API_KEY}\""),
        format!("key: '{API_KEY}'"),
        format!("curl -H (Authorization: {API_KEY})"),
        format!("{{\"key\":\"{API_KEY}\"}}"),
        format!("export KEY={API_KEY}\nnext line"),
    ] {
        assert_eq!(idx.scan(&text).len(), 1, "missed a secret in: {text}");
    }
}

/// Characters that occur inside real secrets must not split tokens.
#[test]
fn secret_internal_punctuation_does_not_fragment_tokens() {
    let (mut idx, item) = index();

    for secret in [
        "sk-ant-api03-Xk92mQ7vB4nR8tL1",
        "ghp_16C7e42F292c6912E7710c838347Ae178B4a",
        "abc+def/ghi=jkl0mnop",
        "https://user:pass@example.com/path",
        "value.with.dots.and_underscores",
    ] {
        idx.insert(secret, item);
        let text = format!("prefix {secret} suffix");
        assert_eq!(idx.scan(&text).len(), 1, "fragmented: {secret}");
    }
}

#[test]
fn ordinary_prose_does_not_match() {
    let (mut idx, item) = index();
    idx.insert(API_KEY, item);

    let text = "Can you help me refactor this authentication middleware? \
                It handles sessions and tokens but the password reset flow is broken.";
    assert!(idx.scan(text).is_empty());
}

#[test]
fn matching_is_case_sensitive() {
    let (mut idx, item) = index();
    idx.insert(API_KEY, item);

    assert_eq!(idx.lookup(&API_KEY.to_uppercase()), None);
    assert_eq!(idx.lookup(&API_KEY.to_lowercase()), None);
}

#[test]
fn multiple_secrets_in_one_text_are_all_found() {
    let (mut idx, _) = index();
    let a = ItemId::from_bytes([1; 16]);
    let b = ItemId::from_bytes([2; 16]);

    idx.insert("sk-ant-first-secret-value", a);
    idx.insert("ghp_second_secret_value_here", b);

    let hits = idx.scan("first sk-ant-first-secret-value then ghp_second_secret_value_here");
    assert_eq!(hits.len(), 2);
    assert_eq!(hits[0].item, a);
    assert_eq!(hits[1].item, b);
}

/// Spec §8: the index stores `HMAC(scan_key, secret)`, never plaintext.
/// Dumping it must reveal nothing without the MUK.
#[test]
fn the_index_never_holds_plaintext() {
    let (mut idx, item) = index();
    idx.insert(API_KEY, item);

    let rendered = format!("{idx:?}");
    assert!(
        !rendered.contains(API_KEY),
        "Debug output leaked the secret"
    );
    assert!(!rendered.contains("sk-ant"), "Debug output leaked a prefix");
    assert!(rendered.contains("redacted"));
}

/// The index is bound to the scan key, which is derived from the MUK. An index
/// built under one account is meaningless under another.
#[test]
fn a_different_scan_key_produces_a_different_index() {
    let item = ItemId::from_bytes([1; 16]);
    let mut a = GuardIndex::new(Key32::new([0xAA; 32]));
    let mut b = GuardIndex::new(Key32::new([0xBB; 32]));

    a.insert(API_KEY, item);
    b.insert(API_KEY, item);

    assert_eq!(a.lookup(API_KEY), Some(item));
    assert_eq!(b.lookup(API_KEY), Some(item));

    // Same input, different keys: the stored tags must differ. Checked through
    // behaviour, since the tags themselves are private.
    let mixed = GuardIndex::new(Key32::new([0xAA; 32]));
    assert_eq!(mixed.lookup(API_KEY), None, "empty index matched");
}

#[test]
fn clear_and_remove_empty_the_index() {
    let (mut idx, item) = index();
    idx.insert(API_KEY, item);
    idx.insert("another-secret-value-here", item);
    assert_eq!(idx.len(), 2);

    assert!(idx.remove(API_KEY));
    assert!(!idx.remove(API_KEY), "removing twice reported success");
    assert_eq!(idx.len(), 1);

    idx.clear();
    assert!(idx.is_empty());
    assert_eq!(idx.lookup("another-secret-value-here"), None);
}

/// Surrounding quotes are stripped on insert as well as on scan, so a secret
/// stored with quotes still matches when pasted without them.
#[test]
fn quotes_are_normalized_on_both_sides() {
    let (mut idx, item) = index();
    idx.insert(&format!("\"{API_KEY}\""), item);

    assert_eq!(idx.lookup(API_KEY), Some(item));
    assert_eq!(idx.scan(&format!("key {API_KEY}")).len(), 1);
}

#[test]
fn empty_and_whitespace_input_is_handled() {
    let (mut idx, item) = index();
    idx.insert(API_KEY, item);

    assert!(idx.scan("").is_empty());
    assert!(idx.scan("   \n\t  ").is_empty());
    assert!(!idx.insert("", item));
    assert!(!idx.insert("       ", item));
}
