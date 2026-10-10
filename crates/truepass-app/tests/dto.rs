//! Tests for the webview boundary conversions.
//!
//! These are small pure functions, but they sit on the path every item id takes
//! in and out of the UI. A parsing bug here would surface as items silently not
//! found, which is a miserable thing to debug.

use truepass_app_lib::dto::{MetaInput, id_from_hex, id_to_hex};
use truepass_crypto::item::ItemId;
use truepass_vault::ItemMeta;

#[test]
fn item_ids_round_trip_through_hex() {
    for _ in 0..100 {
        let id = ItemId::generate().unwrap();
        let hex = id_to_hex(id);
        assert_eq!(hex.len(), 32);
        assert_eq!(id_from_hex(&hex), Some(id));
    }
}

#[test]
fn hex_encoding_is_lowercase_and_padded() {
    let id = ItemId::from_bytes([
        0x00, 0x0f, 0xa0, 0xff, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
    ]);
    assert_eq!(id_to_hex(id), "000fa0ff0102030405060708090a0b0c");
}

/// Anything the webview sends is untrusted. Malformed ids must come back as
/// `None` rather than panicking or, worse, decoding to some other item.
#[test]
fn malformed_ids_are_rejected() {
    for bad in [
        "",
        "abc",
        &"a".repeat(31),
        &"a".repeat(33),
        &"g".repeat(32), // not hex
        "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        "0102030405060708090a0b0c0d0e0f1 ", // trailing space
        "../../../etc/passwd",
    ] {
        assert_eq!(id_from_hex(bad), None, "accepted malformed id {bad:?}");
    }
}

/// Non-ASCII input must not panic the hex parser via byte-boundary slicing.
#[test]
fn non_ascii_ids_do_not_panic() {
    for bad in [
        "é".repeat(16).as_str(),
        "🔑🔑🔑🔑🔑🔑🔑🔑",
        "\u{0}".repeat(32).as_str(),
    ] {
        assert_eq!(id_from_hex(bad), None);
    }
}

/// Blank fields arrive as empty strings from HTML inputs. Storing them would
/// litter the vault with empty URLs and tags that then show up in search.
#[test]
fn blank_metadata_fields_are_dropped() {
    let meta: ItemMeta = MetaInput {
        title: "GitHub".into(),
        urls: vec!["https://github.com".into(), "  ".into(), "".into()],
        username: Some("   ".into()),
        folder: Some("".into()),
        tags: vec!["dev".into(), " ".into()],
    }
    .into();

    assert_eq!(meta.title, "GitHub");
    assert_eq!(meta.urls, vec!["https://github.com".to_string()]);
    assert_eq!(meta.username, None);
    assert_eq!(meta.folder, None);
    assert_eq!(meta.tags, vec!["dev".to_string()]);
}

#[test]
fn populated_metadata_is_preserved() {
    let meta: ItemMeta = MetaInput {
        title: "GitHub".into(),
        urls: vec!["https://github.com".into()],
        username: Some("octocat".into()),
        folder: Some("Work".into()),
        tags: vec!["dev".into(), "ci".into()],
    }
    .into();

    assert_eq!(meta.username.as_deref(), Some("octocat"));
    assert_eq!(meta.folder.as_deref(), Some("Work"));
    assert_eq!(meta.tags.len(), 2);
}
