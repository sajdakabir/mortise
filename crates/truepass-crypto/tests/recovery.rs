//! Recovery kit tests for spec §7.

use truepass_crypto::error::Error;
use truepass_crypto::recovery::{self, PREFIX};
use truepass_crypto::secret::Key32;

fn key() -> Key32 {
    Key32::new([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54,
        0x32, 0x10,
    ])
}

#[test]
fn round_trips() {
    let k = key();
    assert_eq!(recovery::decode(&recovery::encode(&k)).unwrap(), k);
}

#[test]
fn round_trips_for_random_keys() {
    for _ in 0..50 {
        let k = Key32::random().unwrap();
        assert_eq!(recovery::decode(&recovery::encode(&k)).unwrap(), k);
    }
}

#[test]
fn encoding_is_stable() {
    // Pins the format. Changing it strands every kit already printed.
    assert_eq!(
        recovery::encode(&key()),
        "TP1-AAISE-M2EKV-THPCE-ZVK54-ZXPO7-4ASGR-LHRGV-43376-3S5JQ-5SUGI-IIJCY"
    );
}

#[test]
fn format_is_prefixed_and_grouped() {
    let kit = recovery::encode(&key());

    assert!(kit.starts_with(PREFIX));
    for group in kit.strip_prefix(PREFIX).unwrap().split('-').skip(1) {
        assert!(group.len() <= 5, "group too long: {group}");
        assert!(!group.is_empty());
    }
}

/// Base32 (RFC 4648) has no `0`, `1` or `8`, so the usual `0`/`O` and `1`/`I`
/// transcription confusions cannot arise in the body.
#[test]
fn the_alphabet_avoids_confusable_digits() {
    for _ in 0..20 {
        let kit = recovery::encode(&Key32::random().unwrap());
        let body = kit.strip_prefix(PREFIX).unwrap();
        for ch in body.chars().filter(|c| *c != '-') {
            assert!(
                !"018".contains(ch),
                "confusable character {ch} in the kit body"
            );
        }
    }
}

/// People retype these off paper. Be generous about everything except the
/// checksum.
#[test]
fn decoding_tolerates_how_people_actually_type() {
    let k = key();
    let kit = recovery::encode(&k);
    let body = kit.strip_prefix(PREFIX).unwrap();

    let variants = [
        kit.to_lowercase(),
        kit.replace('-', ""),
        kit.replace('-', " "),
        format!("  {kit}  "),
        format!("{kit}\n"),
        body.to_string(),
        body.replace('-', ""),
        kit.replace('-', "--"),
    ];

    for v in variants {
        assert_eq!(
            recovery::decode(&v).unwrap(),
            k,
            "failed to decode variant: {v:?}"
        );
    }
}

/// The checksum exists so a mistyped kit fails immediately, rather than after
/// the user sits through a 64 MiB Argon2 run that was never going to work.
///
/// It is 2 bytes, so roughly 1 in 65536 single-character typos slips through
/// and yields a *different* key. What must never happen is a corrupted kit
/// decoding back to the original key.
#[test]
fn single_character_typos_are_caught() {
    let k = key();
    let kit = recovery::encode(&k);
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    let mut checked = 0usize;
    let mut caught = 0usize;

    let chars: Vec<char> = kit.chars().collect();
    for (i, original) in chars.iter().enumerate() {
        if *original == '-' || i < PREFIX.len() {
            continue;
        }
        for replacement in alphabet.chars() {
            if replacement == *original {
                continue;
            }
            let mut typo: Vec<char> = chars.clone();
            typo[i] = replacement;
            let typo: String = typo.into_iter().collect();

            checked += 1;
            match recovery::decode(&typo) {
                Err(_) => caught += 1,
                Ok(other) => {
                    assert_ne!(other, k, "a corrupted kit decoded back to the original key")
                }
            }
        }
    }

    assert!(checked > 1000, "test did not exercise enough typos");
    let rate = caught as f64 / checked as f64;
    assert!(
        rate > 0.99,
        "checksum caught only {:.2}% of single-character typos",
        rate * 100.0
    );
}

#[test]
fn malformed_input_is_rejected() {
    for bad in [
        "",
        "TP1",
        "TP1-",
        "not a recovery kit at all",
        "TP1-!!!!!-!!!!!",
        "TP1-AAISE",                   // far too short
        "TP1-AAISE-M2EKV-THPCE-ZVK54", // truncated
    ] {
        assert_eq!(
            recovery::decode(bad).unwrap_err(),
            Error::RecoveryKit,
            "accepted malformed kit: {bad:?}"
        );
    }
}

#[test]
fn truncation_at_every_length_is_rejected() {
    let kit = recovery::encode(&key());
    for len in 0..kit.len() {
        let truncated = &kit[..len];
        if let Ok(decoded) = recovery::decode(truncated) {
            assert_ne!(decoded, key(), "truncated kit decoded to the real key");
        }
    }
}

#[test]
fn distinct_keys_give_distinct_kits() {
    let a = recovery::encode(&Key32::new([1; 32]));
    let b = recovery::encode(&Key32::new([2; 32]));
    assert_ne!(a, b);
}
