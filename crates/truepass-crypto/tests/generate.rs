//! Password generator tests.

use std::collections::HashMap;

use truepass_crypto::generate::{
    self, DIGITS, EXCLUDED_AMBIGUOUS, LOWER, PasswordSpec, SYMBOLS, UPPER,
};

#[test]
fn length_is_respected() {
    for length in [8usize, 16, 20, 64, 128] {
        let spec = PasswordSpec {
            length,
            ..Default::default()
        };
        assert_eq!(generate::password(spec).unwrap().chars().count(), length);
    }
}

#[test]
fn only_selected_character_classes_appear() {
    let cases = [
        (
            PasswordSpec {
                length: 200,
                lower: true,
                upper: false,
                digits: false,
                symbols: false,
            },
            LOWER,
        ),
        (
            PasswordSpec {
                length: 200,
                lower: false,
                upper: true,
                digits: false,
                symbols: false,
            },
            UPPER,
        ),
        (
            PasswordSpec {
                length: 200,
                lower: false,
                upper: false,
                digits: true,
                symbols: false,
            },
            DIGITS,
        ),
        (
            PasswordSpec {
                length: 200,
                lower: false,
                upper: false,
                digits: false,
                symbols: true,
            },
            SYMBOLS,
        ),
    ];

    for (spec, allowed) in cases {
        let pw = generate::password(spec).unwrap();
        for ch in pw.chars() {
            assert!(allowed.contains(ch), "{ch:?} is outside the selected class");
        }
    }
}

/// Characters that are hard to tell apart when read off a screen or dictated
/// are excluded from every class.
#[test]
fn ambiguous_characters_never_appear() {
    let spec = PasswordSpec {
        length: 128,
        ..Default::default()
    };
    for _ in 0..40 {
        let pw = generate::password(spec).unwrap();
        for ch in pw.chars() {
            assert!(
                !EXCLUDED_AMBIGUOUS.contains(ch),
                "ambiguous character {ch:?} was generated"
            );
        }
    }
}

#[test]
fn a_spec_with_nothing_selected_is_rejected() {
    let empty = PasswordSpec {
        length: 20,
        lower: false,
        upper: false,
        digits: false,
        symbols: false,
    };
    assert!(generate::password(empty).is_err());

    let zero_length = PasswordSpec {
        length: 0,
        ..Default::default()
    };
    assert!(generate::password(zero_length).is_err());
}

#[test]
fn generated_passwords_differ() {
    let spec = PasswordSpec::default();
    let a = generate::password(spec).unwrap();
    let b = generate::password(spec).unwrap();
    assert_ne!(*a, *b);
}

/// The reason `uniform_below` uses rejection sampling rather than a modulo.
///
/// With a bare `byte % 64` over a 64-character set there would be no bias at
/// all (64 divides 256), which is exactly why this uses the *default* 70-ish
/// character set, where it does not divide evenly. Under modulo bias the first
/// `256 % n` characters come up measurably more often.
///
/// This is statistical, so the bound is loose enough not to flake: with ~100k
/// samples over ~70 buckets, a correct generator stays far inside ±25% of the
/// expected count, while a modulo-biased one skews by a consistent, detectable
/// amount across a whole contiguous block of the charset.
#[test]
fn character_selection_is_uniform() {
    let spec = PasswordSpec {
        length: 100_000,
        ..Default::default()
    };
    let pw = generate::password(spec).unwrap();

    let mut counts: HashMap<char, usize> = HashMap::new();
    for ch in pw.chars() {
        *counts.entry(ch).or_default() += 1;
    }

    let distinct = counts.len();
    assert!(
        distinct > 60,
        "only {distinct} distinct characters appeared; charset is not being covered"
    );

    let expected = spec.length as f64 / distinct as f64;
    for (ch, count) in &counts {
        let deviation = (*count as f64 - expected).abs() / expected;
        assert!(
            deviation < 0.25,
            "{ch:?} appeared {count} times against an expected {expected:.0} \
             ({:.1}% off) — selection looks biased",
            deviation * 100.0
        );
    }
}

#[test]
fn entropy_matches_the_charset_size() {
    let spec = PasswordSpec {
        length: 20,
        lower: true,
        upper: false,
        digits: false,
        symbols: false,
    };
    // 25 lowercase letters after the ambiguous ones are removed.
    let expected = (LOWER.chars().count() as f64).log2() * 20.0;
    assert!((spec.entropy_bits() - expected).abs() < 1e-9);

    // More classes must mean more entropy at the same length.
    let wider = PasswordSpec {
        upper: true,
        digits: true,
        symbols: true,
        ..spec
    };
    assert!(wider.entropy_bits() > spec.entropy_bits());

    // And a longer password must beat a shorter one of the same alphabet.
    let longer = PasswordSpec { length: 40, ..spec };
    assert!(longer.entropy_bits() > spec.entropy_bits());
}

#[test]
fn degenerate_specs_report_zero_entropy() {
    let nothing = PasswordSpec {
        length: 20,
        lower: false,
        upper: false,
        digits: false,
        symbols: false,
    };
    assert_eq!(nothing.entropy_bits(), 0.0);

    let zero = PasswordSpec {
        length: 0,
        ..Default::default()
    };
    assert_eq!(zero.entropy_bits(), 0.0);
}

#[test]
fn passphrases_use_the_supplied_words() {
    let words = ["correct", "horse", "battery", "staple", "anvil", "zebra"];
    let phrase = generate::passphrase(&words, 4, '-').unwrap();

    let parts: Vec<&str> = phrase.split('-').collect();
    assert_eq!(parts.len(), 4);
    for part in parts {
        assert!(words.contains(&part), "{part:?} is not from the word list");
    }
}

#[test]
fn degenerate_passphrase_requests_are_rejected() {
    assert!(generate::passphrase(&["only"], 4, '-').is_err());
    assert!(generate::passphrase(&["a", "b"], 0, '-').is_err());
}
