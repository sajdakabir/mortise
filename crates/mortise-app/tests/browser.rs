//! Browser protocol tests.
//!
//! The proof is what stands between a rogue local process and every stored
//! password, so most of these are about what it must *refuse*.

use mortise_app_lib::browser::associations::{compute_proof, verify_proof};
use mortise_app_lib::browser::protocol::{Request, Response, proof_payload};
use mortise_app_lib::browser::server::sanitize_client_name;

const KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
const OTHER_KEY: &str = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";
const ID: &str = "abcdef0123456789";

fn logins(origin: &str) -> Request {
    Request::Logins {
        origin: origin.into(),
        id: ID.into(),
        proof: String::new(),
    }
}

fn credential(item: &str, origin: &str) -> Request {
    Request::Credential {
        item_id: item.into(),
        origin: origin.into(),
        id: ID.into(),
        proof: String::new(),
    }
}

#[test]
fn a_correct_proof_verifies() {
    let request = logins("https://github.com");
    let proof = compute_proof(KEY, &request).unwrap();
    assert!(verify_proof(KEY, &request, &proof));
}

#[test]
fn a_proof_from_a_different_key_is_refused() {
    let request = logins("https://github.com");
    let proof = compute_proof(OTHER_KEY, &request).unwrap();
    assert!(!verify_proof(KEY, &request, &proof));
}

/// The attack this exists to stop: capture a proof for one site, replay it to
/// pull a credential for another. The origin is inside the signed payload, so
/// the proof does not transfer.
#[test]
fn a_proof_does_not_transfer_between_origins() {
    let honest = logins("https://github.com");
    let proof = compute_proof(KEY, &honest).unwrap();

    for other in [
        "https://evil.example",
        "http://github.com",
        "https://github.com.evil.example",
        "https://gist.github.com",
    ] {
        assert!(
            !verify_proof(KEY, &logins(other), &proof),
            "a proof for github.com was accepted for {other}"
        );
    }
}

/// Same idea one level down: a proof for one item must not fetch another.
#[test]
fn a_proof_does_not_transfer_between_items() {
    let request = credential("aaaa", "https://github.com");
    let proof = compute_proof(KEY, &request).unwrap();

    assert!(verify_proof(KEY, &request, &proof));
    assert!(!verify_proof(
        KEY,
        &credential("bbbb", "https://github.com"),
        &proof
    ));
}

/// A `logins` proof must not be reusable as a `credential` proof — the first
/// returns metadata, the second returns a password.
#[test]
fn a_proof_does_not_transfer_between_request_types() {
    let listing = logins("https://github.com");
    let proof = compute_proof(KEY, &listing).unwrap();

    assert!(!verify_proof(
        KEY,
        &credential("aaaa", "https://github.com"),
        &proof
    ));
}

/// Length prefixes stop two different field splits from producing the same
/// signed bytes. Without them, origin "ab" + item "c" and origin "a" + item
/// "bc" would be indistinguishable.
#[test]
fn field_boundaries_are_unambiguous() {
    let a = proof_payload(&credential("c", "https://ab")).unwrap();
    let b = proof_payload(&credential("bc", "https://a")).unwrap();
    assert_ne!(a, b);
}

#[test]
fn malformed_proofs_are_refused_without_panicking() {
    let request = logins("https://github.com");

    for bad in [
        "",
        "zz",
        "abc",
        &"f".repeat(63),
        &"f".repeat(66),
        "not hex at all!!",
    ] {
        assert!(!verify_proof(KEY, &request, bad), "accepted proof {bad:?}");
    }
}

#[test]
fn a_malformed_key_refuses_rather_than_panicking() {
    let request = logins("https://github.com");
    let proof = compute_proof(KEY, &request).unwrap();

    for bad_key in ["", "zz", "abc"] {
        assert!(!verify_proof(bad_key, &request, &proof));
    }
}

/// Status and Associate carry no proof: the first needs none, the second is
/// what establishes the key. Neither must accidentally verify.
#[test]
fn unprovable_requests_have_no_payload() {
    assert!(proof_payload(&Request::Status).is_none());
    assert!(
        proof_payload(&Request::Associate {
            request_token: None,
            client_name: "Chrome".into()
        })
        .is_none()
    );
    assert!(!verify_proof(KEY, &Request::Status, "00"));
}

// --- client names ---

/// The name comes from the extension and ends up in an approval prompt, so a
/// hostile value must not be able to spoof the surrounding interface text.
#[test]
fn client_names_are_sanitized_before_being_shown() {
    assert_eq!(sanitize_client_name("Chrome"), "Chrome");
    assert_eq!(sanitize_client_name("  Firefox  "), "Firefox");

    assert!(!sanitize_client_name("Chrome\n\nApproved by Apple").contains('\n'));
    assert!(!sanitize_client_name("A\u{0}B").contains('\u{0}'));
    assert!(!sanitize_client_name("A\rB").contains('\r'));

    assert_eq!(sanitize_client_name(""), "A browser");
    assert_eq!(sanitize_client_name("   "), "A browser");
    assert_eq!(sanitize_client_name("\n\t"), "A browser");

    assert!(sanitize_client_name(&"x".repeat(500)).chars().count() <= 40);
}

// --- wire format ---

#[test]
fn requests_round_trip_through_json() {
    let request = credential("abcd", "https://github.com");
    let encoded = serde_json::to_vec(&request).unwrap();
    let decoded: Request = serde_json::from_slice(&encoded).unwrap();

    assert_eq!(proof_payload(&request), proof_payload(&decoded));
}

#[test]
fn unknown_message_types_are_rejected() {
    for bad in [
        br#"{"type":"nonsense"}"#.as_slice(),
        br#"{}"#,
        br#"{"type":"credential"}"#,
        b"not json",
    ] {
        assert!(serde_json::from_slice::<Request>(bad).is_err());
    }
}

#[test]
fn responses_serialize_with_a_type_tag() {
    let encoded = serde_json::to_string(&Response::error("locked", "Unlock first.")).unwrap();
    assert!(encoded.contains(r#""type":"error""#));
    assert!(encoded.contains(r#""code":"locked""#));

    let listing = serde_json::to_string(&Response::Logins { items: Vec::new() }).unwrap();
    assert!(listing.contains(r#""type":"logins""#));
}

// --- capture ---

fn capture(origin: &str, username: Option<&str>, password: &str) -> Request {
    Request::Capture {
        id: "abcdef0123456789".into(),
        origin: origin.into(),
        username: username.map(str::to_string),
        password: password.into(),
        proof: String::new(),
    }
}

/// Capture carries a secret *into* the vault, so an unproved one would let any
/// local process plant an item the user would later trust and use.
#[test]
fn a_capture_needs_a_valid_proof() {
    let request = capture("https://github.com", Some("octocat"), "hunter2");
    let proof = compute_proof(KEY, &request).unwrap();

    assert!(verify_proof(KEY, &request, &proof));
    assert!(!verify_proof(OTHER_KEY, &request, &proof));
}

/// The password is inside the signed payload, so a captured proof cannot be
/// reused to plant a different password for the same site.
#[test]
fn a_capture_proof_does_not_transfer_between_passwords() {
    let request = capture("https://github.com", Some("octocat"), "hunter2");
    let proof = compute_proof(KEY, &request).unwrap();

    assert!(!verify_proof(
        KEY,
        &capture("https://github.com", Some("octocat"), "something-else"),
        &proof
    ));
}

#[test]
fn a_capture_proof_does_not_transfer_between_origins() {
    let request = capture("https://github.com", Some("octocat"), "hunter2");
    let proof = compute_proof(KEY, &request).unwrap();

    assert!(!verify_proof(
        KEY,
        &capture("https://github.evil.example", Some("octocat"), "hunter2"),
        &proof
    ));
}

#[test]
fn a_capture_proof_does_not_transfer_between_usernames() {
    let request = capture("https://github.com", Some("octocat"), "hunter2");
    let proof = compute_proof(KEY, &request).unwrap();

    assert!(!verify_proof(
        KEY,
        &capture("https://github.com", Some("someone-else"), "hunter2"),
        &proof
    ));
}

/// Length prefixes are what make this hold: without them, username "ab" with
/// password "c" and username "a" with password "bc" would sign identically.
#[test]
fn a_capture_proof_respects_field_boundaries() {
    let a = capture("https://x.example", Some("ab"), "c");
    let b = capture("https://x.example", Some("a"), "bc");

    assert_ne!(
        compute_proof(KEY, &a),
        compute_proof(KEY, &b),
        "field boundaries are not covered by the proof"
    );
}

// --- cross-implementation vectors ---

/// Proofs computed by the extension's `proof.js`, pinned here.
///
/// The JS and Rust sides each build the signed payload independently. If they
/// ever drift — a reordered field, a changed length-prefix width, big-endian
/// becoming native-endian — every request fails closed. Annoying, but silent
/// until someone tries to use the extension, which is why these are checked in
/// CI instead.
///
/// Regenerate with `node extension/tools/gen-proof-vectors.mjs` and only update
/// them when the protocol genuinely changes.
#[test]
fn rust_and_javascript_agree_on_proofs() {
    const KEY: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    let cases: [(Request, &str); 5] = [
        (
            Request::Logins {
                id: "abcdef0123456789".into(),
                origin: "https://github.com".into(),
                proof: String::new(),
            },
            "2b4ab681f56b3eadd202f96907a59f7c7c7871d99407a7feee865cd2bccd647e",
        ),
        (
            Request::Credential {
                id: "abcdef0123456789".into(),
                origin: "https://github.com".into(),
                item_id: "0102030405060708090a0b0c0d0e0f10".into(),
                proof: String::new(),
            },
            "b44305cfe57e86381902a2527b2efe9bbba46a1a427933409b6ea910369aff56",
        ),
        (
            Request::Logins {
                id: "ff".into(),
                origin: "http://localhost:3000".into(),
                proof: String::new(),
            },
            "a2a5541a4e548f756d30185f873238d0b43728b08e75e2e655e43eb59eea5960",
        ),
        (
            Request::Capture {
                id: "abcdef0123456789".into(),
                origin: "https://github.com".into(),
                username: Some("octocat".into()),
                password: "hunter2".into(),
                proof: String::new(),
            },
            "8ab474a7f01b67d1ca65415bbd328c1be3577a382a1d6fe49d226a2ec7e075ae",
        ),
        // Pins that a missing username encodes as an empty field rather than
        // being skipped, which would shift every later field.
        (
            Request::Capture {
                id: "abcdef0123456789".into(),
                origin: "https://github.com".into(),
                username: None,
                password: "hunter2".into(),
                proof: String::new(),
            },
            "0018a9a9de27cdea51f0a2b01d5218d86d95861d5fc95e826e743a8997144365",
        ),
    ];

    for (request, from_javascript) in cases {
        assert_eq!(
            compute_proof(KEY, &request).as_deref(),
            Some(from_javascript),
            "Rust and the extension disagree about this request's proof"
        );
        assert!(verify_proof(KEY, &request, from_javascript));
    }
}

/// The payload layout itself, so a failure says *what* diverged rather than
/// just that two hashes differ.
#[test]
fn the_signed_payload_layout_matches_javascript() {
    let payload = proof_payload(&Request::Logins {
        id: "abcdef0123456789".into(),
        origin: "https://github.com".into(),
        proof: String::new(),
    })
    .unwrap();

    let hex: String = payload.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        hex,
        "000000066c6f67696e7300000010616263646566303132333435363738390000001268747470733a\
         2f2f6769746875622e636f6d"
    );
}
