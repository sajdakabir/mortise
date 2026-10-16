//! Origin matching tests.
//!
//! This is the autofill security boundary (threat model A5), so the negative
//! cases matter more than the positive ones. Each one below is a real technique
//! for making a hostile host look like a trusted one.

use mortise_vault::Origin;

fn o(s: &str) -> Origin {
    Origin::parse(s).unwrap_or_else(|| panic!("failed to parse {s:?}"))
}

// --- parsing ---

#[test]
fn urls_reduce_to_their_origin() {
    for (input, expected) in [
        ("https://github.com", "https://github.com"),
        ("https://github.com/", "https://github.com"),
        ("https://github.com/login", "https://github.com"),
        (
            "https://github.com/login?next=/x#frag",
            "https://github.com",
        ),
        ("https://github.com:443/login", "https://github.com"),
        ("http://localhost:3000/app", "http://localhost:3000"),
        ("https://example.com:8443", "https://example.com:8443"),
        ("  https://github.com  ", "https://github.com"),
    ] {
        assert_eq!(o(input).to_canonical_string(), expected, "input {input:?}");
    }
}

/// A bare host is assumed https. Defaulting to http would mean a user typing
/// `github.com` silently permits filling on an unencrypted page.
#[test]
fn a_bare_host_defaults_to_https() {
    let parsed = o("github.com");
    assert_eq!(parsed.scheme(), "https");
    assert_eq!(parsed.port(), 443);
}

#[test]
fn hosts_are_case_insensitive() {
    assert_eq!(o("https://GitHub.COM"), o("https://github.com"));
    assert_eq!(o("HTTPS://github.com"), o("https://github.com"));
}

#[test]
fn default_ports_are_equivalent_to_omitting_them() {
    assert_eq!(o("https://github.com"), o("https://github.com:443"));
    assert_eq!(o("http://example.com"), o("http://example.com:80"));
}

#[test]
fn ipv6_literals_parse() {
    assert_eq!(o("http://[::1]:3000").host(), "::1");
    assert_eq!(o("http://[::1]:3000").port(), 3000);
    assert_eq!(o("https://[2001:db8::1]").port(), 443);
}

#[test]
fn malformed_input_is_rejected() {
    for bad in [
        "",
        "   ",
        "ftp://github.com",
        "javascript:alert(1)",
        "file:///etc/passwd",
        "data:text/html,hi",
        "https://",
        "https:///path",
        "https://.github.com",
        "https://github.com.",
        "https://git..hub.com",
        "https://git hub.com",
        "https://github.com:notaport",
        "https://github.com:99999",
    ] {
        assert!(Origin::parse(bad).is_none(), "accepted malformed {bad:?}");
    }
}

/// Userinfo is not part of an origin, and embedding it is a classic way to
/// make a hostile host read as a trusted one at a glance.
#[test]
fn userinfo_does_not_become_the_host() {
    let parsed = o("https://github.com@evil.example/login");
    assert_eq!(parsed.host(), "evil.example");
    assert!(!parsed.may_fill(&o("https://github.com")));
}

// --- matching ---

#[test]
fn an_exact_origin_matches() {
    assert!(o("https://github.com").may_fill(&o("https://github.com")));
    assert!(o("https://github.com").may_fill(&o("https://github.com/login")));
    assert!(o("github.com").may_fill(&o("https://github.com")));
}

/// The attack this whole module exists to stop. Every one of these is a host
/// that contains or resembles the target and must not match it.
#[test]
fn lookalike_hosts_never_match() {
    let stored = o("https://github.com");

    for hostile in [
        "https://github.com.evil.example", // suffix attack
        "https://evil-github.com",
        "https://githubcom",
        "https://github.co",
        "https://notgithub.com",
        "https://github.com.br",
        "https://wwwgithub.com",
        "https://github.com.attacker.net/login",
        "https://sub.github.com.evil.io",
    ] {
        assert!(
            !stored.may_fill(&o(hostile)),
            "credential for github.com was offered on {hostile}"
        );
    }
}

/// Subdomains are a different origin. See the module docs: matching them
/// safely needs the Public Suffix List, and getting it wrong hands one
/// github.io user another's credentials.
#[test]
fn subdomains_are_a_different_origin() {
    let stored = o("https://github.com");
    assert!(!stored.may_fill(&o("https://gist.github.com")));
    assert!(!stored.may_fill(&o("https://www.github.com")));

    // And the reverse: an item stored for a subdomain does not cover the apex.
    assert!(!o("https://gist.github.com").may_fill(&o("https://github.com")));

    // The case that makes a naive rule dangerous.
    assert!(!o("https://alice.github.io").may_fill(&o("https://mallory.github.io")));
}

/// Filling an https credential into an http page is a downgrade: the password
/// would go out in the clear, and an active network attacker could have forced
/// the downgrade precisely to collect it.
#[test]
fn scheme_must_match_so_https_credentials_never_fill_on_http() {
    assert!(!o("https://github.com").may_fill(&o("http://github.com")));
    assert!(!o("http://github.com").may_fill(&o("https://github.com")));
}

/// A different port is a different service, even on the same host — very much
/// the case on a development machine.
#[test]
fn port_must_match() {
    assert!(!o("http://localhost:3000").may_fill(&o("http://localhost:8080")));
    assert!(!o("https://example.com:8443").may_fill(&o("https://example.com")));
    assert!(o("http://localhost:3000").may_fill(&o("http://localhost:3000/login")));
}

#[test]
fn matching_is_symmetric_and_reflexive() {
    let a = o("https://github.com");
    let b = o("https://github.com/different/path");
    assert!(a.may_fill(&a));
    assert!(a.may_fill(&b) && b.may_fill(&a));
}

/// Unicode hosts are left to the browser, which already shows punycode in the
/// address bar for mixed-script domains. What must not happen is a visually
/// confusable host quietly comparing equal to an ASCII one.
#[test]
fn unicode_lookalike_hosts_do_not_match_ascii_ones() {
    // Cyrillic 'а' (U+0430), not Latin 'a'.
    if let Some(cyrillic) = Origin::parse("https://github.cоm") {
        assert!(!o("https://github.com").may_fill(&cyrillic));
    }
}
