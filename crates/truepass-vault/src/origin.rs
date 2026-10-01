//! Web origin parsing and matching.
//!
//! This is the security boundary for autofill. Adversary A5 in the threat model
//! is a hostile page that controls its own content and may perfectly imitate a
//! site's layout; the only thing it cannot forge is the origin the browser
//! reports. So matching happens here, on origins, and never on page content,
//! window titles, or anything else a page can influence.
//!
//! # Why matching is exact
//!
//! The tempting behaviour is to match `accounts.google.com` against an item
//! stored for `google.com`. Doing that safely needs the Public Suffix List,
//! because without it there is no way to know that `github.io` is a suffix
//! under which `alice.github.io` and `mallory.github.io` are *different
//! parties*. A naive "is a subdomain of" rule hands Mallory Alice's credentials.
//!
//! Shipping a PSL means a few hundred kilobytes and a staleness problem, in a
//! binary whose size is a product goal. So matching is exact, and items can
//! hold several URLs — which the editor already supports. Registrable-domain
//! matching is deferred until there is a reason to pay for it.
//!
//! Note also what is *not* defended against here: a homograph domain in a
//! different script that renders identically. That is the browser's job, and
//! the browser already does it in the address bar.

/// A web origin: scheme, host, and port.
///
/// Compared by all three. Dropping any one of them opens a real attack —
/// ignoring scheme allows an http downgrade, ignoring port allows a different
/// service on the same host.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Origin {
    scheme: String,
    host: String,
    port: u16,
}

impl Origin {
    /// Parse a URL or bare origin.
    ///
    /// Accepts what users actually type into the URL field — `github.com`,
    /// `https://github.com`, `https://github.com/login?x=1` — and reduces it to
    /// an origin. A bare host is assumed `https`: defaulting to `http` would
    /// mean a typo silently permits an unencrypted match.
    pub fn parse(input: &str) -> Option<Self> {
        let input = input.trim();
        if input.is_empty() {
            return None;
        }

        let (scheme, rest) = match input.split_once("://") {
            Some((s, r)) => (s.to_ascii_lowercase(), r),
            None => ("https".to_string(), input),
        };

        if scheme != "http" && scheme != "https" {
            return None;
        }

        // Strip path, query and fragment.
        let authority = rest
            .split(['/', '?', '#'])
            .next()
            .filter(|a| !a.is_empty())?;

        // Credentials in a URL are not part of the origin, and are a classic
        // way to make a hostile host look like a trusted one:
        // https://github.com@evil.example has host evil.example.
        let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);

        let (host, port) = split_host_port(authority)?;
        if host.is_empty() || host.contains(' ') {
            return None;
        }

        let host = host.to_ascii_lowercase();
        // Reject anything that is not plausibly a hostname. Belt and braces:
        // a malformed host that parsed into something surprising is exactly
        // the input that causes a mismatch to become a match.
        if host.starts_with('.') || host.ends_with('.') || host.contains("..") {
            return None;
        }

        let port = match port {
            Some(p) => p,
            None if scheme == "https" => 443,
            None => 80,
        };

        Some(Self { scheme, host, port })
    }

    /// The scheme, lowercased.
    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    /// The host, lowercased.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port, with the scheme's default filled in.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Whether a credential stored for `self` may be offered on `page`.
    ///
    /// Exact match on all three components. See the module docs for why this
    /// is not looser.
    pub fn may_fill(&self, page: &Origin) -> bool {
        self == page
    }

    /// Canonical string form, omitting the default port.
    pub fn to_canonical_string(&self) -> String {
        let default = if self.scheme == "https" { 443 } else { 80 };
        if self.port == default {
            format!("{}://{}", self.scheme, self.host)
        } else {
            format!("{}://{}:{}", self.scheme, self.host, self.port)
        }
    }
}

impl core::fmt::Display for Origin {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_canonical_string())
    }
}

/// Split an authority into host and optional port, handling IPv6 brackets.
fn split_host_port(authority: &str) -> Option<(&str, Option<u16>)> {
    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: [::1]:8080
        let (host, after) = rest.split_once(']')?;
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':')?.parse().ok()?),
        };
        return Some((host, port));
    }

    match authority.rsplit_once(':') {
        Some((host, port)) => Some((host, Some(port.parse().ok()?))),
        None => Some((authority, None)),
    }
}
