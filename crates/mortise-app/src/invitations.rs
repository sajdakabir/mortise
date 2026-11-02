//! Incoming links only open a confirmation screen. They never contact a relay,
//! unlock a vault or grant access. Keep the bearer link in memory, not logs.

use std::sync::Mutex;
use zeroize::Zeroizing;

/// Bind a displayed request to the sealed bytes fetched again on approval.
pub fn request_token(sealed: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(sealed)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Refuse a swapped request before any membership or key delivery is written.
pub fn verify_request(sealed: &[u8], expected: &str) -> crate::error::CmdResult<()> {
    if request_token(sealed) != expected {
        return Err(crate::error::CmdError::bad_request(
            "The access request changed. Review it again before allowing access.",
        ));
    }
    Ok(())
}

/// One bounded pending link, including one delivered before the UI starts.
#[derive(Default)]
pub struct IncomingInvite(Mutex<Option<Zeroizing<String>>>);

impl IncomingInvite {
    /// Accept only the invitation route and its base64url payload. Full crypto
    /// validation happens when the recipient inspects the invitation.
    pub fn receive(&self, link: &str) -> bool {
        let Some(payload) = link
            .strip_prefix(mortise_crypto::invite::LINK_PREFIX)
            .or_else(|| link.strip_prefix("mortise://team-invite#"))
        else {
            return false;
        };
        if payload.is_empty()
            || link.len() > 8192
            || !payload
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return false;
        }
        let Ok(mut pending) = self.0.lock() else {
            return false;
        };
        // Do not replace an invitation the person has not seen yet.
        if pending.is_some() {
            return false;
        }
        *pending = Some(Zeroizing::new(link.to_owned()));
        true
    }

    /// Deliver once to the main window. The UI retains it across unlock.
    pub fn take(&self) -> Option<String> {
        self.0.lock().ok()?.take().map(|link| link.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_invite_route_is_accepted() {
        let queue = IncomingInvite::default();
        for bad in [
            "https://example.com",
            "mortise://join",
            "mortise://join#",
            "mortise://join?redirect=https://example.com#abc",
            "mortise://delete#abc",
            "mortise://join#abc%2F",
            "mortise://join#abc\n",
        ] {
            assert!(!queue.receive(bad));
        }
        assert!(!queue.receive(&format!("mortise://join#{}", "a".repeat(8192))));
        assert!(queue.take().is_none());
    }

    #[test]
    fn cold_start_delivery_is_once_and_not_overwritten() {
        let queue = IncomingInvite::default();
        assert!(queue.receive("mortise://join#first_123"));
        assert!(!queue.receive("mortise://join#second-456"));
        assert_eq!(queue.take().as_deref(), Some("mortise://join#first_123"));
        assert!(queue.take().is_none());
        assert!(queue.receive("mortise://join#second-456"));
    }

    #[test]
    fn account_invitation_is_delivered_without_granting_access() {
        let queue = IncomingInvite::default();
        assert!(queue.receive("mortise://team-invite#payload_123"));
        assert_eq!(
            queue.take().as_deref(),
            Some("mortise://team-invite#payload_123")
        );
        assert!(queue.take().is_none());
        assert!(!queue.receive("mortise://team-invite#"));
    }

    #[test]
    fn approval_is_bound_to_the_request_that_was_displayed() {
        let expected = request_token(b"displayed authenticated request");
        assert!(verify_request(b"displayed authenticated request", &expected).is_ok());
        assert!(verify_request(b"replacement authenticated request", &expected).is_err());
        assert!(verify_request(b"displayed authenticated request", "").is_err());
    }
}
