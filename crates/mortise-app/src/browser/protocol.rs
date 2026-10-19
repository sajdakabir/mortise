//! The wire protocol between the browser extension and the app.
//!
//! JSON frames over a Unix socket, relayed by `mortise-proxy`.
//!
//! # Trust model
//!
//! The socket lives in the app's data directory, so only this user can reach
//! it. That is not enough on its own: *any* process running as this user could
//! connect and ask for credentials. Two things stop it.
//!
//! 1. **Association requires explicit approval in the app.** A client cannot
//!    pair itself; a human has to click approve in a window the client cannot
//!    draw. This is the control that actually matters.
//! 2. **Every later request carries an HMAC** over its own contents, keyed by
//!    the association secret. A process that never paired cannot forge one.
//!
//! What this does *not* defend against is a process that can read the browser
//! profile and steal the stored association key. At that point the attacker is
//! already inside the browser, which is a lost game for any password manager.
//! Documented rather than pretended away.

use serde::{Deserialize, Serialize};

/// Requests the extension can make.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// Is the app there, is this client paired, is the vault unlocked.
    ///
    /// The only request that needs no association — the extension calls it
    /// before it has one.
    Status,

    /// Ask to pair. Requires a human to approve in the app.
    Associate {
        /// Browser name, shown in the approval prompt.
        client_name: String,
        /// Token from this client's previous `approval_required` reply.
        ///
        /// Absent on the first ask. Present on every poll after it, and the
        /// approved key is released only to the client that presents the
        /// token the approval was granted against — otherwise approving a
        /// pairing would mint a key for whoever asked next, which is anyone.
        #[serde(default)]
        request_token: Option<String>,
    },

    /// Credentials that may be offered on `origin`. Metadata only.
    Logins {
        /// Page origin, as the browser reports it.
        origin: String,
        /// Association id.
        id: String,
        /// HMAC proof.
        proof: String,
    },

    /// A login the user just typed on a page, offered for saving.
    ///
    /// Carries a secret *into* the app rather than out of it, which is the
    /// opposite direction from everything else here. It still needs a proof:
    /// without one, any local process could stuff arbitrary items into the
    /// vault, and an item the user believes they saved is one they will trust.
    Capture {
        /// Page origin, as the browser reports it. Never the page's own claim.
        origin: String,
        /// Username field value, if one was found.
        username: Option<String>,
        /// The password that was submitted.
        password: String,
        /// Association id.
        id: String,
        /// HMAC proof.
        proof: String,
    },

    /// The actual secret for one item on one origin.
    Credential {
        /// Item id, hex.
        item_id: String,
        /// Page origin. Re-checked server-side; never trusted from the client.
        origin: String,
        /// Association id.
        id: String,
        /// HMAC proof.
        proof: String,
    },
}

/// Responses the app sends.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    /// Answer to [`Request::Status`].
    Status {
        /// Whether this client is paired.
        associated: bool,
        /// Whether secrets are currently available.
        unlocked: bool,
    },
    /// Pairing needs a human, and this is the token to come back with.
    ApprovalRequired {
        /// Opaque, single-use, bound to this request.
        request_token: String,
    },
    /// Pairing succeeded.
    Associated {
        /// Association id to send with later requests.
        id: String,
        /// Secret for computing proofs, base64.
        key: String,
    },
    /// Matching items, without secrets.
    Logins {
        /// Candidates for this origin.
        items: Vec<LoginCandidate>,
    },
    /// One credential.
    Credential {
        /// Username, if the item has one.
        username: Option<String>,
        /// The password.
        password: String,
    },
    /// A capture was handled.
    Captured {
        /// False when this login is already saved, so nothing was queued.
        queued: bool,
    },
    /// Something went wrong.
    Error {
        /// Stable machine-readable code.
        code: String,
        /// Message safe to show a user.
        message: String,
    },
}

/// One item that could fill on the current page. Carries no secret.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginCandidate {
    /// Item id, hex.
    pub item_id: String,
    /// Display name.
    pub title: String,
    /// Username, if any.
    pub username: Option<String>,
}

impl Response {
    /// Build an error response.
    pub fn error(code: &str, message: &str) -> Self {
        Self::Error {
            code: code.to_string(),
            message: message.to_string(),
        }
    }
}

/// Canonical bytes a request's proof is computed over.
///
/// Built field by field with length prefixes rather than by re-serializing the
/// JSON. Two reasons: serde_json gives no canonical ordering guarantee, and a
/// proof over "whatever JSON arrived" would let an attacker who can reorder or
/// reformat fields reuse a captured proof for a different request.
///
/// The item id and origin are both covered, so a proof captured for one origin
/// cannot be replayed to pull a credential for another.
pub fn proof_payload(request: &Request) -> Option<Vec<u8>> {
    let mut out = Vec::new();

    let push = |out: &mut Vec<u8>, part: &str| {
        out.extend_from_slice(&(part.len() as u32).to_be_bytes());
        out.extend_from_slice(part.as_bytes());
    };

    match request {
        Request::Logins { origin, id, .. } => {
            push(&mut out, "logins");
            push(&mut out, id);
            push(&mut out, origin);
        }
        Request::Credential {
            item_id,
            origin,
            id,
            ..
        } => {
            push(&mut out, "credential");
            push(&mut out, id);
            push(&mut out, origin);
            push(&mut out, item_id);
        }
        // The password is covered too, so a captured proof cannot be replayed
        // with a different password substituted for the same origin.
        //
        // A missing username and an empty one hash identically. They mean the
        // same thing here, so that is not worth a discriminator byte.
        Request::Capture {
            origin,
            username,
            password,
            id,
            ..
        } => {
            push(&mut out, "capture");
            push(&mut out, id);
            push(&mut out, origin);
            push(&mut out, username.as_deref().unwrap_or(""));
            push(&mut out, password);
        }
        // Status and Associate carry no proof: the first needs none, and the
        // second is the request that establishes the key in the first place.
        Request::Status | Request::Associate { .. } => return None,
    }

    Some(out)
}
