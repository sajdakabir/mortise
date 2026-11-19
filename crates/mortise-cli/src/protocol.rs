//! Messages on the command-line socket.
//!
//! Shared by the `mortise` binary and the app so the two cannot drift. Framed
//! with the same length prefix as the browser socket
//! ([`mortise_proxy::framing`]); one request per connection.
//!
//! A request can take a while: the app may need the user to unlock, then to
//! approve. Rather than leaving the terminal silent, the app sends
//! [`Response::Waiting`] frames first and the final answer last.

use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// What the command line asks for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    /// Variables from one environment of one project.
    Env {
        /// Project name, matched case-insensitively.
        project: String,
        /// Environment name, matched exactly.
        environment: String,
        /// Only these keys, or every key when `None`.
        keys: Option<Vec<String>>,
        /// The command about to run, for the approval prompt.
        ///
        /// A claim by the client, shown as one. The directory and process
        /// chain beside it come from the kernel, not from here.
        command: String,
    },
    /// Start an agent session: the process making this request is about to
    /// `exec` an agent, and anything that agent runs may then read this
    /// environment without asking again, until it exits or the session ends.
    ///
    /// The session is bound to this connection's process as the kernel
    /// reports it — pid and start time — so it cannot be claimed by a
    /// process outside the agent's tree.
    StartSession {
        /// Project name, matched case-insensitively.
        project: String,
        /// Environment name, matched exactly.
        environment: String,
        /// The agent about to run, for the approval prompt. A claim.
        command: String,
    },
}

/// What the app answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    /// Still working; more frames follow.
    Waiting {
        /// What the app is waiting for.
        reason: WaitReason,
    },
    /// The variables. Final.
    Env {
        /// Sorted by key.
        vars: Vec<Var>,
    },
    /// The agent session is live. Final.
    SessionStarted {
        /// When it ends at the latest, in Unix milliseconds.
        expires_at_ms: u64,
    },
    /// The request was refused or failed. Final.
    Error {
        /// Machine-readable reason.
        code: ErrorCode,
        /// Shown to the user as is.
        message: String,
    },
}

impl Response {
    /// Shorthand for an error response.
    pub fn error(code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Error {
            code,
            message: message.into(),
        }
    }
}

/// Why the app has not answered yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaitReason {
    /// The vault is locked; the user has been asked to unlock it.
    Unlock,
    /// The user has been asked to approve this request.
    Approval,
}

/// Why a request failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// No vault on this Mac, or it will not open.
    NoVault,
    /// The vault stayed locked.
    Locked,
    /// No project by that name.
    UnknownProject,
    /// The project has no environment by that name.
    UnknownEnvironment,
    /// Some requested keys are not in the environment.
    MissingKeys,
    /// The user said no.
    Denied,
    /// Nobody answered in time.
    Timeout,
    /// Too many requests are already waiting.
    Busy,
    /// The kernel would not say which process is asking.
    Unidentified,
    /// The request was malformed.
    BadRequest,
    /// Something went wrong inside the app.
    Internal,
    /// A code from a newer app this binary does not know.
    #[serde(other)]
    Other,
}

/// One environment variable. The value is wiped when this is dropped and is
/// never printed by `Debug`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Var {
    /// Variable name.
    pub key: String,
    /// Secret value.
    pub value: String,
}

impl Drop for Var {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl fmt::Debug for Var {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Var")
            .field("key", &self.key)
            .field("value", &"<redacted>")
            .finish()
    }
}
