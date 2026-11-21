//! The `mortise` command line's side of the app.
//!
//! The binary lives in `mortise-cli`; this is the socket it talks to and the
//! approvals that guard it. See `docs/cli.md` for the user-facing behaviour
//! and `docs/threat-model.md` (A10) for why it is shaped this way.

pub mod access;
pub mod server;
