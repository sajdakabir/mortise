//! The `mortise` command line.
//!
//! `mortise run -- <command>` starts `<command>` with secrets from the vault
//! in its environment, so they never sit in a `.env` file on disk. The binary
//! holds no keys and opens no vault: it asks the running app over a local
//! socket, the app asks the user, and the answer is handed straight to the
//! child process.
//!
//! The library half exists so the app and the binary share one definition of
//! the protocol, and so the parsing rules are testable without a socket.

#![forbid(unsafe_code)]
#![warn(missing_docs, clippy::all)]

pub mod args;
pub mod config;
pub mod plan;
pub mod protocol;
pub mod template;
