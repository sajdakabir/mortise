//! Browser extension integration.
//!
//! Three processes, deliberately:
//!
//! ```text
//! extension  --native messaging-->  truepass-proxy  --unix socket-->  app
//! ```
//!
//! See [`truepass_proxy`] for why the middle one exists, and [`protocol`] for
//! the trust model.

pub mod associations;
pub mod native_host;
pub mod protocol;
pub mod server;
