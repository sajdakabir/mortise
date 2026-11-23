//! macOS keychain integration, and identifying local socket peers.
//!
//! **This is the only crate in the project that uses `unsafe`.** Everything
//! else is `forbid(unsafe_code)`, and the point of isolating the FFI here is
//! that a reviewer only has to read one small file carefully.
//!
//! The job is narrow: store a few bytes in the login keychain, optionally
//! behind a Touch ID prompt, and read them back.
//!
//! ## Why no LocalAuthentication
//!
//! The obvious approach — call `LAContext.evaluatePolicy`, and on success read
//! an unprotected keychain item — is weaker than it looks: the item is still
//! readable by anything that can skip the check. Instead the keychain item
//! itself carries a `SecAccessControl` requiring user presence, so the
//! *keychain* enforces it and raises the prompt during `SecItemCopyMatching`.
//! Nothing can read the bytes without passing that check.
//!
//! It also sidesteps biometric enrolment entirely: `kSecAccessControlUserPresence`
//! means "Touch ID, or the device passcode", so there is no availability check
//! to get wrong and no path where a user without Touch ID is locked out.

#![cfg_attr(not(target_os = "macos"), allow(unused))]
#![warn(missing_docs)]

mod error;

#[cfg(target_os = "macos")]
mod keychain;

#[cfg(target_os = "macos")]
mod process;

pub use error::{Error, Result};

#[cfg(target_os = "macos")]
pub use keychain::{Protection, delete, exists, load, store};

#[cfg(target_os = "macos")]
pub use process::{peer_pid, process_info};

/// A process as the kernel reports it. Nothing here comes from the process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    /// Process id.
    pub pid: i32,
    /// Parent's pid, if it has a living parent other than launchd.
    pub parent_pid: Option<i32>,
    /// Path of the running executable.
    pub executable: Option<std::path::PathBuf>,
    /// Current working directory.
    pub cwd: Option<std::path::PathBuf>,
    /// When the process started, in microseconds since the Unix epoch.
    ///
    /// A pid alone does not name a process for long: once it exits, the
    /// number is reused. Pid plus start time does.
    pub started_at_us: u64,
}

/// `pid` and up to `depth` of its ancestors, nearest first.
///
/// Shown to the user so "`mortise` ← `zsh` ← `claude`" reveals whether a
/// person or an agent asked. Stops early at launchd or a process that has
/// already exited.
pub fn process_chain(pid: i32, depth: usize) -> Vec<ProcessInfo> {
    let mut chain = Vec::new();
    let mut next = Some(pid);
    while let Some(pid) = next {
        if chain.len() > depth {
            break;
        }
        let Some(info) = process_info(pid) else { break };
        next = info.parent_pid.filter(|p| *p > 1);
        chain.push(info);
    }
    chain
}

/// Stubs for non-macOS builds, so the rest of the workspace still compiles.
///
/// v1 is macOS only; these exist so `cargo check` on another platform fails
/// with a clear runtime error rather than a wall of missing symbols.
#[cfg(not(target_os = "macos"))]
mod stub {
    use super::{Error, Result};
    use zeroize::Zeroizing;

    /// How a stored secret is protected.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Protection {
        /// Readable whenever the device is unlocked.
        DeviceUnlocked,
        /// Requires Touch ID or the device passcode on every read.
        UserPresence,
    }

    /// Unsupported off macOS.
    pub fn store(_: &str, _: &str, _: &[u8], _: Protection) -> Result<()> {
        Err(Error::Unsupported)
    }
    /// Unsupported off macOS.
    pub fn load(_: &str, _: &str, _: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Err(Error::Unsupported)
    }
    /// Unsupported off macOS.
    pub fn delete(_: &str, _: &str) -> Result<()> {
        Err(Error::Unsupported)
    }
    /// Unsupported off macOS.
    pub fn exists(_: &str, _: &str) -> Result<bool> {
        Err(Error::Unsupported)
    }
}

#[cfg(not(target_os = "macos"))]
pub use stub::{Protection, delete, exists, load, store};

/// Unsupported off macOS: no peer can be identified, so callers refuse.
#[cfg(not(target_os = "macos"))]
pub fn peer_pid(_: std::os::fd::RawFd) -> Option<i32> {
    None
}

/// Unsupported off macOS.
#[cfg(not(target_os = "macos"))]
pub fn process_info(_: i32) -> Option<ProcessInfo> {
    None
}
