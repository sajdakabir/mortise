//! The crate's only source of randomness.
//!
//! Spec §1: OS CSPRNG, never a userspace PRNG for key material. Every random
//! byte in this crate comes through here so there is exactly one place to audit.

use crate::error::{Error, Result};

/// Fill `buf` with cryptographically secure random bytes from the OS.
pub fn fill(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| Error::Rng)
}

/// Return `N` cryptographically secure random bytes from the OS.
pub fn bytes<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}
