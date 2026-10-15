//! Fixed-size secret bytes that zeroize on drop and compare in constant time.
//!
//! Spec §9: never `String` or bare `[u8; N]` for key material.

use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

/// `N` secret bytes. Zeroized on drop, redacted in `Debug`, compared in
/// constant time.
///
/// `Clone` is intentionally available — wrapping a key for several recipients
/// needs it — but every clone is independently zeroized.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes<const N: usize>([u8; N]);

impl<const N: usize> SecretBytes<N> {
    /// Wrap existing bytes. Prefer [`SecretBytes::random`] for new keys.
    pub fn new(bytes: [u8; N]) -> Self {
        Self(bytes)
    }

    /// Generate `N` fresh bytes from the OS CSPRNG.
    pub fn random() -> Result<Self> {
        Ok(Self(crate::rand::bytes::<N>()?))
    }

    /// Wrap a slice, which must be exactly `N` bytes.
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        let bytes: [u8; N] = slice.try_into().map_err(|_| Error::Length {
            expected: N,
            got: slice.len(),
        })?;
        Ok(Self(bytes))
    }

    /// Borrow the raw bytes.
    ///
    /// Named to make every call site obvious in review. Do not copy the result
    /// into an unprotected buffer.
    pub fn expose(&self) -> &[u8; N] {
        &self.0
    }

    /// Length in bytes. Always `N`.
    pub const fn len(&self) -> usize {
        N
    }

    /// Always false; present so `len` does not trip clippy.
    pub const fn is_empty(&self) -> bool {
        N == 0
    }
}

/// Redacted: printing a key by accident is a real way to leak one.
impl<const N: usize> core::fmt::Debug for SecretBytes<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecretBytes<{N}>(redacted)")
    }
}

impl<const N: usize> ConstantTimeEq for SecretBytes<N> {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

/// Constant-time, so secrets can be compared without a timing oracle.
impl<const N: usize> PartialEq for SecretBytes<N> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl<const N: usize> Eq for SecretBytes<N> {}

/// A 256-bit symmetric key. The workhorse of the spec's key hierarchy.
pub type Key32 = SecretBytes<32>;

/// A 128-bit salt. Not secret, but fixed-size, so it shares the plumbing.
pub type Salt16 = [u8; 16];
