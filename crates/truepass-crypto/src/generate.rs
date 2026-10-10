//! Password and passphrase generation.
//!
//! Lives here rather than in the UI layer because the trap is cryptographic:
//! picking a character with `rand_byte % charset.len()` is biased whenever the
//! charset size does not divide 256. For a 70-character set that skews the
//! first 46 characters ~1.4% more likely than the rest — small, but it is
//! entropy the user thinks they have and does not.
//!
//! This uses rejection sampling instead, so every character is uniform.

use zeroize::Zeroizing;

use crate::error::Result;

/// Lowercase letters.
pub const LOWER: &str = "abcdefghijkmnopqrstuvwxyz";
/// Uppercase letters.
pub const UPPER: &str = "ABCDEFGHJKLMNPQRSTUVWXYZ";
/// Digits.
pub const DIGITS: &str = "23456789";
/// Punctuation safe to paste into most fields.
pub const SYMBOLS: &str = "!@#$%^&*()-_=+[]{}:,.?";

/// Characters excluded from the sets above because they are easily confused
/// when read aloud or off a screen: `l`, `I`, `1`, `O`, `0`.
pub const EXCLUDED_AMBIGUOUS: &str = "lI1O0";

/// What to include in a generated password.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PasswordSpec {
    /// Total length.
    pub length: usize,
    /// Include lowercase.
    pub lower: bool,
    /// Include uppercase.
    pub upper: bool,
    /// Include digits.
    pub digits: bool,
    /// Include symbols.
    pub symbols: bool,
}

impl Default for PasswordSpec {
    fn default() -> Self {
        Self {
            length: 20,
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
        }
    }
}

impl PasswordSpec {
    fn charset(&self) -> String {
        let mut set = String::new();
        if self.lower {
            set.push_str(LOWER);
        }
        if self.upper {
            set.push_str(UPPER);
        }
        if self.digits {
            set.push_str(DIGITS);
        }
        if self.symbols {
            set.push_str(SYMBOLS);
        }
        set
    }

    /// Shannon entropy in bits, assuming uniform selection.
    ///
    /// Honest only because selection really is uniform — with modulo bias this
    /// number would overstate the strength.
    pub fn entropy_bits(&self) -> f64 {
        let n = self.charset().chars().count();
        if n < 2 || self.length == 0 {
            return 0.0;
        }
        (n as f64).log2() * self.length as f64
    }
}

/// Generate a password.
///
/// Returns an error if the spec selects no character classes or zero length.
pub fn password(spec: PasswordSpec) -> Result<Zeroizing<String>> {
    let charset: Vec<char> = spec.charset().chars().collect();
    if charset.len() < 2 || spec.length == 0 {
        return Err(crate::error::Error::Params);
    }

    let mut out = Zeroizing::new(String::with_capacity(spec.length));
    for _ in 0..spec.length {
        out.push(charset[uniform_below(charset.len())?]);
    }
    Ok(out)
}

/// A uniformly random `usize` in `0..n`, by rejection sampling.
///
/// Draws 4 bytes at a time and discards any draw landing in the final partial
/// block, which is what removes the bias a bare modulo would introduce.
fn uniform_below(n: usize) -> Result<usize> {
    debug_assert!(n > 0);
    let n = n as u32;

    // Largest multiple of n that fits in u32; draws at or above it are discarded.
    let limit = u32::MAX - (u32::MAX % n) - (n - 1);

    loop {
        let value = u32::from_be_bytes(crate::rand::bytes::<4>()?);
        if value <= limit {
            return Ok((value % n) as usize);
        }
    }
}

/// Generate a passphrase from a caller-supplied word list.
///
/// The list is a parameter rather than embedded: shipping a dictionary would
/// add hundreds of kilobytes to a binary whose size is a product goal, and the
/// UI layer can load one lazily if the user wants passphrases.
pub fn passphrase(words: &[&str], count: usize, separator: char) -> Result<Zeroizing<String>> {
    if words.len() < 2 || count == 0 {
        return Err(crate::error::Error::Params);
    }

    let mut out = Zeroizing::new(String::new());
    for i in 0..count {
        if i > 0 {
            out.push(separator);
        }
        out.push_str(words[uniform_below(words.len())?]);
    }
    Ok(out)
}
