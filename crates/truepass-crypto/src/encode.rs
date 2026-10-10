//! Deterministic binary encoding for anything that gets hashed or signed.
//!
//! # Why not CBOR
//!
//! The spec originally called for "canonical CBOR". `ciborium` does not
//! guarantee canonical output — map key ordering in particular is not pinned.
//! For a hash-linked change log that is not cosmetic: two devices could encode
//! the same logical change into different bytes, compute different change ids,
//! and fork the DAG permanently.
//!
//! Rather than hand-roll a CBOR canonicalizer and hope, this encoding removes
//! the problem by construction:
//!
//! * no maps, so there is no key ordering to get wrong
//! * no self-description, so there is no tag/length representation choice
//! * fixed field order, written explicitly by each type
//! * explicit length prefixes, so concatenation is unambiguous
//! * fixed-width big-endian integers
//!
//! Every encodable type writes a leading [`Tag`] so a signature over one type
//! can never be replayed as a signature over another.

/// Domain separation tag, written as the first byte of every encoded struct.
///
/// Never renumber an existing tag: doing so silently invalidates every
/// signature ever produced over that type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Tag {
    /// A device certificate (spec §2.3).
    DeviceCert = 1,
    /// A change in the vault log (spec §5).
    Change = 2,
    /// An entry in the ACL log (spec §6).
    AclEntry = 3,
}

/// Append-only deterministic writer.
#[derive(Debug, Clone)]
pub struct Writer(Vec<u8>);

impl Writer {
    /// Start a new buffer for the given type.
    pub fn new(tag: Tag) -> Self {
        Self(vec![tag as u8])
    }

    /// Write one byte.
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }

    /// Write a big-endian `u32`.
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Write a big-endian `u64`.
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_be_bytes());
        self
    }

    /// Write `N` bytes with no length prefix. Only for genuinely fixed-width
    /// fields such as public keys and digests.
    pub fn fixed<const N: usize>(&mut self, v: &[u8; N]) -> &mut Self {
        self.0.extend_from_slice(v);
        self
    }

    /// Write a variable-length byte string, `u32` length prefix first.
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.u32(v.len() as u32);
        self.0.extend_from_slice(v);
        self
    }

    /// Write a sequence of fixed-width items, count first.
    ///
    /// The caller is responsible for ordering. For sets whose order is not
    /// semantically meaningful, sort before calling or the encoding is not
    /// deterministic across devices.
    pub fn fixed_seq<'a, const N: usize, I>(&mut self, items: I) -> &mut Self
    where
        I: IntoIterator<Item = &'a [u8; N]>,
        I::IntoIter: ExactSizeIterator,
    {
        let iter = items.into_iter();
        self.u32(iter.len() as u32);
        for item in iter {
            self.0.extend_from_slice(item);
        }
        self
    }

    /// Finish, yielding the encoded bytes.
    pub fn finish(&self) -> Vec<u8> {
        self.0.clone()
    }

    /// Finish and hash with BLAKE3. The common case, since almost everything
    /// encoded here exists to be hashed or signed.
    pub fn digest(&self) -> [u8; 32] {
        *blake3::hash(&self.0).as_bytes()
    }
}

/// A type with exactly one canonical byte representation.
pub trait Canonical {
    /// Write `self` into `w` in canonical field order.
    fn encode(&self, w: &mut Writer);

    /// The tag this type is encoded under.
    fn tag() -> Tag;

    /// Canonical bytes, including the leading tag.
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new(Self::tag());
        self.encode(&mut w);
        w.finish()
    }

    /// BLAKE3 digest of the canonical bytes. This is what gets signed.
    fn canonical_digest(&self) -> [u8; 32] {
        let mut w = Writer::new(Self::tag());
        self.encode(&mut w);
        w.digest()
    }
}
