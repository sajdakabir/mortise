//! Chrome native messaging framing.
//!
//! Each message is a 4-byte **native-endian** length followed by that many
//! bytes of UTF-8 JSON. Native-endian, not big-endian, is what the protocol
//! actually specifies — it is a common and silent source of bugs, because on
//! every platform this ships to it happens to be little-endian, so getting it
//! wrong works until it suddenly does not.
//!
//! The same framing is reused on the Unix socket to the app. There is no reason
//! to translate between two framings when one will do.

use std::io::{self, Read, Write};

/// Largest message accepted from the browser.
///
/// Chrome's own limit is 64 MB, but nothing in this protocol is remotely that
/// big: the largest legitimate message is a credential. A smaller cap means a
/// confused or hostile sender cannot make us allocate a gigabyte.
pub const MAX_MESSAGE: usize = 1024 * 1024;

/// Read one frame. Returns `Ok(None)` at a clean end of stream.
///
/// A clean EOF is how the browser says the user closed it, so it is a normal
/// shutdown rather than an error.
pub fn read_frame(reader: &mut impl Read) -> io::Result<Option<Vec<u8>>> {
    // Read the prefix manually rather than with read_exact, which cannot tell
    // "the stream ended cleanly" from "the stream ended mid-prefix". Zero bytes
    // is the browser closing; one to three bytes is a truncated message, and
    // silently treating that as a clean shutdown would hide a real fault.
    let mut len_bytes = [0u8; 4];
    let mut filled = 0;
    while filled < 4 {
        match reader.read(&mut len_bytes[filled..]) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    format!("length prefix truncated after {filled} bytes"),
                ));
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }

    let len = u32::from_ne_bytes(len_bytes) as usize;
    if len > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("message of {len} bytes exceeds the {MAX_MESSAGE} byte limit"),
        ));
    }

    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf)?;
    Ok(Some(buf))
}

/// Write one frame and flush.
///
/// Flushing matters: the browser blocks waiting for a reply, so a response
/// sitting in a buffer looks exactly like a hung native host.
pub fn write_frame(writer: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    if payload.len() > MAX_MESSAGE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "response exceeds the message size limit",
        ));
    }
    writer.write_all(&(payload.len() as u32).to_ne_bytes())?;
    writer.write_all(payload)?;
    writer.flush()
}
