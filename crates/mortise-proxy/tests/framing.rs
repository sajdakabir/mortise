//! Native messaging framing tests.

use std::io::Cursor;

use mortise_proxy::error_frame;
use mortise_proxy::framing::{MAX_MESSAGE, read_frame, write_frame};

#[test]
fn a_frame_round_trips() {
    let message = br#"{"type":"get_logins","origin":"https://github.com"}"#;

    let mut written = Vec::new();
    write_frame(&mut written, message).unwrap();

    let mut cursor = Cursor::new(written);
    assert_eq!(
        read_frame(&mut cursor).unwrap().as_deref(),
        Some(&message[..])
    );
}

#[test]
fn several_frames_read_in_order() {
    let mut stream = Vec::new();
    for msg in [b"first".as_slice(), b"second", b"third"] {
        write_frame(&mut stream, msg).unwrap();
    }

    let mut cursor = Cursor::new(stream);
    for expected in [b"first".as_slice(), b"second", b"third"] {
        assert_eq!(read_frame(&mut cursor).unwrap().as_deref(), Some(expected));
    }
    assert_eq!(read_frame(&mut cursor).unwrap(), None);
}

/// A clean end of stream is how the browser says it closed, so it must be a
/// normal shutdown rather than an error the proxy reports back.
#[test]
fn a_clean_eof_is_not_an_error() {
    let mut empty = Cursor::new(Vec::new());
    assert_eq!(read_frame(&mut empty).unwrap(), None);
}

#[test]
fn an_empty_payload_round_trips() {
    let mut written = Vec::new();
    write_frame(&mut written, b"").unwrap();
    assert_eq!(written.len(), 4);

    let mut cursor = Cursor::new(written);
    assert_eq!(read_frame(&mut cursor).unwrap(), Some(Vec::new()));
}

/// The length prefix is native-endian, which is what the protocol specifies.
/// Using big-endian would work on nothing and fail silently on everything.
#[test]
fn the_length_prefix_is_native_endian() {
    let mut written = Vec::new();
    write_frame(&mut written, b"abcd").unwrap();
    assert_eq!(&written[..4], &4u32.to_ne_bytes());
}

/// A declared length nobody could honour must be refused before allocating it.
/// Without the cap, one hostile frame header makes the proxy try to reserve a
/// gigabyte.
#[test]
fn an_oversized_length_is_rejected_without_allocating() {
    let mut header = u32::MAX.to_ne_bytes().to_vec();
    header.extend_from_slice(b"short");

    let mut cursor = Cursor::new(header);
    let err = read_frame(&mut cursor).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
}

#[test]
fn a_length_just_over_the_cap_is_rejected() {
    let header = ((MAX_MESSAGE + 1) as u32).to_ne_bytes().to_vec();
    let mut cursor = Cursor::new(header);
    assert!(read_frame(&mut cursor).is_err());
}

/// A frame claiming more bytes than follow is truncation, not a short read to
/// be papered over.
#[test]
fn a_truncated_frame_is_an_error() {
    let mut stream = 100u32.to_ne_bytes().to_vec();
    stream.extend_from_slice(b"only a few bytes");

    let mut cursor = Cursor::new(stream);
    assert!(read_frame(&mut cursor).is_err());
}

#[test]
fn a_truncated_length_prefix_is_an_error() {
    let mut cursor = Cursor::new(vec![0u8, 1]);
    assert!(read_frame(&mut cursor).is_err());
}

#[test]
fn writing_an_oversized_payload_is_refused() {
    let huge = vec![0u8; MAX_MESSAGE + 1];
    let mut sink = Vec::new();
    assert!(write_frame(&mut sink, &huge).is_err());
}

#[test]
fn a_frame_at_exactly_the_cap_is_accepted() {
    let payload = vec![b'x'; MAX_MESSAGE];
    let mut written = Vec::new();
    write_frame(&mut written, &payload).unwrap();

    let mut cursor = Cursor::new(written);
    assert_eq!(read_frame(&mut cursor).unwrap().unwrap().len(), MAX_MESSAGE);
}

#[test]
fn binary_payloads_survive_intact() {
    let payload: Vec<u8> = (0..=255u8).cycle().take(5000).collect();
    let mut written = Vec::new();
    write_frame(&mut written, &payload).unwrap();

    let mut cursor = Cursor::new(written);
    assert_eq!(read_frame(&mut cursor).unwrap().unwrap(), payload);
}

/// The error frame is hand-built rather than serialized, so its escaping has
/// to be right or a stray quote in a path produces invalid JSON at exactly the
/// moment the user needs a readable message.
///
/// Checks the property that actually matters — the result parses, and the
/// message survives intact — rather than counting quote characters.
#[test]
fn error_frames_are_valid_json_with_the_message_intact() {
    let nasty = r#"path "with" quotes, a \ backslash, and /slashes/"#;
    let frame = error_frame("io", nasty);

    let parsed: serde_json::Value =
        serde_json::from_slice(&frame).expect("error frame was not valid JSON");

    assert_eq!(parsed["type"], "error");
    assert_eq!(parsed["code"], "io");
    assert_eq!(parsed["message"], nasty);
}

#[test]
fn error_frames_handle_control_characters() {
    let frame = error_frame("io", "line one\nline two\ttabbed\u{0}nul");
    let parsed: serde_json::Value =
        serde_json::from_slice(&frame).expect("control characters broke the JSON");

    let message = parsed["message"].as_str().unwrap();
    assert!(message.contains("line one"));
    assert!(message.contains("tabbed"));
    // The raw NUL must not survive into the output.
    assert!(!message.contains('\u{0}'));
}
