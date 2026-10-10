//! The proxy binary. See the crate docs for why it exists.

use std::io;
use std::os::unix::net::UnixStream;

use truepass_proxy::framing::{read_frame, write_frame};
use truepass_proxy::{error_frame, socket_path};

fn main() {
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();

    while let Some(request) = match read_frame(&mut stdin) {
        Ok(frame) => frame,
        // A malformed frame means the stream is no longer trustworthy, so stop
        // rather than trying to resynchronise on a boundary we cannot find.
        Err(e) => {
            let _ = write_frame(&mut stdout, &error_frame("protocol", &e.to_string()));
            return;
        }
    } {
        let response =
            forward(&request).unwrap_or_else(|(code, message)| error_frame(code, &message));
        if write_frame(&mut stdout, &response).is_err() {
            return; // browser went away
        }
    }
}

/// One request, one short-lived connection.
///
/// Reconnecting per message rather than holding one open means the app can be
/// restarted — or crash — without the extension needing to notice, and a
/// wedged connection cannot outlive a single request.
fn forward(request: &[u8]) -> Result<Vec<u8>, (&'static str, String)> {
    let path = socket_path().ok_or(("internal", "no home directory".into()))?;

    let mut socket = UnixStream::connect(&path).map_err(|_| {
        (
            "app_not_running",
            "TruePassword is not running. Open it to use autofill.".to_string(),
        )
    })?;

    write_frame(&mut socket, request).map_err(|e| ("io", e.to_string()))?;

    match read_frame(&mut socket) {
        Ok(Some(response)) => Ok(response),
        Ok(None) => Err(("io", "TruePassword closed the connection".into())),
        Err(e) => Err(("io", e.to_string())),
    }
}
