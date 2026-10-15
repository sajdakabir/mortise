//! Registering the native messaging host, from the app rather than a script.
//!
//! A browser will only launch a native helper it has been told about, through
//! a small JSON manifest dropped in a per-browser directory. Something has to
//! write that file.
//!
//! `extension/tools/install-host.sh` does it for development and still works.
//! It is the wrong thing to put in front of a user: installing a password
//! manager should not require a terminal, and the script's failure modes —
//! wrong profile directory, proxy not built, stale path after a rebuild — are
//! all invisible until autofill silently does nothing.
//!
//! So the app writes it. The app already knows where its own proxy binary is,
//! which is the part a script has to be told.

use std::fs;
use std::path::PathBuf;

use serde::Serialize;

/// Must match the `name` the extension passes to `connectNative`.
const HOST_NAME: &str = "com.mortise.proxy";

/// Every Chromium-family browser reads from its own directory, so the manifest
/// has to be written once per browser rather than to one shared location.
/// Paths are relative to `~/Library/Application Support`, and name the
/// browser's *user data* directory.
///
/// Note the two layouts. Chrome's user data directory is the product folder
/// itself (`Google/Chrome`); the newer forks put theirs one level down, in
/// `<Product>/User Data`. Getting this wrong does not fail loudly — the
/// manifest lands somewhere the browser never reads, registration reports
/// success, and autofill simply never works.
const BROWSERS: &[(&str, &str)] = &[
    ("Google Chrome", "Google/Chrome"),
    ("Chrome Canary", "Google/Chrome Canary"),
    ("Chromium", "Chromium"),
    ("Brave", "BraveSoftware/Brave-Browser"),
    ("Microsoft Edge", "Microsoft Edge"),
    ("Dia", "Dia/User Data"),
    ("Arc", "Arc/User Data"),
    ("Vivaldi", "Vivaldi"),
    ("Opera", "com.operasoftware.Opera"),
];

/// What went wrong registering the host.
#[derive(Debug)]
pub enum Error {
    /// The id is not a Chrome extension id.
    BadExtensionId,
    /// No Chromium-family browser is installed.
    NoBrowsers,
    /// The proxy binary is not next to the app.
    ProxyMissing(PathBuf),
    /// Writing the manifest failed.
    Io(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadExtensionId => write!(
                f,
                "That is not a Chrome extension ID — they are 32 letters, a to p."
            ),
            Self::NoBrowsers => write!(f, "No Chrome, Brave, Edge or Chromium found on this Mac."),
            Self::ProxyMissing(p) => write!(f, "The helper is missing from {}.", p.display()),
            Self::Io(e) => write!(f, "Could not write the browser manifest: {e}"),
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[derive(Serialize)]
struct HostManifest<'a> {
    name: &'a str,
    description: &'a str,
    path: String,
    #[serde(rename = "type")]
    kind: &'a str,
    /// The access control. Only this extension may spawn the proxy — leaving it
    /// broad would let any installed extension reach the vault.
    allowed_origins: Vec<String>,
}

/// What the UI needs to show the browser-connection step.
#[derive(Debug, Clone, Serialize)]
pub struct HostStatus {
    /// Browsers installed on this Mac.
    pub browsers: Vec<String>,
    /// Browsers the host manifest is currently written for.
    pub registered: Vec<String>,
    /// The extension id currently authorised, if any.
    pub extension_id: Option<String>,
    /// Whether the proxy binary is actually present.
    pub proxy_present: bool,
}

fn support_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join("Library/Application Support"))
}

/// Where this browser's manifest goes, if the browser is installed at all.
///
/// Presence is judged by the browser's own support directory, not by creating
/// one: making `NativeMessagingHosts` under a browser nobody has installed
/// leaves litter and tells the user we registered something we did not.
fn manifest_path(relative: &str) -> Option<PathBuf> {
    let base = support_dir()?.join(relative);
    base.is_dir()
        .then(|| base.join("NativeMessagingHosts").join(format!("{HOST_NAME}.json")))
}

/// The proxy ships beside the app binary — `target/debug` in development,
/// `TruePassword.app/Contents/MacOS` once bundled. Deriving it from the running
/// executable means the same code is right in both, and that a rebuilt proxy
/// never leaves a stale absolute path behind in a browser's manifest.
fn proxy_path() -> Result<PathBuf, Error> {
    let exe = std::env::current_exe()?;
    let dir = exe.parent().ok_or_else(|| {
        Error::Io(std::io::Error::other("the running binary has no parent directory"))
    })?;
    let proxy = dir.join("mortise-proxy");
    if !proxy.is_file() {
        return Err(Error::ProxyMissing(proxy));
    }
    Ok(proxy)
}

/// Chrome extension ids are exactly 32 characters from a-p. Checking here turns
/// a typo into a clear message now, rather than a browser that silently refuses
/// to connect later with nothing logged anywhere the user can see.
fn valid_extension_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_lowercase() && b <= b'p')
}

/// Register the host for every installed Chromium-family browser.
///
/// Returns the browsers it was written for.
pub fn install(extension_id: &str) -> Result<Vec<String>, Error> {
    let id = extension_id.trim();
    if !valid_extension_id(id) {
        return Err(Error::BadExtensionId);
    }

    let proxy = proxy_path()?;
    let json = manifest_json(&proxy, id)?;

    let mut written = Vec::new();
    for (name, relative) in BROWSERS {
        let Some(path) = manifest_path(relative) else {
            continue;
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, &json)?;
        written.push((*name).to_string());
    }

    if written.is_empty() {
        return Err(Error::NoBrowsers);
    }
    Ok(written)
}

/// The exact bytes the browser reads.
///
/// Split out so the shape can be tested without writing into the real browser
/// directories: these field names are Chrome's, not ours, and a typo in one
/// produces a host the browser silently never launches.
fn manifest_json(proxy: &std::path::Path, extension_id: &str) -> Result<Vec<u8>, std::io::Error> {
    let manifest = HostManifest {
        name: HOST_NAME,
        description: "TruePassword native messaging bridge",
        path: proxy.to_string_lossy().into_owned(),
        kind: "stdio",
        allowed_origins: vec![format!("chrome-extension://{extension_id}/")],
    };
    serde_json::to_vec_pretty(&manifest).map_err(std::io::Error::other)
}

/// Remove the host manifest everywhere. Autofill stops working.
pub fn uninstall() -> Result<(), Error> {
    for (_, relative) in BROWSERS {
        if let Some(path) = manifest_path(relative)
            && path.is_file()
        {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

/// Current registration, for the onboarding step.
pub fn status() -> HostStatus {
    let mut browsers = Vec::new();
    let mut registered = Vec::new();
    let mut extension_id = None;

    for (name, relative) in BROWSERS {
        let Some(path) = manifest_path(relative) else {
            continue;
        };
        browsers.push((*name).to_string());

        let Ok(bytes) = fs::read(&path) else { continue };
        registered.push((*name).to_string());

        // Recover the id we authorised so the UI can show it rather than
        // asking for something the user already supplied once.
        if extension_id.is_none()
            && let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes)
            && let Some(origin) = value
                .get("allowed_origins")
                .and_then(|o| o.get(0))
                .and_then(|o| o.as_str())
        {
            extension_id = origin
                .trim_start_matches("chrome-extension://")
                .trim_end_matches('/')
                .to_string()
                .into();
        }
    }

    HostStatus {
        browsers,
        registered,
        extension_id,
        proxy_present: proxy_path().is_ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_a_real_looking_extension_id() {
        assert!(valid_extension_id("abcdefghijklmnopabcdefghijklmnop"));
    }

    /// Ids are base-16 encoded into a-p, so q-z never appear. A 32-character
    /// string that merely looks right is the likely paste error.
    #[test]
    fn rejects_letters_outside_a_to_p() {
        assert!(!valid_extension_id("abcdefghijklmnozabcdefghijklmnop"));
    }

    #[test]
    fn rejects_the_wrong_length() {
        assert!(!valid_extension_id("abcdefghijklmnop"));
        assert!(!valid_extension_id(""));
    }

    #[test]
    fn rejects_uppercase_and_digits() {
        assert!(!valid_extension_id("ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP"));
        assert!(!valid_extension_id("abcdefghijklmno1abcdefghijklmnop"));
    }

    /// Chrome's own field names. `type` rather than `kind`, `allowed_origins`
    /// with the trailing slash on the origin — get any of these wrong and the
    /// browser simply never launches the host, with nothing logged.
    #[test]
    fn the_manifest_is_shaped_the_way_chrome_expects() {
        let json = manifest_json(
            std::path::Path::new("/Applications/TruePassword.app/Contents/MacOS/mortise-proxy"),
            "abcdefghijklmnopabcdefghijklmnop",
        )
        .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();

        assert_eq!(v["name"], HOST_NAME);
        assert_eq!(v["type"], "stdio");
        assert_eq!(
            v["path"],
            "/Applications/TruePassword.app/Contents/MacOS/mortise-proxy"
        );
        assert_eq!(
            v["allowed_origins"],
            serde_json::json!(["chrome-extension://abcdefghijklmnopabcdefghijklmnop/"]),
            "the origin needs the scheme and the trailing slash"
        );
    }

    /// Exactly one extension may spawn the proxy. A manifest that authorised
    /// more than one would let another installed extension reach the vault.
    #[test]
    fn only_one_origin_is_authorised() {
        let json = manifest_json(std::path::Path::new("/tmp/p"), "a".repeat(32).as_str()).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(v["allowed_origins"].as_array().unwrap().len(), 1);
    }

    /// Dia and Arc put their user data in `<Product>/User Data`, not in the
    /// product folder. Writing to the product folder lands the manifest where
    /// the browser never looks: registration reports success and autofill
    /// silently never works, which is exactly how this was found.
    #[test]
    fn forks_with_a_user_data_directory_keep_that_segment() {
        for product in ["Dia", "Arc"] {
            let (_, path) = BROWSERS
                .iter()
                .find(|(name, _)| *name == product)
                .unwrap_or_else(|| panic!("{product} is missing from the browser list"));
            assert_eq!(
                *path,
                format!("{product}/User Data"),
                "{product} reads from <Product>/User Data"
            );
        }
    }

    /// Chrome is the other layout: its user data directory *is* the product
    /// folder, so adding "User Data" here would break it the same way.
    #[test]
    fn chrome_has_no_user_data_segment() {
        let (_, path) = BROWSERS
            .iter()
            .find(|(name, _)| *name == "Google Chrome")
            .expect("Chrome is missing from the browser list");
        assert_eq!(*path, "Google/Chrome");
    }

    /// Two browsers writing to one directory would mean the second silently
    /// overwrote the first.
    #[test]
    fn no_two_browsers_share_a_directory() {
        let mut seen = std::collections::HashSet::new();
        for (name, path) in BROWSERS {
            assert!(seen.insert(*path), "{name} shares a directory with another");
        }
    }

    /// The host name is what the extension passes to `connectNative`. If these
    /// ever drift the browser reports only that the host is not found.
    #[test]
    fn host_name_matches_the_extension() {
        let background = include_str!("../../../../extension/background.js");
        assert!(
            background.contains(HOST_NAME),
            "background.js does not mention {HOST_NAME}"
        );
    }
}
