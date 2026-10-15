//! Application state and the auto-lock clock.
//!
//! The vault lives behind a mutex here and **never** leaves this process. The
//! webview gets DTOs; it never gets a key, a handle, or a path.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use mortise_vault::Vault;

use crate::browser::associations::Association;

/// A login the browser saw submitted, waiting for the user to accept it.
///
/// The password is plaintext in memory for as long as this exists, which is
/// why it is dropped the moment the user decides either way and zeroized when
/// it goes. Nothing persists it: if the app restarts first, the capture is
/// lost and the user saves it by hand, which is the safe direction to fail.
pub struct PendingCapture {
    /// Origin the browser reported, never the page's own claim.
    pub origin: String,
    /// Username field value, if the page had one.
    pub username: Option<String>,
    /// The submitted password.
    pub password: zeroize::Zeroizing<String>,
}

/// How long without user activity before the vault locks itself.
///
/// Five minutes is the usual default for this class of app. It is deliberately
/// not configurable to "never" — see [`AppState::tick`].
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// How often the auto-lock clock checks.
pub const TICK_INTERVAL: Duration = Duration::from_secs(10);

struct Inner {
    vault: Option<Vault>,
    last_activity: Instant,
    idle_timeout: Duration,
}

/// Shared application state.
pub struct AppState {
    vault_path: PathBuf,
    inner: Mutex<Inner>,
    /// Name of a browser waiting to be approved, if any.
    pending_association: Mutex<Option<String>>,
    /// An approved association the extension has not collected yet.
    ///
    /// Held in memory only. If the app restarts before the extension picks it
    /// up, the user approves again — which is the safe direction to fail.
    approved_association: Mutex<Option<Association>>,
    /// A submitted login waiting for the user to accept or discard it.
    pending_capture: Mutex<Option<PendingCapture>>,
}

impl AppState {
    /// Create state for a vault at `vault_path`. The file need not exist yet.
    pub fn new(vault_path: PathBuf) -> Self {
        Self {
            vault_path,
            inner: Mutex::new(Inner {
                vault: None,
                last_activity: Instant::now(),
                idle_timeout: DEFAULT_IDLE_TIMEOUT,
            }),
            pending_association: Mutex::new(None),
            approved_association: Mutex::new(None),
            pending_capture: Mutex::new(None),
        }
    }

    /// Hold a submitted login for the user to accept.
    ///
    /// Replaces any earlier one. Two sign-ins in a row should offer the second,
    /// not queue both: a backlog of password prompts is how people start
    /// clicking through them.
    pub fn set_pending_capture(&self, capture: PendingCapture) {
        if let Ok(mut pending) = self.pending_capture.lock() {
            *pending = Some(capture);
        }
    }

    /// Origin and username of the waiting capture. Never the password.
    pub fn pending_capture_summary(&self) -> Option<(String, Option<String>)> {
        let guard = self.pending_capture.lock().ok()?;
        let capture = guard.as_ref()?;
        Some((capture.origin.clone(), capture.username.clone()))
    }

    /// Take the waiting capture, leaving none behind.
    pub fn take_pending_capture(&self) -> Option<PendingCapture> {
        self.pending_capture.lock().ok()?.take()
    }

    /// Throw the waiting capture away.
    pub fn clear_pending_capture(&self) {
        let _ = self.take_pending_capture();
    }

    /// Record that a browser is asking to pair.
    pub fn set_pending_association(&self, name: String) {
        if let Ok(mut pending) = self.pending_association.lock() {
            *pending = Some(name);
        }
    }

    /// The browser currently asking to pair, if any.
    pub fn pending_association(&self) -> Option<String> {
        self.pending_association.lock().ok()?.clone()
    }

    /// Clear a pending request without approving it.
    pub fn clear_pending_association(&self) {
        if let Ok(mut pending) = self.pending_association.lock() {
            *pending = None;
        }
    }

    /// Hand an approved association to the next `associate` call.
    pub fn set_approved_association(&self, association: Association) {
        if let Ok(mut approved) = self.approved_association.lock() {
            *approved = Some(association);
        }
        self.clear_pending_association();
    }

    /// Collect an approved association. Returns it at most once.
    pub fn take_approved_association(&self) -> Option<Association> {
        self.approved_association.lock().ok()?.take()
    }

    /// Where the vault file lives.
    pub fn vault_path(&self) -> &PathBuf {
        &self.vault_path
    }

    /// Whether a vault file exists on disk.
    pub fn vault_exists(&self) -> bool {
        self.vault_path.exists()
    }

    /// Record user activity, deferring auto-lock.
    pub fn touch(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.last_activity = Instant::now();
        }
    }

    /// Change the idle timeout.
    ///
    /// Clamped to at least a minute: a zero or near-zero timeout would make the
    /// app unusable, and there is no "never" because an unattended unlocked
    /// vault is the single most likely way a user loses everything.
    pub fn set_idle_timeout(&self, timeout: Duration) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.idle_timeout = timeout.max(Duration::from_secs(60));
        }
    }

    /// Lock if the idle timeout has elapsed. Returns true if it locked now.
    ///
    /// Called by the background clock. Uses `Instant`, not wall-clock time, so
    /// moving the system clock backwards cannot defer a lock.
    pub fn tick(&self) -> bool {
        let Ok(mut inner) = self.inner.lock() else {
            return false;
        };
        let idle = inner.last_activity.elapsed();
        let timeout = inner.idle_timeout;

        match inner.vault.as_mut() {
            Some(v) if v.is_unlocked() && idle >= timeout => {
                v.lock();
                true
            }
            _ => false,
        }
    }

    /// Run `f` with the vault, opening it from disk if needed.
    ///
    /// Returns `None` to `f` when no vault file exists yet.
    pub fn with_vault<T>(&self, f: impl FnOnce(Option<&mut Vault>) -> T) -> T {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        if inner.vault.is_none() && self.vault_path.exists() {
            // Open lazily and locked. A failure here is surfaced to the caller
            // as "no vault" rather than panicking the app.
            inner.vault = Vault::open(&self.vault_path).ok();
        }
        let vault = inner.vault.as_mut();
        f(vault)
    }

    /// Install a freshly created vault.
    pub fn install(&self, vault: Vault) {
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        inner.last_activity = Instant::now();
        inner.vault = Some(vault);
    }
}
