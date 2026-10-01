//! Application state and the auto-lock clock.
//!
//! The vault lives behind a mutex here and **never** leaves this process. The
//! webview gets DTOs; it never gets a key, a handle, or a path.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use truepass_vault::Vault;

use crate::browser::associations::Association;

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
        }
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
