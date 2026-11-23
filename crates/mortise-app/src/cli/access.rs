//! Who the command line may hand secrets to, and who is waiting to ask.
//!
//! Two lists, both in memory only:
//!
//! - **Grants**: "anything run from this directory may read `api/dev` until
//!   six o'clock". Created when the user picks *Allow for 8 hours*.
//! - **Pending**: requests waiting for the user. Each holds the channel its
//!   connection thread is blocked on.
//!
//! Nothing here is persisted. If the app restarts, every grant is gone and
//! the next run asks again — the safe direction to fail, and the same choice
//! the browser pairing flow makes for unanswered approvals.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::mpsc::{Receiver, Sender, channel};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// How long *Allow for 8 hours* lasts.
pub const GRANT_DURATION: Duration = Duration::from_secs(8 * 60 * 60);

/// Most requests allowed to wait at once.
///
/// A local process could otherwise queue prompts faster than anyone can read
/// them, and a backlog of approval dialogs is how people start clicking
/// Allow without looking.
pub const MAX_PENDING: usize = 4;

/// Files that mark the top of a project for the purpose of a grant.
const ROOT_MARKERS: [&str; 2] = [".mortise.toml", ".git"];

/// The user's answer to a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Answer {
    /// Refuse.
    Deny,
    /// This request only.
    Once,
    /// This request, and any like it from the same directory for
    /// [`GRANT_DURATION`].
    ForEightHours,
}

/// A request as the approval prompt shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RequestSummary {
    /// Opaque id for answering.
    pub id: String,
    /// Canonical project name.
    pub project: String,
    /// Environment.
    pub environment: String,
    /// Specific keys asked for, or `None` for the whole environment.
    pub keys: Option<Vec<String>>,
    /// The command line, as the client claims it.
    pub command: String,
    /// The directory a grant would cover. From the kernel.
    pub directory: String,
    /// The requesting process and its ancestors, nearest first. From the
    /// kernel; the first entry is a full path so an impostor binary shows.
    pub process_chain: Vec<String>,
}

/// A live grant, as Settings shows it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct GrantSummary {
    /// Opaque id for revoking.
    pub id: String,
    /// Canonical project name.
    pub project: String,
    /// Environment.
    pub environment: String,
    /// Directory it covers, including everything below it.
    pub directory: String,
    /// When it expires, for display only. Expiry itself is decided by a
    /// monotonic clock, so moving the system clock back cannot extend it.
    pub expires_at_ms: u64,
}

struct Grant {
    summary: GrantSummary,
    directory: PathBuf,
    expires: Instant,
}

impl Grant {
    fn covers(&self, project: &str, environment: &str, cwd: &Path, now: Instant) -> bool {
        now < self.expires
            && self.summary.project == project
            && self.summary.environment == environment
            && cwd.starts_with(&self.directory)
    }
}

struct Pending {
    summary: RequestSummary,
    reply: Sender<Answer>,
}

/// The command line's access state. One per app.
#[derive(Default)]
pub struct CliAccess {
    grants: Mutex<Vec<Grant>>,
    pending: Mutex<Vec<Pending>>,
}

impl CliAccess {
    /// Whether a live grant covers this request.
    pub fn is_granted(&self, project: &str, environment: &str, cwd: &Path) -> bool {
        let now = Instant::now();
        let mut grants = lock(&self.grants);
        grants.retain(|g| now < g.expires);
        grants
            .iter()
            .any(|g| g.covers(project, environment, cwd, now))
    }

    /// Queue a request for the user. Returns the receiver its answer will
    /// arrive on, or `None` when the queue is full.
    pub fn enqueue(&self, summary: RequestSummary) -> Option<Receiver<Answer>> {
        let mut pending = lock(&self.pending);
        if pending.len() >= MAX_PENDING {
            return None;
        }
        let (reply, answer) = channel();
        pending.push(Pending { summary, reply });
        Some(answer)
    }

    /// Drop a request that stopped waiting (timed out), so the prompt does
    /// not offer to approve something nobody is listening for.
    pub fn withdraw(&self, id: &str) {
        lock(&self.pending).retain(|p| p.summary.id != id);
    }

    /// The oldest request waiting for the user.
    pub fn next_pending(&self) -> Option<RequestSummary> {
        lock(&self.pending).first().map(|p| p.summary.clone())
    }

    /// Answer a waiting request. Records a grant for
    /// [`Answer::ForEightHours`]. Returns false if the request had already
    /// gone.
    pub fn answer(&self, id: &str, answer: Answer) -> bool {
        let Some(pending) = ({
            let mut queue = lock(&self.pending);
            queue
                .iter()
                .position(|p| p.summary.id == id)
                .map(|i| queue.remove(i))
        }) else {
            return false;
        };

        if answer == Answer::ForEightHours {
            self.add_grant(&pending.summary, GRANT_DURATION);
        }
        // A send failure means the requester hung up while waiting. The grant
        // above still stands: the user approved that directory, and the next
        // run from it should not ask again.
        let _ = pending.reply.send(answer);
        true
    }

    fn add_grant(&self, request: &RequestSummary, duration: Duration) {
        let expires_at_ms = SystemTime::now()
            .checked_add(duration)
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_millis() as u64);
        lock(&self.grants).push(Grant {
            summary: GrantSummary {
                id: request.id.clone(),
                project: request.project.clone(),
                environment: request.environment.clone(),
                directory: request.directory.clone(),
                expires_at_ms,
            },
            directory: PathBuf::from(&request.directory),
            expires: Instant::now() + duration,
        });
    }

    /// Live grants, soonest to expire first.
    pub fn grants(&self) -> Vec<GrantSummary> {
        let now = Instant::now();
        let mut grants = lock(&self.grants);
        grants.retain(|g| now < g.expires);
        let mut out: Vec<GrantSummary> = grants.iter().map(|g| g.summary.clone()).collect();
        out.sort_by_key(|g| g.expires_at_ms);
        out
    }

    /// End a grant now. Returns false if there was none by that id.
    pub fn revoke(&self, id: &str) -> bool {
        let mut grants = lock(&self.grants);
        let before = grants.len();
        grants.retain(|g| g.summary.id != id);
        grants.len() != before
    }
}

/// The directory a grant for a request from `cwd` should cover.
///
/// The nearest ancestor holding `.mortise.toml` or `.git`, so approving
/// `npm run dev` in `api/web` also covers `api/scripts` — but never `$HOME`
/// or `/`. A dotfiles repository in the home directory would otherwise turn
/// one approval into "everything this user runs". Falls back to `cwd`.
pub fn grant_root(cwd: &Path, home: Option<&Path>, has_marker: impl Fn(&Path) -> bool) -> PathBuf {
    cwd.ancestors()
        .take_while(|dir| dir.parent().is_some() && Some(*dir) != home)
        .find(|dir| has_marker(dir))
        .unwrap_or(cwd)
        .to_path_buf()
}

/// [`grant_root`] against the real filesystem.
pub fn grant_root_on_disk(cwd: &Path) -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    grant_root(cwd, home.as_deref(), |dir| {
        ROOT_MARKERS.iter().any(|m| dir.join(m).exists())
    })
}

/// A poisoned lock here means a panic mid-update of a list of plain values;
/// the data is still well-formed, so carry on rather than lock everyone out.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(id: &str, dir: &str) -> RequestSummary {
        RequestSummary {
            id: id.into(),
            project: "api".into(),
            environment: "dev".into(),
            keys: None,
            command: "npm run dev".into(),
            directory: dir.into(),
            process_chain: vec!["/usr/local/bin/mortise".into(), "zsh".into()],
        }
    }

    #[test]
    fn once_serves_one_request_and_leaves_no_grant() {
        let access = CliAccess::default();
        let rx = access.enqueue(request("a", "/code/api")).unwrap();
        assert!(access.answer("a", Answer::Once));
        assert_eq!(rx.recv().unwrap(), Answer::Once);
        assert!(!access.is_granted("api", "dev", Path::new("/code/api")));
        assert!(
            !access.answer("a", Answer::Once),
            "an answered request cannot be answered again"
        );
    }

    #[test]
    fn a_grant_covers_its_directory_tree_project_and_environment_only() {
        let access = CliAccess::default();
        let _rx = access.enqueue(request("a", "/code/api")).unwrap();
        access.answer("a", Answer::ForEightHours);

        assert!(access.is_granted("api", "dev", Path::new("/code/api")));
        assert!(access.is_granted("api", "dev", Path::new("/code/api/web/src")));
        assert!(!access.is_granted("api", "prod", Path::new("/code/api")));
        assert!(!access.is_granted("web", "dev", Path::new("/code/api")));
        assert!(!access.is_granted("api", "dev", Path::new("/code")));
        // A sibling whose name merely starts the same way is not inside.
        assert!(!access.is_granted("api", "dev", Path::new("/code/api-evil")));
    }

    #[test]
    fn grants_expire_and_can_be_revoked() {
        let access = CliAccess::default();
        access.add_grant(&request("short", "/code/a"), Duration::ZERO);
        access.add_grant(&request("long", "/code/b"), GRANT_DURATION);

        assert!(
            !access.is_granted("api", "dev", Path::new("/code/a")),
            "expired"
        );
        assert_eq!(
            access
                .grants()
                .iter()
                .map(|g| g.id.as_str())
                .collect::<Vec<_>>(),
            ["long"]
        );

        assert!(access.revoke("long"));
        assert!(!access.is_granted("api", "dev", Path::new("/code/b")));
        assert!(!access.revoke("long"));
    }

    #[test]
    fn the_queue_is_bounded_and_withdrawn_requests_vanish() {
        let access = CliAccess::default();
        let receivers: Vec<_> = (0..MAX_PENDING)
            .map(|i| access.enqueue(request(&i.to_string(), "/x")).unwrap())
            .collect();
        assert!(access.enqueue(request("overflow", "/x")).is_none());

        assert_eq!(access.next_pending().unwrap().id, "0", "oldest first");
        access.withdraw("0");
        assert_eq!(access.next_pending().unwrap().id, "1");
        assert!(!access.answer("0", Answer::Once));
        drop(receivers);
    }

    #[test]
    fn a_denial_reaches_the_waiting_request() {
        let access = CliAccess::default();
        let rx = access.enqueue(request("a", "/x")).unwrap();
        access.answer("a", Answer::Deny);
        assert_eq!(rx.recv().unwrap(), Answer::Deny);
        assert!(!access.is_granted("api", "dev", Path::new("/x")));
    }

    #[test]
    fn the_grant_root_is_the_nearest_marked_ancestor_below_home() {
        let home = Path::new("/Users/me");
        let marked =
            |dirs: &'static [&'static str]| move |d: &Path| dirs.iter().any(|m| d == Path::new(m));

        // Run from deep inside a repository: the repository root.
        assert_eq!(
            grant_root(
                Path::new("/Users/me/code/api/web/src"),
                Some(home),
                marked(&["/Users/me/code/api"])
            ),
            Path::new("/Users/me/code/api")
        );
        // A dotfiles repository in $HOME must not widen a grant to everything.
        assert_eq!(
            grant_root(
                Path::new("/Users/me/scratch"),
                Some(home),
                marked(&["/Users/me"])
            ),
            Path::new("/Users/me/scratch")
        );
        // Nor may `/`, outside home.
        assert_eq!(
            grant_root(Path::new("/tmp/x"), Some(home), marked(&["/"])),
            Path::new("/tmp/x")
        );
        // No marker at all: just the directory itself.
        assert_eq!(
            grant_root(Path::new("/Users/me/a/b"), Some(home), marked(&[])),
            Path::new("/Users/me/a/b")
        );
    }
}
