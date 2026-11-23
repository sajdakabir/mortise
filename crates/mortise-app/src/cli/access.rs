//! Who the command line may hand secrets to, and who is waiting to ask.
//!
//! Two lists, both in memory only:
//!
//! - **Grants**, of two kinds:
//!   - *directory*: "anything run from this directory may read `api/dev`
//!     until six o'clock". Created by *Allow for 8 hours* on a `mortise run`.
//!   - *agent session*: "anything this agent process runs may read
//!     `api/dev`". Created by approving `mortise agent`. Bound to the agent's
//!     pid **and start time**, so it cannot outlive the agent or be inherited
//!     by whatever process is later given the same pid, and covers only
//!     requests whose kernel-reported ancestry contains that process.
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

/// A process, unambiguously: a pid is reused once its process exits, a pid
/// with its start time is not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessKey {
    /// Process id.
    pub pid: i32,
    /// Start time, microseconds since the Unix epoch.
    pub started_at_us: u64,
}

/// What a request is asking for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RequestKind {
    /// `mortise run`: values now.
    Run,
    /// `mortise agent`: a session for the agent about to start.
    Session,
}

/// Which kind of grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantKind {
    /// Covers a directory tree.
    Directory,
    /// Covers one agent process and everything it runs.
    Agent,
}

/// What let a request through without asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    /// A directory grant.
    Directory,
    /// An agent session.
    Session,
}

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
    /// What is being asked for.
    pub kind: RequestKind,
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
    /// Directory grant or agent session.
    pub kind: GrantKind,
    /// For an agent session: what the agent said it was, and its pid.
    pub agent: Option<String>,
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
    scope: Scope,
    expires: Instant,
}

enum Scope {
    Directory(PathBuf),
    Session(ProcessKey),
}

impl Grant {
    fn covers(
        &self,
        project: &str,
        environment: &str,
        cwd: &Path,
        chain: &[ProcessKey],
    ) -> Option<Coverage> {
        if self.summary.project != project || self.summary.environment != environment {
            return None;
        }
        match &self.scope {
            Scope::Directory(dir) => cwd.starts_with(dir).then_some(Coverage::Directory),
            Scope::Session(root) => chain.contains(root).then_some(Coverage::Session),
        }
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
    /// The grant that covers this request, if any. `chain` is the
    /// requester's full kernel-reported ancestry, nearest first.
    pub fn coverage(
        &self,
        project: &str,
        environment: &str,
        cwd: &Path,
        chain: &[ProcessKey],
    ) -> Option<Coverage> {
        let now = Instant::now();
        let mut grants = lock(&self.grants);
        grants.retain(|g| now < g.expires);
        // A session is the narrower statement, so it is the one reported.
        let hits: Vec<Coverage> = grants
            .iter()
            .filter_map(|g| g.covers(project, environment, cwd, chain))
            .collect();
        hits.iter()
            .find(|c| **c == Coverage::Session)
            .or(hits.first())
            .copied()
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

        // Sessions are recorded by the connection thread, which knows the
        // agent's pid and start time; only a directory grant is made here.
        if answer == Answer::ForEightHours && pending.summary.kind == RequestKind::Run {
            self.add_grant(&pending.summary, GRANT_DURATION);
        }
        // A send failure means the requester hung up while waiting. The grant
        // above still stands: the user approved that directory, and the next
        // run from it should not ask again.
        let _ = pending.reply.send(answer);
        true
    }

    fn add_grant(&self, request: &RequestSummary, duration: Duration) {
        self.push(
            request,
            Scope::Directory(PathBuf::from(&request.directory)),
            duration,
        );
    }

    /// Record an approved agent session rooted at `root`. Returns when it
    /// expires, in Unix milliseconds.
    pub fn start_session(&self, request: &RequestSummary, root: ProcessKey) -> u64 {
        self.push(request, Scope::Session(root), GRANT_DURATION)
    }

    fn push(&self, request: &RequestSummary, scope: Scope, duration: Duration) -> u64 {
        let expires_at_ms = SystemTime::now()
            .checked_add(duration)
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_millis() as u64);
        let (kind, agent) = match &scope {
            Scope::Directory(_) => (GrantKind::Directory, None),
            Scope::Session(root) => (
                GrantKind::Agent,
                Some(format!("{} (pid {})", request.command, root.pid)),
            ),
        };
        lock(&self.grants).push(Grant {
            summary: GrantSummary {
                id: request.id.clone(),
                kind,
                agent,
                project: request.project.clone(),
                environment: request.environment.clone(),
                directory: request.directory.clone(),
                expires_at_ms,
            },
            scope,
            expires: Instant::now() + duration,
        });
        expires_at_ms
    }

    /// Live grants, soonest to expire first.
    ///
    /// Sessions whose agent has exited are dropped here: `is_alive` asks the
    /// kernel whether that exact process (pid and start time) still runs.
    pub fn grants(&self, is_alive: impl Fn(ProcessKey) -> bool) -> Vec<GrantSummary> {
        let now = Instant::now();
        let mut grants = lock(&self.grants);
        grants.retain(|g| {
            now < g.expires
                && match g.scope {
                    Scope::Directory(_) => true,
                    Scope::Session(root) => is_alive(root),
                }
        });
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

/// Whether that exact process still runs, according to the kernel.
pub fn process_alive(key: ProcessKey) -> bool {
    mortise_macos::process_info(key.pid).is_some_and(|p| p.started_at_us == key.started_at_us)
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
            kind: RequestKind::Run,
            project: "api".into(),
            environment: "dev".into(),
            keys: None,
            command: "npm run dev".into(),
            directory: dir.into(),
            process_chain: vec!["/usr/local/bin/mortise".into(), "zsh".into()],
        }
    }

    fn covered(access: &CliAccess, project: &str, environment: &str, cwd: &Path) -> bool {
        access.coverage(project, environment, cwd, &[]).is_some()
    }

    const AGENT: ProcessKey = ProcessKey {
        pid: 4242,
        started_at_us: 1_700_000_000_000_000,
    };
    const SHELL: ProcessKey = ProcessKey {
        pid: 4300,
        started_at_us: 1_700_000_000_500_000,
    };
    const RUN: ProcessKey = ProcessKey {
        pid: 4301,
        started_at_us: 1_700_000_000_600_000,
    };

    fn session(access: &CliAccess) {
        let mut r = request("s", "/code/api");
        r.kind = RequestKind::Session;
        r.command = "claude".into();
        access.start_session(&r, AGENT);
    }

    #[test]
    fn a_session_covers_only_requests_descending_from_that_exact_agent() {
        let access = CliAccess::default();
        session(&access);
        let anywhere = Path::new("/somewhere/else");

        // mortise ← sh ← claude: covered, wherever it runs from.
        assert_eq!(
            access.coverage("api", "dev", anywhere, &[RUN, SHELL, AGENT]),
            Some(Coverage::Session)
        );
        // A process in the agent's directory but not its tree: not covered.
        assert_eq!(
            access.coverage("api", "dev", Path::new("/code/api"), &[RUN, SHELL]),
            None
        );
        // The same pid, started later — a reused pid, not the agent.
        let impostor = ProcessKey {
            started_at_us: AGENT.started_at_us + 1,
            ..AGENT
        };
        assert_eq!(
            access.coverage("api", "dev", anywhere, &[RUN, impostor]),
            None
        );
        // The agent's tree, but another environment.
        assert_eq!(
            access.coverage("api", "prod", anywhere, &[RUN, AGENT]),
            None
        );
    }

    #[test]
    fn a_session_ends_when_its_agent_exits_or_is_revoked() {
        let access = CliAccess::default();
        session(&access);
        let listed = access.grants(|p| p == AGENT);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].kind, GrantKind::Agent);
        assert_eq!(listed[0].agent.as_deref(), Some("claude (pid 4242)"));

        assert!(
            access.grants(|_| false).is_empty(),
            "agent gone, session gone"
        );
        assert_eq!(
            access.coverage("api", "dev", Path::new("/"), &[RUN, AGENT]),
            None
        );

        session(&access);
        assert!(access.revoke("s"));
        assert_eq!(
            access.coverage("api", "dev", Path::new("/"), &[RUN, AGENT]),
            None
        );
    }

    #[test]
    fn approving_a_session_request_makes_no_directory_grant() {
        let access = CliAccess::default();
        let mut r = request("s", "/code/api");
        r.kind = RequestKind::Session;
        let _rx = access.enqueue(r).unwrap();
        access.answer("s", Answer::ForEightHours);
        assert!(!covered(&access, "api", "dev", Path::new("/code/api")));
    }

    #[test]
    fn once_serves_one_request_and_leaves_no_grant() {
        let access = CliAccess::default();
        let rx = access.enqueue(request("a", "/code/api")).unwrap();
        assert!(access.answer("a", Answer::Once));
        assert_eq!(rx.recv().unwrap(), Answer::Once);
        assert!(!covered(&access, "api", "dev", Path::new("/code/api")));
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

        assert!(covered(&access, "api", "dev", Path::new("/code/api")));
        assert!(covered(
            &access,
            "api",
            "dev",
            Path::new("/code/api/web/src")
        ));
        assert!(!covered(&access, "api", "prod", Path::new("/code/api")));
        assert!(!covered(&access, "web", "dev", Path::new("/code/api")));
        assert!(!covered(&access, "api", "dev", Path::new("/code")));
        // A sibling whose name merely starts the same way is not inside.
        assert!(!covered(&access, "api", "dev", Path::new("/code/api-evil")));
    }

    #[test]
    fn grants_expire_and_can_be_revoked() {
        let access = CliAccess::default();
        access.add_grant(&request("short", "/code/a"), Duration::ZERO);
        access.add_grant(&request("long", "/code/b"), GRANT_DURATION);

        assert!(
            !covered(&access, "api", "dev", Path::new("/code/a")),
            "expired"
        );
        assert_eq!(
            access
                .grants(|_| true)
                .iter()
                .map(|g| g.id.as_str())
                .collect::<Vec<_>>(),
            ["long"]
        );

        assert!(access.revoke("long"));
        assert!(!covered(&access, "api", "dev", Path::new("/code/b")));
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
        assert!(!covered(&access, "api", "dev", Path::new("/x")));
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
