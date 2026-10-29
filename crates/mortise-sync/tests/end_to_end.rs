//! Full-stack sync: two vaults, a real relay on a real socket.
//!
//! The relay runs on its own thread with its own runtime, and the tests are
//! plain blocking functions. That is deliberate — the client is blocking
//! (ureq), and calling it from inside a tokio runtime would mean wrapping
//! every call in spawn_blocking for no benefit to the thing under test.

use std::sync::Mutex;

use tempfile::TempDir;
use mortise_crypto::identity::Device;
use mortise_crypto::kdf::Argon2Params;
use mortise_relay::protocol::{PullResponse, WireChange};
use mortise_relay::server::router;
use mortise_relay::store::Store;
use mortise_sync::transport::Transport;
use mortise_sync::{Error, HttpTransport, Syncer};
use mortise_vault::enroll;
use mortise_vault::{ItemMeta, ItemPayload, Vault};

const FAST: Argon2Params = Argon2Params {
    m_cost_kib: 64,
    t_cost: 1,
    p_cost: 1,
};
const PASSWORD: &[u8] = b"correct horse battery staple";

/// Start a relay on an ephemeral port and return its base URL.
fn spawn_relay() -> String {
    let (tx, rx) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            let store = Store::open(":memory:").unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send(listener.local_addr().unwrap()).unwrap();
            axum::serve(listener, router(store)).await.unwrap();
        });
    });

    format!("http://{}", rx.recv().unwrap())
}

fn item(title: &str, password: &str) -> (ItemMeta, ItemPayload) {
    (
        ItemMeta {
            title: title.into(),
            ..Default::default()
        },
        ItemPayload::Login {
            password: password.into(),
            totp_seed: None,
            notes: None,
        },
    )
}

fn titles(vault: &Vault) -> Vec<String> {
    let mut names: Vec<String> = vault
        .list()
        .unwrap()
        .into_iter()
        .map(|s| s.meta.title)
        .collect();
    names.sort();
    names
}

/// Two devices on one account, both registered with the relay.
struct Fixture {
    _dir: TempDir,
    a: Vault,
    b: Vault,
    syncer: Syncer<HttpTransport>,
}

// The fixture's account key, stashed so tests can re-unlock after locking.
//
// A thread local rather than a field: `Vault` deliberately never exposes the
// account key again after creation, and a test helper should not be the thing
// that pokes a hole in that.
thread_local! {
    static ACCOUNT_KEY: std::cell::RefCell<Option<mortise_crypto::secret::Key32>> =
        const { std::cell::RefCell::new(None) };
}

fn reopen_account_key() -> mortise_crypto::secret::Key32 {
    ACCOUNT_KEY.with(|k| k.borrow().clone().expect("fixture did not stash a key"))
}

impl Fixture {
    fn new() -> Self {
        let url = spawn_relay();
        let dir = TempDir::new().unwrap();

        let (mut a, account_key) = Vault::create(dir.path().join("a.db"), PASSWORD, FAST).unwrap();
        let device_b = Device::generate().unwrap();
        let enrollment = a.enroll_device(device_b.public()).unwrap();
        let b = enroll::join(
            dir.path().join("b.db"),
            PASSWORD,
            &account_key,
            &device_b,
            &enrollment,
        )
        .unwrap();

        ACCOUNT_KEY.with(|k| *k.borrow_mut() = Some(account_key.clone()));
        let syncer = Syncer::new(HttpTransport::new(&url));

        // A registers the vault, then authorizes B.
        syncer.claim(&a).unwrap();
        syncer
            .authorize_device(
                &a,
                device_b.public().id().as_bytes(),
                device_b.public().signing_public(),
            )
            .unwrap();

        a.set_relay_url(Some(&url)).unwrap();
        b.set_relay_url(Some(&url)).unwrap();

        Self {
            _dir: dir,
            a,
            b,
            syncer,
        }
    }
}

// --- the happy path ---

#[test]
fn an_item_reaches_the_other_device_through_the_relay() {
    let mut f = Fixture::new();
    let (meta, payload) = item("GitHub", "hunter2");
    let id = f.a.create_item(&meta, &payload).unwrap();

    let pushed = f.syncer.sync(&mut f.a).unwrap();
    assert!(pushed.pushed >= 1, "nothing was uploaded");

    let pulled = f.syncer.sync(&mut f.b).unwrap();
    assert!(pulled.pulled >= 1, "nothing was downloaded");
    assert_eq!(pulled.rejected, 0);

    assert_eq!(titles(&f.b), vec!["GitHub"]);
    assert_eq!(f.b.reveal(id).unwrap(), payload);
}

#[test]
fn edits_flow_both_ways() {
    let mut f = Fixture::new();

    f.a.create_item(&item("From A", "a").0, &item("From A", "a").1)
        .unwrap();
    f.b.create_item(&item("From B", "b").0, &item("From B", "b").1)
        .unwrap();

    f.syncer.sync(&mut f.a).unwrap();
    f.syncer.sync(&mut f.b).unwrap();
    f.syncer.sync(&mut f.a).unwrap();

    assert_eq!(titles(&f.a), vec!["From A", "From B"]);
    assert_eq!(titles(&f.b), vec!["From A", "From B"]);
}

#[test]
fn deletions_reach_the_other_device() {
    let mut f = Fixture::new();
    let id =
        f.a.create_item(&item("Doomed", "x").0, &item("Doomed", "x").1)
            .unwrap();
    f.syncer.sync(&mut f.a).unwrap();
    f.syncer.sync(&mut f.b).unwrap();
    assert_eq!(f.b.item_count().unwrap(), 1);

    f.a.delete_item(id).unwrap();
    f.syncer.sync(&mut f.a).unwrap();
    f.syncer.sync(&mut f.b).unwrap();

    assert_eq!(f.b.item_count().unwrap(), 0);
}

#[test]
fn syncing_with_nothing_to_do_is_harmless() {
    let mut f = Fixture::new();

    let first = f.syncer.sync(&mut f.a).unwrap();
    assert_eq!(first.pushed, 0);
    assert_eq!(first.pulled, 0);

    f.a.create_item(&item("GitHub", "x").0, &item("GitHub", "x").1)
        .unwrap();
    f.syncer.sync(&mut f.a).unwrap();

    // A second round must not re-upload or re-ingest its own work.
    let second = f.syncer.sync(&mut f.a).unwrap();
    assert_eq!(second.pushed, 0);
    assert_eq!(second.pulled, 0);
    assert_eq!(f.a.item_count().unwrap(), 1);
}

#[test]
fn the_cursor_advances_and_persists() {
    let mut f = Fixture::new();
    assert_eq!(f.a.sync_cursor().unwrap(), 0);

    f.a.create_item(&item("GitHub", "x").0, &item("GitHub", "x").1)
        .unwrap();
    f.syncer.sync(&mut f.a).unwrap();

    assert!(f.a.sync_cursor().unwrap() > 0, "the cursor did not move");
}

/// Sync needs the vault unlocked, and the reason is worth stating.
///
/// `Vault::ingest` itself works locked — verifying a signature is not
/// decryption — so the storage layer could absolutely take changes in the
/// background. What cannot is the transport: signing a relay request needs the
/// device key, and `lock` drops it along with everything else.
///
/// Keeping the whole device key alive through a lock would be worse than it
/// sounds: it holds the X25519 key that unwraps vault keys, so an attacker with
/// the running process could read the vault outright. Background sync needs the
/// Ed25519 signing key split from the X25519 agreement key so only the former
/// survives locking. That is deferred, and until then sync is an
/// unlocked-only operation.
#[test]
fn sync_requires_the_vault_to_be_unlocked() {
    let mut f = Fixture::new();
    let (meta, payload) = item("GitHub", "hunter2");
    let id = f.a.create_item(&meta, &payload).unwrap();
    f.syncer.sync(&mut f.a).unwrap();

    f.b.lock();
    assert!(
        matches!(
            f.syncer.sync(&mut f.b),
            Err(Error::Vault(mortise_vault::Error::Locked))
        ),
        "sync should refuse while locked rather than half-complete"
    );

    let ak = reopen_account_key();
    f.b.unlock(PASSWORD, &ak).unwrap();
    let outcome = f.syncer.sync(&mut f.b).unwrap();
    assert!(outcome.pulled >= 1);
    assert_eq!(f.b.reveal(id).unwrap(), payload);
}

/// The storage half, in isolation: ingesting works while locked, and applying
/// waits for the key. This is what background sync would rely on once the
/// device key is split.
#[test]
fn ingest_works_while_locked_but_applying_waits() {
    let mut f = Fixture::new();
    let (meta, payload) = item("GitHub", "hunter2");
    let id = f.a.create_item(&meta, &payload).unwrap();

    let changes = f.a.unpushed_changes(100).unwrap();
    f.b.lock();

    let report = f.b.ingest(&changes).unwrap();
    assert_eq!(report.accepted, changes.len() as u32);
    assert_eq!(report.rejected, 0);
    assert!(matches!(
        f.b.apply_pending(),
        Err(mortise_vault::Error::Locked)
    ));

    let ak = reopen_account_key();
    f.b.unlock(PASSWORD, &ak).unwrap();
    assert!(f.b.apply_pending().unwrap() >= 1);
    assert_eq!(f.b.reveal(id).unwrap(), payload);
}

// --- revocation over the relay (crypto-spec §6) ---

/// The headline of Stage 2: a revocation issued on one device reaches the
/// others. The remaining member learns the removal and the rotation, picks up
/// the new epoch's key, reads what is written afterwards, and refuses anything
/// from the removed device — which is also cut off at the relay.
#[test]
fn a_revocation_reaches_the_other_device_and_cuts_off_the_removed_one() {
    let url = spawn_relay();
    let dir = TempDir::new().unwrap();

    // A owns the vault; B and C are enrolled members.
    let (mut a, account_key) = Vault::create(dir.path().join("a.db"), PASSWORD, FAST).unwrap();

    let device_b = Device::generate().unwrap();
    let enroll_b = a.enroll_device(device_b.public()).unwrap();
    let mut b = enroll::join(
        dir.path().join("b.db"),
        PASSWORD,
        &account_key,
        &device_b,
        &enroll_b,
    )
    .unwrap();

    let device_c = Device::generate().unwrap();
    let enroll_c = a.enroll_device(device_c.public()).unwrap();
    let mut c = enroll::join(
        dir.path().join("c.db"),
        PASSWORD,
        &account_key,
        &device_c,
        &enroll_c,
    )
    .unwrap();

    let syncer = Syncer::new(HttpTransport::new(&url));
    syncer.claim(&a).unwrap();
    for d in [&device_b, &device_c] {
        syncer
            .authorize_device(&a, d.public().id().as_bytes(), d.public().signing_public())
            .unwrap();
    }

    // Converge, so B learns C was added before C is removed.
    syncer.sync(&mut a).unwrap();
    syncer.sync(&mut b).unwrap();
    syncer.sync(&mut c).unwrap();
    assert!(
        b.acl().unwrap().role(device_c.public().id()).is_some(),
        "B should see C as a member before the revocation"
    );

    // A revokes C, then everyone syncs.
    let c_id = *device_c.public().id().as_bytes();
    a.revoke_member(device_c.public().id()).unwrap();
    syncer.sync(&mut a).unwrap();
    let out_b = syncer.sync(&mut b).unwrap();

    assert!(
        out_b.acl_pulled >= 2,
        "B did not receive the removal and the rotation"
    );
    assert!(out_b.keys_applied >= 1, "B did not receive the rotated key");
    assert!(
        b.acl().unwrap().role(device_c.public().id()).is_none(),
        "B still trusts the revoked device"
    );
    assert_eq!(
        b.meta().epoch.value(),
        a.meta().epoch.value(),
        "B is not on the new epoch"
    );

    // An item A writes under the new epoch reaches and opens on B.
    let (meta, payload) = item("after-revocation", "s3cret");
    let id = a.create_item(&meta, &payload).unwrap();
    syncer.sync(&mut a).unwrap();
    let out_b2 = syncer.sync(&mut b).unwrap();
    assert!(out_b2.pulled >= 1, "the post-rotation item did not reach B");
    assert_eq!(b.reveal(id).unwrap(), payload);

    // A change from the removed device is refused by B on ingest.
    c.create_item(&item("from-c", "x").0, &item("from-c", "x").1)
        .unwrap();
    let _ = syncer.push(&mut c);
    let out_b3 = syncer.sync(&mut b).unwrap();
    assert!(
        out_b3.rejected >= 1,
        "B accepted a change from the revoked device"
    );

    // Defence in depth: once C is removed at the relay, its sync is refused.
    syncer.remove_device(&a, &c_id).unwrap();
    c.create_item(&item("from-c-again", "y").0, &item("from-c-again", "y").1)
        .unwrap();
    assert!(matches!(syncer.push(&mut c), Err(Error::Refused { .. })));
}

// --- what the relay refuses ---

#[test]
fn an_unauthorized_device_cannot_sync() {
    let url = spawn_relay();
    let dir = TempDir::new().unwrap();

    let (a, _) = Vault::create(dir.path().join("a.db"), PASSWORD, FAST).unwrap();
    let (mut stranger, _) = Vault::create(dir.path().join("s.db"), PASSWORD, FAST).unwrap();
    // Without a pending change, push returns early and never reaches the relay.
    stranger
        .create_item(&item("Theirs", "x").0, &item("Theirs", "x").1)
        .unwrap();

    let syncer = Syncer::new(HttpTransport::new(&url));
    syncer.claim(&a).unwrap();

    // The stranger has its own vault id, so it is simply not registered for
    // A's. Pointing it at A's vault is what the relay must refuse.
    assert!(matches!(
        syncer.push(&mut stranger),
        Err(Error::Refused { .. })
    ));
}

#[test]
fn claiming_a_vault_twice_is_reported() {
    let url = spawn_relay();
    let dir = TempDir::new().unwrap();
    let (a, _) = Vault::create(dir.path().join("a.db"), PASSWORD, FAST).unwrap();

    let syncer = Syncer::new(HttpTransport::new(&url));
    syncer.claim(&a).unwrap();
    assert!(matches!(syncer.claim(&a), Err(Error::AlreadyClaimed)));
}

#[test]
fn an_unreachable_relay_is_reported_as_such() {
    let dir = TempDir::new().unwrap();
    let (mut a, _) = Vault::create(dir.path().join("a.db"), PASSWORD, FAST).unwrap();
    a.create_item(&item("GitHub", "x").0, &item("GitHub", "x").1)
        .unwrap();

    // Port 1 on loopback: nothing listens, and connecting fails fast.
    let syncer = Syncer::new(HttpTransport::new("http://127.0.0.1:1"));
    assert!(matches!(syncer.push(&mut a), Err(Error::Unreachable(_))));
}

// --- a misbehaving relay ---

/// Returns whatever it was told to, so the client can be tested against
/// responses a real relay would not produce on demand.
struct FakeRelay {
    replies: Mutex<Vec<(u16, Vec<u8>)>>,
}

impl FakeRelay {
    fn new(replies: Vec<(u16, Vec<u8>)>) -> Self {
        Self {
            replies: Mutex::new(replies),
        }
    }
}

impl Transport for FakeRelay {
    fn send(
        &self,
        _method: &str,
        _path: &str,
        _headers: &[(&str, String)],
        _body: &[u8],
    ) -> mortise_sync::Result<(u16, Vec<u8>)> {
        let mut replies = self.replies.lock().unwrap();
        Ok(if replies.is_empty() {
            (200, b"{}".to_vec())
        } else {
            replies.remove(0)
        })
    }
}

fn solo_vault(dir: &TempDir, name: &str) -> Vault {
    Vault::create(dir.path().join(name), PASSWORD, FAST)
        .unwrap()
        .0
}

#[test]
fn an_unparseable_response_is_not_retried_forever() {
    let dir = TempDir::new().unwrap();
    let mut vault = solo_vault(&dir, "v.db");
    vault
        .create_item(&item("GitHub", "x").0, &item("GitHub", "x").1)
        .unwrap();

    let syncer = Syncer::new(FakeRelay::new(vec![(200, b"not json at all".to_vec())]));
    assert!(matches!(syncer.push(&mut vault), Err(Error::BadResponse)));
}

/// A push that is not acknowledged must stay in the outbox. Marking it pushed
/// before the relay confirms would silently lose the change.
#[test]
fn a_refused_push_leaves_the_outbox_intact() {
    let dir = TempDir::new().unwrap();
    let mut vault = solo_vault(&dir, "v.db");
    vault
        .create_item(&item("GitHub", "x").0, &item("GitHub", "x").1)
        .unwrap();
    let before = vault.unpushed_changes(100).unwrap().len();

    let syncer = Syncer::new(FakeRelay::new(vec![(
        500,
        br#"{"code":"storage","message":"nope"}"#.to_vec(),
    )]));
    assert!(syncer.push(&mut vault).is_err());

    assert_eq!(
        vault.unpushed_changes(100).unwrap().len(),
        before,
        "a failed push must not mark changes as sent"
    );
}

/// A relay that mangles a change must not get it ingested, and must not crash
/// the client either.
#[test]
fn malformed_changes_from_the_relay_are_dropped() {
    let dir = TempDir::new().unwrap();
    let mut vault = solo_vault(&dir, "v.db");

    let nonsense = WireChange {
        id: "not hex".into(),
        epoch: 0,
        hlc_wall: 1,
        hlc_counter: 0,
        author: "zz".into(),
        parents: vec!["also not hex".into()],
        payload: "!!!not base64!!!".into(),
        signature: "short".into(),
    };
    let body = serde_json::to_vec(&PullResponse {
        changes: vec![nonsense],
        cursor: 1,
        more: false,
    })
    .unwrap();

    let syncer = Syncer::new(FakeRelay::new(vec![(200, body)]));
    let outcome = syncer.pull(&mut vault).unwrap();

    assert_eq!(outcome.pulled, 0);
    assert_eq!(outcome.rejected, 1);
    assert_eq!(vault.item_count().unwrap(), 0);
}

/// A relay replaying an old cursor must not be able to rewind this device, or
/// it could make it re-pull the same changes indefinitely.
#[test]
fn the_cursor_never_moves_backwards() {
    let dir = TempDir::new().unwrap();
    let vault = solo_vault(&dir, "v.db");

    vault.set_sync_cursor(50).unwrap();
    assert_eq!(vault.sync_cursor().unwrap(), 50);

    vault.set_sync_cursor(10).unwrap();
    assert_eq!(vault.sync_cursor().unwrap(), 50, "the cursor was rewound");

    vault.set_sync_cursor(60).unwrap();
    assert_eq!(vault.sync_cursor().unwrap(), 60);
}

#[test]
fn the_relay_url_round_trips_and_can_be_cleared() {
    let dir = TempDir::new().unwrap();
    let vault = solo_vault(&dir, "v.db");

    assert_eq!(vault.relay_url().unwrap(), None);
    vault.set_relay_url(Some("https://relay.example")).unwrap();
    assert_eq!(
        vault.relay_url().unwrap().as_deref(),
        Some("https://relay.example")
    );

    vault.set_relay_url(None).unwrap();
    assert_eq!(vault.relay_url().unwrap(), None);
}

#[test]
fn a_trailing_slash_on_the_relay_url_is_normalized() {
    // A doubled slash would produce a path that no longer matches what was
    // signed, so every request would fail authentication.
    assert_eq!(
        HttpTransport::new("http://relay.example/").base_url(),
        "http://relay.example"
    );
    assert_eq!(
        HttpTransport::new("http://relay.example///").base_url(),
        "http://relay.example"
    );
}
