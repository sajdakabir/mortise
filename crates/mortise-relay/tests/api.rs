//! Relay API tests, driven through the router directly — no sockets, no ports.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use mortise_crypto::identity::Device;
use mortise_relay::auth::{hex, sign};
use mortise_relay::protocol::{
    AddDevice, ClaimVault, HEADER_DEVICE, HEADER_SIGNATURE, HEADER_TIMESTAMP, PushRequest,
    WireChange,
};
use mortise_relay::server::router;
use mortise_relay::store::Store;
use serde_json::Value;
use tower::ServiceExt;

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64
}

struct Client {
    device: Device,
}

impl Client {
    fn new() -> Self {
        Self {
            device: Device::generate().unwrap(),
        }
    }

    fn device_id(&self) -> String {
        hex(self.device.id().as_bytes())
    }

    fn signing_key(&self) -> String {
        hex(self.device.public().signing_public())
    }

    /// Build a correctly signed request.
    fn request(&self, method: &str, path: &str, body: &[u8]) -> Request<Body> {
        self.request_at(method, path, body, now_ms())
    }

    fn request_at(&self, method: &str, path: &str, body: &[u8], ts: i64) -> Request<Body> {
        let signature = sign(&self.device, method, path, ts, body);
        Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json")
            .header(HEADER_DEVICE, self.device_id())
            .header(HEADER_TIMESTAMP, ts.to_string())
            .header(HEADER_SIGNATURE, signature)
            .body(Body::from(body.to_vec()))
            .unwrap()
    }
}

async fn send(store: &Store, request: Request<Body>) -> (StatusCode, Value) {
    let response = router(store.clone()).oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

const VAULT: &str = "0102030405060708090a0b0c0d0e0f10";

async fn claimed() -> (Store, Client) {
    let store = Store::open(":memory:").unwrap();
    let client = Client::new();

    let body = serde_json::to_vec(&ClaimVault {
        vault_id: VAULT.into(),
        device_signing_key: client.signing_key(),
    })
    .unwrap();

    let (status, _) = send(&store, client.request("POST", "/v1/vaults", &body)).await;
    assert_eq!(status, StatusCode::CREATED);
    (store, client)
}

fn change(id: &str) -> WireChange {
    WireChange {
        id: id.into(),
        epoch: 0,
        hlc_wall: 1_759_000_000_000,
        hlc_counter: 0,
        author: "aa".repeat(8),
        parents: vec![],
        payload: "c2VhbGVkIGJ5dGVz".into(),
        signature: "bb".repeat(32),
    }
}

async fn push(store: &Store, client: &Client, changes: Vec<WireChange>) -> (StatusCode, Value) {
    let body = serde_json::to_vec(&PushRequest { changes }).unwrap();
    let path = format!("/v1/vaults/{VAULT}/changes");
    send(store, client.request("POST", &path, &body)).await
}

// --- claiming ---

#[tokio::test]
async fn health_needs_no_auth() {
    let store = Store::open(":memory:").unwrap();
    let request = Request::builder()
        .uri("/v1/health")
        .body(Body::empty())
        .unwrap();
    let response = router(store).oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_vault_can_be_claimed_once() {
    let (store, client) = claimed().await;

    let body = serde_json::to_vec(&ClaimVault {
        vault_id: VAULT.into(),
        device_signing_key: client.signing_key(),
    })
    .unwrap();
    let (status, _) = send(&store, client.request("POST", "/v1/vaults", &body)).await;
    assert_eq!(status, StatusCode::CONFLICT);
}

/// A claim is self-authenticating: the signature must match the key in the
/// body. Otherwise anyone could register a vault under someone else's key.
#[tokio::test]
async fn a_claim_signed_by_a_different_device_is_refused() {
    let store = Store::open(":memory:").unwrap();
    let honest = Client::new();
    let attacker = Client::new();

    let body = serde_json::to_vec(&ClaimVault {
        vault_id: VAULT.into(),
        device_signing_key: honest.signing_key(),
    })
    .unwrap();

    let (status, _) = send(&store, attacker.request("POST", "/v1/vaults", &body)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// --- push and pull ---

#[tokio::test]
async fn changes_round_trip() {
    let (store, client) = claimed().await;

    let (status, body) = push(&store, &client, vec![change("aa"), change("bb")]).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["accepted"], 2);
    assert_eq!(body["duplicates"], 0);

    let path = format!("/v1/vaults/{VAULT}/changes?after=0");
    let (status, body) = send(&store, client.request("GET", &path, b"")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["changes"].as_array().unwrap().len(), 2);
    assert_eq!(body["more"], false);
}

#[tokio::test]
async fn pushing_the_same_change_twice_is_a_duplicate() {
    let (store, client) = claimed().await;

    push(&store, &client, vec![change("aa")]).await;
    let (_, body) = push(&store, &client, vec![change("aa")]).await;

    assert_eq!(body["accepted"], 0);
    assert_eq!(body["duplicates"], 1);
}

#[tokio::test]
async fn pulling_from_a_cursor_returns_only_newer_changes() {
    let (store, client) = claimed().await;
    push(&store, &client, vec![change("aa")]).await;

    let path = format!("/v1/vaults/{VAULT}/changes?after=0");
    let (_, first) = send(&store, client.request("GET", &path, b"")).await;
    let cursor = first["cursor"].as_u64().unwrap();
    assert_eq!(first["changes"].as_array().unwrap().len(), 1);

    push(&store, &client, vec![change("bb")]).await;

    let path = format!("/v1/vaults/{VAULT}/changes?after={cursor}");
    let (_, second) = send(&store, client.request("GET", &path, b"")).await;
    let changes = second["changes"].as_array().unwrap();
    assert_eq!(
        changes.len(),
        1,
        "the cursor should skip what we already had"
    );
    assert_eq!(changes[0]["id"], "bb");
}

#[tokio::test]
async fn a_push_beyond_the_limit_is_refused() {
    let (store, client) = claimed().await;
    let many: Vec<WireChange> = (0..501).map(|i| change(&format!("{i:04x}"))).collect();

    let (status, _) = push(&store, &client, many).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

// --- what the relay refuses ---

#[tokio::test]
async fn an_unregistered_device_is_refused() {
    let (store, _) = claimed().await;
    let stranger = Client::new();

    let (status, _) = push(&store, &stranger, vec![change("aa")]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn an_unsigned_request_is_refused() {
    let (store, _) = claimed().await;
    let path = format!("/v1/vaults/{VAULT}/changes?after=0");
    let request = Request::builder().uri(&path).body(Body::empty()).unwrap();

    let (status, _) = send(&store, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// The signature covers a hash of the body, so a relay-side attacker who
/// rewrites a push cannot keep the signature valid.
#[tokio::test]
async fn a_tampered_body_is_refused() {
    let (store, client) = claimed().await;

    let body = serde_json::to_vec(&PushRequest {
        changes: vec![change("aa")],
    })
    .unwrap();
    let path = format!("/v1/vaults/{VAULT}/changes");
    let signature = sign(&client.device, "POST", &path, now_ms(), &body);

    let altered = serde_json::to_vec(&PushRequest {
        changes: vec![change("ff")],
    })
    .unwrap();

    let request = Request::builder()
        .method("POST")
        .uri(&path)
        .header(HEADER_DEVICE, client.device_id())
        .header(HEADER_TIMESTAMP, now_ms().to_string())
        .header(HEADER_SIGNATURE, signature)
        .body(Body::from(altered))
        .unwrap();

    let (status, _) = send(&store, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// The path is signed too, so a captured request cannot be aimed somewhere
/// else — including at a different cursor.
#[tokio::test]
async fn a_signature_does_not_transfer_to_another_path() {
    let (store, client) = claimed().await;
    push(&store, &client, vec![change("aa"), change("bb")]).await;

    let signed_path = format!("/v1/vaults/{VAULT}/changes?after=0");
    let signature = sign(&client.device, "GET", &signed_path, now_ms(), b"");

    let other_path = format!("/v1/vaults/{VAULT}/changes?after=1");
    let request = Request::builder()
        .uri(&other_path)
        .header(HEADER_DEVICE, client.device_id())
        .header(HEADER_TIMESTAMP, now_ms().to_string())
        .header(HEADER_SIGNATURE, signature)
        .body(Body::empty())
        .unwrap();

    let (status, _) = send(&store, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_stale_request_is_refused() {
    let (store, client) = claimed().await;
    let body = serde_json::to_vec(&PushRequest {
        changes: vec![change("aa")],
    })
    .unwrap();
    let path = format!("/v1/vaults/{VAULT}/changes");

    for offset in [-10 * 60 * 1000i64, 10 * 60 * 1000] {
        let request = client.request_at("POST", &path, &body, now_ms() + offset);
        let (status, _) = send(&store, request).await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "offset {offset}ms accepted"
        );
    }
}

/// A member signing as themselves must not be able to claim another device id.
#[tokio::test]
async fn a_device_id_that_does_not_match_its_key_is_refused() {
    let (store, client) = claimed().await;
    let body = serde_json::to_vec(&PushRequest {
        changes: vec![change("aa")],
    })
    .unwrap();
    let path = format!("/v1/vaults/{VAULT}/changes");
    let ts = now_ms();
    let signature = sign(&client.device, "POST", &path, ts, &body);

    let request = Request::builder()
        .method("POST")
        .uri(&path)
        .header(HEADER_DEVICE, "ff".repeat(16)) // not this key's id
        .header(HEADER_TIMESTAMP, ts.to_string())
        .header(HEADER_SIGNATURE, signature)
        .body(Body::from(body))
        .unwrap();

    let (status, _) = send(&store, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// Vaults are isolated: a device registered for one must not reach another.
#[tokio::test]
async fn a_device_cannot_reach_another_vault() {
    let (store, client) = claimed().await;
    let other = Client::new();

    let body = serde_json::to_vec(&ClaimVault {
        vault_id: "ff".repeat(16),
        device_signing_key: other.signing_key(),
    })
    .unwrap();
    send(&store, other.request("POST", "/v1/vaults", &body)).await;

    let path = format!("/v1/vaults/{}/changes?after=0", "ff".repeat(16));
    let (status, _) = send(&store, client.request("GET", &path, b"")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// --- adding devices ---

#[tokio::test]
async fn an_added_device_can_sync() {
    let (store, first) = claimed().await;
    let second = Client::new();

    let path = format!("/v1/vaults/{VAULT}/devices");
    let body = serde_json::to_vec(&AddDevice {
        device_id: second.device_id(),
        device_signing_key: second.signing_key(),
    })
    .unwrap();

    let (status, _) = send(&store, first.request("POST", &path, &body)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (status, _) = push(&store, &second, vec![change("aa")]).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn a_stranger_cannot_add_a_device() {
    let (store, _) = claimed().await;
    let stranger = Client::new();
    let accomplice = Client::new();

    let path = format!("/v1/vaults/{VAULT}/devices");
    let body = serde_json::to_vec(&AddDevice {
        device_id: accomplice.device_id(),
        device_signing_key: accomplice.signing_key(),
    })
    .unwrap();

    let (status, _) = send(&store, stranger.request("POST", &path, &body)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
