//! HTTP surface.
//!
//! All but one endpoint is authenticated by device signature:
//!
//! | Route | Purpose |
//! |---|---|
//! | `POST /v1/vaults` | claim a vault id, registering the first device |
//! | `POST /v1/vaults/{id}/devices` | authorize another device |
//! | `POST /v1/vaults/{id}/changes` | push |
//! | `GET  /v1/vaults/{id}/changes` | pull |
//! | `POST /v1/vaults/{id}/acl` | push ACL entries |
//! | `GET  /v1/vaults/{id}/acl` | pull ACL entries |
//! | `POST /v1/vaults/{id}/keys` | push vault keys sealed to other devices |
//! | `GET  /v1/vaults/{id}/keys` | pull the keys sealed to the caller |
//!
//! The last four carry membership and the keys that enforce it, and the relay
//! can read none of it. It cannot tell an owner from a viewer, because roles
//! live in the encrypted entries, so it only checks that *some* device of this
//! vault is calling. Authority is decided by clients when they replay the log.

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;

use crate::auth::{self, SignedRequest};
use crate::protocol::{
    AclPullResponse, AclPushRequest, AddDevice, ClaimVault, ErrorBody, KeyPullResponse,
    KeyPushRequest, PullResponse, PushRequest, PushResponse, StoreCounts, HEADER_DEVICE,
    HEADER_SIGNATURE, HEADER_TIMESTAMP,
};
use crate::store::Store;

/// Largest request body accepted.
///
/// A push of a few hundred changes is well inside this. The cap exists so one
/// client cannot make the relay buffer something enormous.
pub const MAX_BODY: usize = 8 * 1024 * 1024;

/// Most changes returned by a single pull.
pub const PULL_LIMIT: u32 = 500;

/// Most changes accepted in a single push.
pub const PUSH_LIMIT: usize = 500;

/// Most ACL entries returned by a single pull, and accepted in a single push.
///
/// Smaller than the change limits because an ACL log grows with membership
/// edits rather than with use: a vault whose ACL runs past a few hundred
/// entries is remarkable, and a client that needs a second page gets one.
pub const ACL_LIMIT: u32 = 200;

/// Most wrapped keys accepted in a single push.
///
/// One per remaining member device per rotation, so this is a bound on team
/// size rather than on activity.
pub const KEY_PUSH_LIMIT: usize = 200;

/// Build the router.
pub fn router(store: Store) -> Router {
    Router::new()
        .route("/v1/health", get(|| async { "ok" }))
        .route("/v1/vaults", post(claim))
        .route("/v1/vaults/{vault_id}/devices", post(add_device))
        .route("/v1/vaults/{vault_id}/changes", post(push).get(pull))
        .route("/v1/vaults/{vault_id}/acl", post(push_acl).get(pull_acl))
        .route("/v1/vaults/{vault_id}/keys", post(push_keys).get(pull_keys))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_BODY))
        .with_state(store)
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn fail(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(ErrorBody {
            code: code.to_string(),
            message: message.to_string(),
        }),
    )
        .into_response()
}

/// Pull the signing headers out of a request.
fn signed<'a>(
    headers: &'a HeaderMap,
    method: &'a str,
    path: &'a str,
    body: &'a [u8],
) -> Option<SignedRequest<'a>> {
    Some(SignedRequest {
        method,
        path,
        device_id: headers.get(HEADER_DEVICE)?.to_str().ok()?,
        timestamp_ms: headers.get(HEADER_TIMESTAMP)?.to_str().ok()?.parse().ok()?,
        signature: headers.get(HEADER_SIGNATURE)?.to_str().ok()?,
        body,
    })
}

/// Verify that the caller is a device registered for this vault.
///
/// The error is boxed because an axum `Response` is large, and an unboxed one
/// in every handler's `Result` bloats each future for a path that is almost
/// never taken.
fn authorize(
    store: &Store,
    vault_id: &str,
    headers: &HeaderMap,
    method: &str,
    path: &str,
    body: &[u8],
) -> Result<String, Box<Response>> {
    let request = signed(headers, method, path, body).ok_or_else(|| {
        Box::new(fail(
            StatusCode::UNAUTHORIZED,
            "malformed_auth",
            "Missing or malformed authentication headers.",
        ))
    })?;

    let key = store
        .signing_key(vault_id, request.device_id)
        .map_err(|_| {
            fail(
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage",
                "Storage error.",
            )
        })?
        // Deliberately the same response as a bad signature. Distinguishing
        // "no such device" from "wrong signature" would let anyone probe which
        // devices sync a vault.
        .ok_or_else(|| {
            fail(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "Not authorized for this vault.",
            )
        })?;

    auth::verify(&request, &key, now_ms()).map_err(|_| {
        Box::new(fail(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Not authorized for this vault.",
        ))
    })?;

    Ok(request.device_id.to_string())
}

/// Claim a vault id and register the first device.
///
/// Self-authenticating: the signature is checked against the key in the body,
/// which proves possession of that key. Vault ids are 128-bit random, so
/// squatting an id someone else would later pick is not a practical concern.
async fn claim(State(store): State<Store>, headers: HeaderMap, body: Bytes) -> Response {
    let Ok(payload) = serde_json::from_slice::<ClaimVault>(&body) else {
        return fail(StatusCode::BAD_REQUEST, "bad_request", "Malformed body.");
    };
    let Some(request) = signed(&headers, "POST", "/v1/vaults", &body) else {
        return fail(
            StatusCode::UNAUTHORIZED,
            "malformed_auth",
            "Missing or malformed authentication headers.",
        );
    };

    if auth::verify(&request, &payload.device_signing_key, now_ms()).is_err() {
        return fail(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Signature does not match the supplied device key.",
        );
    }

    match store.claim(
        &payload.vault_id,
        request.device_id,
        &payload.device_signing_key,
        now_ms(),
    ) {
        Ok(true) => (
            StatusCode::CREATED,
            Json(serde_json::json!({"claimed": true})),
        )
            .into_response(),
        Ok(false) => fail(
            StatusCode::CONFLICT,
            "already_claimed",
            "That vault id is already registered.",
        ),
        Err(_) => fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage",
            "Storage error.",
        ),
    }
}

/// Authorize another device to sync this vault.
///
/// Any already-registered device may do this. The relay has no way to tell an
/// owner from a member — roles live in the encrypted ACL it cannot read — so
/// the real authority check happens on the clients, which reject ACL entries
/// from devices without the right role.
async fn add_device(
    State(store): State<Store>,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = format!("/v1/vaults/{vault_id}/devices");
    if let Err(response) = authorize(&store, &vault_id, &headers, "POST", &path, &body) {
        return *response;
    }

    let Ok(payload) = serde_json::from_slice::<AddDevice>(&body) else {
        return fail(StatusCode::BAD_REQUEST, "bad_request", "Malformed body.");
    };

    match store.add_device(
        &vault_id,
        &payload.device_id,
        &payload.device_signing_key,
        now_ms(),
    ) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage",
            "Storage error.",
        ),
    }
}

async fn push(
    State(store): State<Store>,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = format!("/v1/vaults/{vault_id}/changes");
    if let Err(response) = authorize(&store, &vault_id, &headers, "POST", &path, &body) {
        return *response;
    }

    let Ok(payload) = serde_json::from_slice::<PushRequest>(&body) else {
        return fail(StatusCode::BAD_REQUEST, "bad_request", "Malformed body.");
    };
    if payload.changes.len() > PUSH_LIMIT {
        return fail(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_many_changes",
            "Send at most 500 changes per request.",
        );
    }

    match store.push(&vault_id, &payload.changes, now_ms()) {
        Ok((report, cursor)) => Json(PushResponse {
            accepted: report.accepted,
            duplicates: report.duplicates,
            cursor,
        })
        .into_response(),
        Err(_) => fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage",
            "Storage error.",
        ),
    }
}

#[derive(Debug, Deserialize)]
struct PullParams {
    #[serde(default)]
    after: u64,
}

async fn pull(
    State(store): State<Store>,
    Path(vault_id): Path<String>,
    Query(params): Query<PullParams>,
    headers: HeaderMap,
) -> Response {
    // The signed path includes the query string, so a captured pull cannot be
    // replayed with a different cursor.
    let path = format!("/v1/vaults/{vault_id}/changes?after={}", params.after);
    if let Err(response) = authorize(&store, &vault_id, &headers, "GET", &path, b"") {
        return *response;
    }

    match store.pull(&vault_id, params.after, PULL_LIMIT) {
        Ok((changes, cursor, more)) => Json(PullResponse {
            changes,
            cursor,
            more,
        })
        .into_response(),
        Err(_) => fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage",
            "Storage error.",
        ),
    }
}

async fn push_acl(
    State(store): State<Store>,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = format!("/v1/vaults/{vault_id}/acl");
    if let Err(response) = authorize(&store, &vault_id, &headers, "POST", &path, &body) {
        return *response;
    }

    let Ok(payload) = serde_json::from_slice::<AclPushRequest>(&body) else {
        return fail(StatusCode::BAD_REQUEST, "bad_request", "Malformed body.");
    };
    if payload.entries.len() > ACL_LIMIT as usize {
        return fail(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_many_entries",
            "Send at most 200 acl entries per request.",
        );
    }

    match store.push_acl(&vault_id, &payload.entries, now_ms()) {
        Ok(report) => Json(StoreCounts {
            accepted: report.accepted,
            duplicates: report.duplicates,
        })
        .into_response(),
        Err(_) => fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage",
            "Storage error.",
        ),
    }
}

async fn pull_acl(
    State(store): State<Store>,
    Path(vault_id): Path<String>,
    Query(params): Query<PullParams>,
    headers: HeaderMap,
) -> Response {
    let path = format!("/v1/vaults/{vault_id}/acl?after={}", params.after);
    if let Err(response) = authorize(&store, &vault_id, &headers, "GET", &path, b"") {
        return *response;
    }

    match store.pull_acl(&vault_id, params.after, ACL_LIMIT) {
        Ok((entries, more)) => Json(AclPullResponse { entries, more }).into_response(),
        Err(_) => fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage",
            "Storage error.",
        ),
    }
}

async fn push_keys(
    State(store): State<Store>,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = format!("/v1/vaults/{vault_id}/keys");
    if let Err(response) = authorize(&store, &vault_id, &headers, "POST", &path, &body) {
        return *response;
    }

    let Ok(payload) = serde_json::from_slice::<KeyPushRequest>(&body) else {
        return fail(StatusCode::BAD_REQUEST, "bad_request", "Malformed body.");
    };
    if payload.keys.len() > KEY_PUSH_LIMIT {
        return fail(
            StatusCode::PAYLOAD_TOO_LARGE,
            "too_many_keys",
            "Send at most 200 wrapped keys per request.",
        );
    }

    match store.push_keys(&vault_id, &payload.keys, now_ms()) {
        Ok(report) => Json(StoreCounts {
            accepted: report.accepted,
            duplicates: report.duplicates,
        })
        .into_response(),
        Err(_) => fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage",
            "Storage error.",
        ),
    }
}

/// Hand back the keys sealed to the calling device.
///
/// The recipient is the authenticated device id, not a parameter, so one member
/// cannot ask for another's copies. They would be useless to them — each is
/// sealed to a device key they do not hold — but there is no reason to let the
/// relay or a member enumerate who has collected what.
async fn pull_keys(
    State(store): State<Store>,
    Path(vault_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let path = format!("/v1/vaults/{vault_id}/keys");
    let device = match authorize(&store, &vault_id, &headers, "GET", &path, b"") {
        Ok(device) => device,
        Err(response) => return *response,
    };

    match store.keys_for(&vault_id, &device) {
        Ok(keys) => Json(KeyPullResponse { keys }).into_response(),
        Err(_) => fail(
            StatusCode::INTERNAL_SERVER_ERROR,
            "storage",
            "Storage error.",
        ),
    }
}
