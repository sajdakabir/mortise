//! HTTP surface.
//!
//! Four endpoints, all but one authenticated by device signature:
//!
//! | Route | Purpose |
//! |---|---|
//! | `POST /v1/vaults` | claim a vault id, registering the first device |
//! | `POST /v1/vaults/{id}/devices` | authorize another device |
//! | `POST /v1/vaults/{id}/changes` | push |
//! | `GET  /v1/vaults/{id}/changes` | pull |

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;

use crate::auth::{self, SignedRequest};
use crate::protocol::{
    AddDevice, ClaimVault, ErrorBody, HEADER_DEVICE, HEADER_SIGNATURE, HEADER_TIMESTAMP,
    PullResponse, PushRequest, PushResponse,
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

/// Build the router.
pub fn router(store: Store) -> Router {
    Router::new()
        .route("/v1/health", get(|| async { "ok" }))
        .route("/v1/vaults", post(claim))
        .route("/v1/vaults/{vault_id}/devices", post(add_device))
        .route("/v1/vaults/{vault_id}/changes", post(push).get(pull))
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
