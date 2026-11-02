use crate::{Error, Result, protocol::*, store::Store};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{OriginalUri, State},
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{any, get},
};
use serde::de::DeserializeOwned;
use std::{path::PathBuf, sync::Arc};

#[derive(Clone)]
pub struct Service {
    pub store: Store,
    pub auth: AuthConfig,
}

impl IntoResponse for Error {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Untrusted => (StatusCode::FORBIDDEN, "untrusted_device"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::Invalid(_) => (StatusCode::BAD_REQUEST, "invalid"),
            Self::Conflict(_) => (StatusCode::CONFLICT, "conflict"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
            Self::Storage => (StatusCode::INTERNAL_SERVER_ERROR, "storage"),
        };
        (
            status,
            Json(serde_json::json!({"code":code,"message":self.to_string()})),
        )
            .into_response()
    }
}

pub fn router(service: Service) -> Router {
    Router::new()
        .route("/health",get(||async{"ok"}))
        .route("/v1/auth/config",get(|State(s):State<Arc<Service>>|async move{Json(s.auth.clone())}))
        .route("/v1/{*path}",any(api))
        .route("/join",get(||async{axum::response::Html(include_str!("join.html"))}))
        .route("/join.js",get(||async{([("content-type","text/javascript")],include_str!("join.js"))}))
        .layer(axum::extract::DefaultBodyLimit::max(32*1024))
        .layer(axum::middleware::map_response(|mut response:Response|async move{
            response.headers_mut().insert("cache-control","no-store".parse().unwrap());
            response.headers_mut().insert("referrer-policy","no-referrer".parse().unwrap());
            response.headers_mut().insert("x-content-type-options","nosniff".parse().unwrap());
            response.headers_mut().insert("content-security-policy","default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'".parse().unwrap());
            response
        }))
        .with_state(Arc::new(service))
}
fn parse<T: DeserializeOwned>(body: &[u8]) -> Result<T> {
    serde_json::from_slice(body).map_err(|_| Error::Invalid("Malformed request."))
}
fn json<T: serde::Serialize>(value: T) -> Result<Response> {
    Ok(Json(value).into_response())
}
fn proof(headers: &HeaderMap) -> Result<Proof> {
    let value = headers
        .get("x-mortise-proof")
        .ok_or(Error::Unauthorized)?
        .to_str()
        .map_err(|_| Error::Unauthorized)?;
    if value.len() > 2048 {
        return Err(Error::Unauthorized);
    }
    parse(value.as_bytes()).map_err(|_| Error::Unauthorized)
}
async fn api(
    State(service): State<Arc<Service>>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if uri.query().is_some() {
        return Error::Invalid("Query parameters are not accepted.").into_response();
    }
    // OIDC and SQLite use bounded blocking IO off the async request executor.
    match tokio::task::spawn_blocking(move || {
        dispatch(&service, method.as_str(), uri.path(), &headers, &body)
    })
    .await
    {
        Ok(Ok(response)) => response,
        Ok(Err(error)) => error.into_response(),
        Err(_) => Error::Unavailable.into_response(),
    }
}
fn dispatch(
    s: &Service,
    method: &str,
    path: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Response> {
    let now = now();
    let proof = proof(headers)?;
    if method == "POST" && path == "/v1/auth/start" {
        return json(s.store.start_login(&parse(body)?, &proof, body, now)?);
    }
    if method == "POST" && path == "/v1/auth/finish" {
        let input: LoginFinish = parse(body)?;
        let nonce = s.store.login_nonce(&input.id, &proof, body, now)?;
        let metadata = crate::oidc::discover(&s.auth)?;
        let identity = crate::oidc::verify(&s.auth, metadata, &input.id_token, &nonce)?;
        return json(s.store.finish_login(
            &input.id,
            &identity,
            &proof,
            body,
            crate::protocol::now(),
        )?);
    }
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(Error::Unauthorized)?;
    let actor = s
        .store
        .authenticate(token, &proof, method, path, body, now)?;
    let p: Vec<_> = path.trim_start_matches('/').split('/').collect();
    match (method, p.as_slice()) {
        ("GET", ["v1", "me"]) => json(s.store.dashboard(&actor)?),
        ("POST", ["v1", "logout"]) => {
            s.store.logout(token)?;
            json(())
        }
        ("POST", ["v1", "devices", id, "approve"]) => {
            let input: ApproveDevice = parse(body)?;
            s.store.approve_device(&actor, id, &input.certificate)?;
            json(())
        }
        ("POST", ["v1", "devices", id, "revoke"]) => {
            s.store.revoke_device(&actor, id)?;
            json(())
        }
        ("POST", ["v1", "teams"]) => {
            let input: Named = parse(body)?;
            json(s.store.create_team(&actor, &input.name, now)?)
        }
        ("GET", ["v1", "teams", id, "members"]) => json(s.store.members(&actor, id)?),
        ("POST", ["v1", "teams", id, "members", member, "remove"]) => {
            s.store.remove_member(&actor, id, member)?;
            json(())
        }
        ("POST", ["v1", "teams", id, "invitations"]) => {
            json(s.store.invite(&actor, id, &parse(body)?, now)?)
        }
        ("GET", ["v1", "teams", id, "requests"]) => json(s.store.requests(&actor, id, now)?),
        ("POST", ["v1", "teams", id, "requests", invite, "decide"]) => {
            s.store.decide(&actor, id, invite, &parse(body)?, now)?;
            json(())
        }
        ("POST", ["v1", "teams", id, "invitations", invite, "revoke"]) => {
            s.store.revoke_invite(&actor, id, invite)?;
            json(())
        }
        ("POST", ["v1", "invitations", "preview"]) => {
            let input: InviteToken = parse(body)?;
            json(s.store.preview(&actor, &input.token, now)?)
        }
        ("POST", ["v1", "invitations", "request"]) => {
            let input: InviteToken = parse(body)?;
            s.store.request_invite(&actor, &input.token, now)?;
            json(())
        }
        _ => Err(Error::Invalid("Unknown account operation.")),
    }
}

pub async fn run() -> std::result::Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "postgres")]
    if std::env::args().nth(1).as_deref() == Some("--migrate") {
        let url = std::env::var("DATABASE_URL_UNPOOLED")?;
        tokio::task::spawn_blocking(move || Store::migrate_postgres(&url)).await??;
        println!("Account metadata migrations applied (schema version 1).");
        return Ok(());
    }
    let auth = AuthConfig {
        issuer: std::env::var("MORTISE_OIDC_ISSUER")
            .or_else(|_| std::env::var("NEON_AUTH_BASE_URL"))?,
        client_id: std::env::var("MORTISE_OIDC_CLIENT_ID")?,
        callback_port: std::env::var("MORTISE_OIDC_CALLBACK_PORT")
            .ok()
            .map(|p| p.parse())
            .transpose()?,
        resource: std::env::var("MORTISE_OIDC_RESOURCE").ok(),
    };
    service_url(&auth.issuer)?;
    let db = PathBuf::from(
        std::env::var("MORTISE_ACCOUNTS_DB").unwrap_or_else(|_| "accounts.sqlite".into()),
    );
    let bind = std::env::var("MORTISE_ACCOUNTS_BIND").unwrap_or_else(|_| "127.0.0.1:8788".into());
    #[cfg(feature = "postgres")]
    let store = if let Ok(url) = std::env::var("DATABASE_URL") {
        tokio::task::spawn_blocking(move || Store::postgres(&url)).await??
    } else {
        Store::open(&db)?
    };
    #[cfg(not(feature = "postgres"))]
    let store = {
        if std::env::var_os("DATABASE_URL").is_some() {
            return Err(
                Error::Invalid("Build with --features postgres to use DATABASE_URL.").into(),
            );
        }
        Store::open(&db)?
    };
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    eprintln!("mortise-accounts listening on {}", listener.local_addr()?);
    axum::serve(listener, router(Service { store, auth }))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
