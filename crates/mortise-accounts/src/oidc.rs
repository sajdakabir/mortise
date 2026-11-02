//! OIDC verification using a maintained protocol implementation. Neither the
//! provider password nor the vault master password reaches this service.
use crate::{
    Error, Result,
    protocol::{AuthConfig, service_url},
};
#[cfg(feature = "server")]
use openidconnect::{
    ClientId, Nonce,
    core::{CoreClient, CoreIdToken},
};
use openidconnect::{IssuerUrl, core::CoreProviderMetadata};
#[cfg(feature = "server")]
use std::str::FromStr;
use std::time::Duration;

/// Bounded transport without redirects, shared by discovery and token exchange.
pub fn http(request: openidconnect::HttpRequest) -> Result<openidconnect::HttpResponse> {
    let uri = request.uri().to_string();
    service_url(&uri)?;
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(15)))
        .build()
        .into();
    let mut response = match request.method().as_str() {
        "GET" => {
            let mut req = agent.get(&uri);
            for (name, value) in request.headers() {
                req = req.header(name.as_str(), value.as_bytes());
            }
            req.call().map_err(|_| Error::Unavailable)?
        }
        "POST" => {
            let mut req = agent.post(&uri);
            for (name, value) in request.headers() {
                req = req.header(name.as_str(), value.as_bytes());
            }
            req.send(request.body().as_slice())
                .map_err(|_| Error::Unavailable)?
        }
        _ => return Err(Error::Unavailable),
    };
    let mut out = openidconnect::http::Response::builder().status(response.status().as_u16());
    for (name, value) in response.headers() {
        out = out.header(name.as_str(), value.as_bytes());
    }
    let body = response
        .body_mut()
        .with_config()
        .limit(1024 * 1024)
        .read_to_vec()
        .map_err(|_| Error::Unavailable)?;
    out.body(body).map_err(|_| Error::Unavailable)
}

pub fn discover(config: &AuthConfig) -> Result<CoreProviderMetadata> {
    service_url(&config.issuer)?;
    if config.client_id.is_empty() {
        return Err(Error::Invalid("OIDC client ID is required."));
    }
    let metadata = CoreProviderMetadata::discover(
        &IssuerUrl::new(config.issuer.clone()).map_err(|_| Error::Unavailable)?,
        &http,
    )
    .map_err(|_| Error::Unavailable)?;
    service_url(metadata.authorization_endpoint().as_str())?;
    if let Some(endpoint) = metadata.token_endpoint() {
        service_url(endpoint.as_str())?;
    }
    Ok(metadata)
}

#[cfg(feature = "server")]
pub fn verify(
    config: &AuthConfig,
    metadata: CoreProviderMetadata,
    token: &str,
    nonce: &str,
) -> Result<crate::store::Identity> {
    if token.len() > 16_384 {
        return Err(Error::Unauthorized);
    }
    let client =
        CoreClient::from_provider_metadata(metadata, ClientId::new(config.client_id.clone()), None);
    let id = CoreIdToken::from_str(token).map_err(|_| Error::Unauthorized)?;
    let claims = id
        .claims(&client.id_token_verifier(), &Nonce::new(nonce.to_owned()))
        .map_err(|_| Error::Unauthorized)?;
    if claims.email_verified() != Some(true)
        || claims.issue_time().timestamp() > crate::protocol::now() + 60
    {
        return Err(Error::Unauthorized);
    }
    let email = claims
        .email()
        .ok_or(Error::Unauthorized)?
        .as_str()
        .to_string();
    let name = claims
        .name()
        .and_then(|n| n.get(None))
        .map(|n| n.as_str())
        .unwrap_or("Mortise user")
        .to_string();
    Ok(crate::store::Identity {
        issuer: config.issuer.clone(),
        subject: claims.subject().as_str().to_string(),
        email,
        name,
    })
}
