//! OIDC verification using a maintained protocol implementation. Neither the
//! provider password nor the vault master password reaches this service.
use crate::{
    Error, Result,
    protocol::{AuthConfig, service_url},
};
#[cfg(feature = "server")]
use openidconnect::{
    AccessToken, AccessTokenHash, ClientId, Nonce,
    core::{CoreClient, CoreIdToken, CoreUserInfoClaims},
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
    access_token: Option<&str>,
) -> Result<crate::store::Identity> {
    if token.len() > 16_384 {
        return Err(Error::Unauthorized);
    }
    let client =
        CoreClient::from_provider_metadata(metadata, ClientId::new(config.client_id.clone()), None);
    let id = CoreIdToken::from_str(token).map_err(|_| Error::Unauthorized)?;
    let verifier = client.id_token_verifier();
    let claims = id
        .claims(&verifier, &Nonce::new(nonce.to_owned()))
        .map_err(|_| Error::Unauthorized)?;
    if claims.issue_time().timestamp() > crate::protocol::now() + 60
        || claims.email_verified() == Some(false)
    {
        return Err(Error::Unauthorized);
    }
    let access_token = access_token
        .map(|token| {
            if token.is_empty() || token.len() > 16_384 {
                return Err(Error::Unauthorized);
            }
            Ok(AccessToken::new(token.to_owned()))
        })
        .transpose()?;
    // Bind the access token to the signed ID token when the provider supplies
    // at_hash. Do this before sending it to UserInfo; never accept client claims.
    if let (Some(expected), Some(access)) = (claims.access_token_hash(), &access_token) {
        let actual = AccessTokenHash::from_token(
            access,
            id.signing_alg().map_err(|_| Error::Unauthorized)?,
            id.signing_key(&verifier).map_err(|_| Error::Unauthorized)?,
        )
        .map_err(|_| Error::Unauthorized)?;
        if actual != *expected {
            return Err(Error::Unauthorized);
        }
    }
    let (email, name) = if let (Some(email), Some(true)) = (claims.email(), claims.email_verified())
    {
        (
            email.as_str().to_owned(),
            claims
                .name()
                .and_then(|n| n.get(None))
                .map(|n| n.as_str().to_owned()),
        )
    } else {
        // OIDC code-flow providers may deliver profile/email only via UserInfo.
        // Query the discovered provider ourselves and require its subject to
        // match the already verified ID token. Never persist this bearer token.
        let endpoint = client.user_info_url().ok_or(Error::Unauthorized)?;
        service_url(endpoint.as_str())?;
        let info: CoreUserInfoClaims = client
            .user_info(
                access_token.ok_or(Error::Unauthorized)?,
                Some(claims.subject().clone()),
            )
            .map_err(|_| Error::Unauthorized)?
            .request(&http)
            .map_err(|_| Error::Unauthorized)?;
        if info.email_verified() != Some(true) {
            return Err(Error::Unauthorized);
        }
        let email = info.email().ok_or(Error::Unauthorized)?;
        if claims.email().is_some_and(|expected| expected != email) {
            return Err(Error::Unauthorized);
        }
        (
            email.as_str().to_owned(),
            info.name()
                .and_then(|n| n.get(None))
                .map(|n| n.as_str().to_owned()),
        )
    };
    let name = name
        .filter(|n| !n.trim().is_empty())
        .unwrap_or_else(|| "Mortise user".into());
    Ok(crate::store::Identity {
        issuer: config.issuer.clone(),
        subject: claims.subject().as_str().to_string(),
        email,
        name,
    })
}
