use crate::{Error, Result};
use mortise_crypto::identity::{Device, DeviceCert};
use serde::{Deserialize, Serialize};

pub const SESSION_LIFETIME: i64 = 8 * 60 * 60;
pub const LOGIN_LIFETIME: i64 = 10 * 60;
pub const INVITE_LIFETIME: i64 = 7 * 24 * 60 * 60;
pub const CLOCK_SKEW: u64 = 120;

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
pub fn unhex(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(Error::Unauthorized);
    }
    s.as_bytes()
        .chunks(2)
        .map(|c| {
            let t = std::str::from_utf8(c).map_err(|_| Error::Unauthorized)?;
            u8::from_str_radix(t, 16).map_err(|_| Error::Unauthorized)
        })
        .collect()
}
pub fn random() -> Result<String> {
    let secret = mortise_crypto::secret::Key32::random().map_err(|_| Error::Unavailable)?;
    Ok(hex(secret.expose()))
}
pub fn digest(value: &str) -> String {
    hex(blake3::hash(value.as_bytes()).as_bytes())
}
pub fn certificate(value: &str) -> Result<DeviceCert> {
    DeviceCert::from_bytes(&unhex(value)?).map_err(|_| Error::Unauthorized)
}
pub fn device_id(cert: &DeviceCert) -> String {
    hex(cert.device().id().as_bytes())
}

/// Requests are bound to this service, exact body/path, session and one nonce.
pub fn signing_payload(
    method: &str,
    path: &str,
    timestamp: i64,
    nonce: &str,
    token: &str,
    body: &[u8],
) -> [u8; 32] {
    let value = format!(
        "mortise/accounts/v1\n{method}\n{path}\n{timestamp}\n{nonce}\n{}\n{}",
        digest(token),
        hex(blake3::hash(body).as_bytes())
    );
    *blake3::hash(value.as_bytes()).as_bytes()
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub device_id: String,
    pub timestamp: i64,
    pub nonce: String,
    pub signature: String,
}
impl Proof {
    pub fn sign(
        device: &Device,
        method: &str,
        path: &str,
        token: &str,
        body: &[u8],
    ) -> Result<Self> {
        let timestamp = now();
        let nonce = random()?;
        let signature = hex(&device.sign(&signing_payload(
            method, path, timestamp, &nonce, token, body,
        )));
        Ok(Self {
            device_id: hex(device.public().id().as_bytes()),
            timestamp,
            nonce,
            signature,
        })
    }
    pub fn verify(
        &self,
        cert: &DeviceCert,
        method: &str,
        path: &str,
        token: &str,
        body: &[u8],
        now: i64,
    ) -> Result<()> {
        if self.timestamp.abs_diff(now) > CLOCK_SKEW
            || self.nonce.len() != 64
            || !self.nonce.bytes().all(|b| b.is_ascii_hexdigit())
            || self.device_id != device_id(cert)
        {
            return Err(Error::Unauthorized);
        }
        use mortise_crypto::ed25519::{Signature, VerifyingKey};
        let key = VerifyingKey::from_bytes(cert.device().signing_public())
            .map_err(|_| Error::Unauthorized)?;
        let sig: [u8; 64] = unhex(&self.signature)?
            .try_into()
            .map_err(|_| Error::Unauthorized)?;
        key.verify_strict(
            &signing_payload(method, path, self.timestamp, &self.nonce, token, body),
            &Signature::from_bytes(&sig),
        )
        .map_err(|_| Error::Unauthorized)
    }
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AuthConfig {
    pub issuer: String,
    pub client_id: String,
    /// Providers with exact redirect matching use a registered loopback port.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub callback_port: Option<u16>,
    /// OAuth resource indicator, when required by the provider (e.g. Neon).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginStart {
    pub certificate: String,
    pub device_name: String,
}
#[derive(Serialize, Deserialize)]
pub struct LoginChallenge {
    pub id: String,
    pub nonce: String,
    pub expires_at: i64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginFinish {
    pub id: String,
    pub id_token: String,
}
#[derive(Serialize, Deserialize)]
pub struct Session {
    pub token: String,
    pub expires_at: i64,
    pub account: Account,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct Account {
    pub id: String,
    pub email: String,
    pub name: String,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct DeviceInfo {
    pub id: String,
    pub name: String,
    pub certificate: String,
    pub fingerprint: String,
    pub status: String,
    pub created_at: i64,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct Team {
    pub id: String,
    pub name: String,
    pub role: String,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct Member {
    pub account_id: String,
    pub email: String,
    pub name: String,
    pub role: String,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct Dashboard {
    pub account: Account,
    pub current_device_id: String,
    pub devices: Vec<DeviceInfo>,
    pub teams: Vec<Team>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Named {
    pub name: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveDevice {
    pub certificate: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewInvite {
    pub email: Option<String>,
    pub role: String,
}
#[derive(Serialize, Deserialize)]
pub struct Invitation {
    pub id: String,
    pub token: String,
    pub expires_at: i64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InviteToken {
    pub token: String,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct InvitePreview {
    pub team_id: String,
    pub team_name: String,
    pub role: String,
    pub status: String,
    pub expires_at: i64,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct JoinRequest {
    pub id: String,
    pub account_id: String,
    pub email: String,
    pub name: String,
    pub role: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecideInvite {
    pub account_id: String,
    pub approve: bool,
}

pub fn service_url(value: &str) -> Result<url::Url> {
    let url = url::Url::parse(value).map_err(|_| Error::Invalid("Invalid service URL."))?;
    let local = matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"));
    if (url.scheme() != "https" && !(url.scheme() == "http" && local))
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(Error::Invalid(
            "Use HTTPS, or HTTP on localhost for development.",
        ));
    }
    Ok(url)
}
