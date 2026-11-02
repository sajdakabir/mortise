//! Interactive verification against a disposable Neon branch. Never opens a
//! real vault or writes device private keys/session tokens to disk.
use mortise_accounts::{
    client::{Client, Request, browser_login},
    protocol::*,
};
use mortise_crypto::identity::{Device, Identity};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("NEON_BRANCH").as_deref() != Ok("mortise-integration") {
        return Err("Run only against the disposable mortise-integration branch".into());
    }
    let base = std::env::var("MORTISE_ACCOUNTS_URL")?;
    let identity = Identity::generate()?;
    let device = Device::generate()?;
    let certificate = hex(&identity
        .certify(device.public(), (now() * 1000) as u64)
        .to_bytes());
    let client = Client::new(&base, String::new())?;
    let config = client.config()?;
    let challenge: LoginChallenge = client.send(Request::signed(
        &device,
        "POST",
        "/v1/auth/start",
        "",
        &LoginStart {
            certificate,
            device_name: "Temporary Neon integration test".into(),
        },
    )?)?;
    let id_token = browser_login(&config, &challenge.nonce, |url| {
        println!("Complete this test sign-in in your browser:\n{url}");
        Ok(())
    })?;
    let session: Session = client.send(Request::signed(
        &device,
        "POST",
        "/v1/auth/finish",
        "",
        &LoginFinish {
            id: challenge.id,
            id_token: id_token.to_string(),
        },
    )?)?;
    let client = Client::new(&base, session.token)?;
    let dashboard: Dashboard = client.send(Request::signed(
        &device,
        "GET",
        "/v1/me",
        client.token(),
        &(),
    )?)?;
    assert_eq!(dashboard.account.id, session.account.id);
    println!(
        "PASS: Neon browser sign-in, PKCE, verified ID token, signed API session and Postgres dashboard."
    );
    let _: () = client.send(Request::signed(
        &device,
        "POST",
        "/v1/logout",
        client.token(),
        &(),
    )?)?;
    let denied: mortise_accounts::Result<Dashboard> = client.send(Request::signed(
        &device,
        "GET",
        "/v1/me",
        client.token(),
        &(),
    )?);
    assert!(denied.is_err());
    println!("PASS: logout invalidates the API session.");
    Ok(())
}
