//! The relay binary.
//!
//! ```text
//! MORTISE_RELAY_DB=relay.db MORTISE_RELAY_ADDR=127.0.0.1:8787 mortise-relay
//! ```
//!
//! Serves plain HTTP. Put it behind a TLS terminator in production — the
//! payloads are already end-to-end encrypted, but the device public keys and
//! sync timing in the clear would hand a network observer the social graph for
//! free, and that is precisely the metadata the threat model says to minimize.

use mortise_relay::server;
use mortise_relay::store::Store;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mortise_relay=info,tower_http=warn".into()),
        )
        .init();

    let db = std::env::var("MORTISE_RELAY_DB").unwrap_or_else(|_| "relay.db".into());
    let addr = std::env::var("MORTISE_RELAY_ADDR").unwrap_or_else(|_| "127.0.0.1:8787".into());

    let store = Store::open(&db)?;
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    tracing::info!(%addr, %db, "relay listening");
    tracing::info!("this process stores ciphertext it cannot read");

    axum::serve(listener, server::router(store))
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("shutting down");
}
