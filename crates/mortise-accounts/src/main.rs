#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    mortise_accounts::server::run().await
}
