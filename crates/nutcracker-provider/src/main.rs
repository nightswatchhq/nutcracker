//! Run a nutcracker provider.
//!
//! ```sh
//! nutcracker-provider --listen 127.0.0.1:8099
//! ```
//!
//! Storage is in memory in this build: it is a reference implementation, and a provider that
//! actually sells this should back it with the Postgres schema in `nutcracker_store::schema`.
//! Saying so here rather than shipping a durable-looking thing that is not.

use clap::Parser;
use nutcracker_provider::{router, AppState};

#[derive(Parser, Debug)]
#[command(about = "A nutcracker memory provider. Holds ciphertext; cannot read it.")]
struct Args {
    #[arg(long, env = "NUTCRACKER_LISTEN", default_value = "127.0.0.1:8099")]
    listen: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();

    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    tracing::info!(listen = %args.listen, "nutcracker provider up; storage is in-memory (reference build)");
    axum::serve(listener, router(AppState::default())).await?;
    Ok(())
}
