//! Run a nutcracker provider.
//!
//! ```sh
//! nutcracker-provider --listen 127.0.0.1:8099
//! ```
//!
//! `--data <file>` snapshots after every mutation and reloads on start, which is enough for a
//! personal provider. A provider actually *selling* this should back it with the Postgres schema
//! in `nutcracker_store::schema`; a JSON snapshot is honest about being a single-writer file and
//! should not be dressed up as more.

use clap::Parser;
use nutcracker_provider::{router, AppState};

#[derive(Parser, Debug)]
#[command(about = "A nutcracker memory provider. Holds ciphertext; cannot read it.")]
struct Args {
    #[arg(long, env = "NUTCRACKER_LISTEN", default_value = "127.0.0.1:8099")]
    listen: String,

    /// Snapshot file. Without it everything is lost on restart, which is fine for a demo and
    /// not fine for anything you would keep notes in.
    #[arg(long, env = "NUTCRACKER_DATA")]
    data: Option<std::path::PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let args = Args::parse();

    let state = match &args.data {
        Some(p) => AppState::with_data(p.clone())?,
        None => AppState::default(),
    };
    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    match &args.data {
        Some(p) => {
            tracing::info!(listen = %args.listen, data = %p.display(), "nutcracker provider up")
        }
        None => {
            tracing::warn!(listen = %args.listen, "nutcracker provider up with NO --data: everything is lost on restart")
        }
    }
    axum::serve(listener, router(state)).await?;
    Ok(())
}
