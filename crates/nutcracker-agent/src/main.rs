//! `nutcracker-mcp` — a local MCP server over stdio.
//!
//! Point an agent at this, not at a provider. It runs on your machine, holds your root key, and
//! seals everything before it leaves. See the module docs in `lib.rs` for why that ordering is
//! the whole design rather than a deployment preference.
//!
//! ```sh
//! nutcracker-mcp --key ~/.nutcracker/root.key --provider http://127.0.0.1:8099
//! ```

use std::io::{BufRead, Write};

use clap::Parser;
use nutcracker_agent::{
    embedder::{check_or_record, manifest_path_for, BagOfBytes, Embedder, Ollama},
    tools::MemoryTools,
    HttpTransport,
};
use nutcracker_crypto::RootKey;

#[derive(Parser, Debug)]
#[command(about = "A local MCP memory server. Your key stays here; the provider gets ciphertext.")]
struct Args {
    /// File holding the 32-byte root key, hex or raw.
    ///
    /// A file rather than a flag or an env var on purpose: argv is world-readable on Linux via
    /// /proc, and environment blocks leak into crash reports and child processes. A key that
    /// protects everything you have ever told an agent should not be visible in `ps`.
    #[arg(long)]
    key: std::path::PathBuf,

    #[arg(
        long,
        env = "NUTCRACKER_PROVIDER",
        default_value = "http://127.0.0.1:8099"
    )]
    provider: String,

    #[arg(long, default_value = "default")]
    namespace: String,

    /// Embedding model, or `bag-of-bytes` for the dependency-free placeholder.
    ///
    /// Defaults to a real local model, because the placeholder is a byte histogram and not a
    /// semantic model: measured recall against real sentences is in the README, and it is the
    /// difference between search and coincidence.
    #[arg(long, env = "NUTCRACKER_EMBEDDER", default_value = "nomic-embed-text")]
    embedder: String,

    /// Where the embedder listens. Loopback only unless you explicitly say otherwise.
    #[arg(
        long,
        env = "NUTCRACKER_EMBEDDER_URL",
        default_value = "http://127.0.0.1:11434"
    )]
    embedder_url: String,

    /// Permit a non-loopback embedder.
    ///
    /// Named for what it costs rather than for what it enables. An embedder sees the plaintext of
    /// every memory before it is sealed, so a remote one hands your memories to a third party in
    /// the clear and leaves the encryption doing nothing but decorating the trip afterwards.
    #[arg(long)]
    i_accept_sending_plaintext_to_a_remote_embedder: bool,
}

fn read_key(path: &std::path::Path) -> anyhow::Result<RootKey> {
    let raw = std::fs::read(path)?;
    let text = String::from_utf8_lossy(&raw);
    let trimmed = text.trim();
    let bytes: Vec<u8> = if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        (0..64)
            .step_by(2)
            .map(|i| u8::from_str_radix(&trimmed[i..i + 2], 16).unwrap())
            .collect()
    } else {
        raw.clone()
    };
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("key file must hold 32 raw bytes or 64 hex characters"))?;
    Ok(RootKey::from_bytes(key))
}

fn ok(id: serde_json::Value, result: serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn err(id: serde_json::Value, message: String) -> serde_json::Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32000, "message": message }})
}

fn text_result(s: impl Into<String>) -> serde_json::Value {
    serde_json::json!({ "content": [{ "type": "text", "text": s.into() }] })
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let root = read_key(&args.key)?;

    // A real local model by default. `--embedder bag-of-bytes` keeps the old placeholder for
    // running with nothing installed, and it is named for what it is rather than for what one
    // might wish it were.
    let embedder: Box<dyn Embedder> = if args.embedder == "bag-of-bytes" {
        Box::new(BagOfBytes)
    } else {
        Box::new(Ollama::new(
            &args.embedder_url,
            &args.embedder,
            args.i_accept_sending_plaintext_to_a_remote_embedder,
        )?)
    };

    // Refuses rather than warns. See `embedder.rs`: a changed model means a disjoint token space,
    // so old memories become unfindable and new ones look fine, with nothing to see in a log.
    check_or_record(&manifest_path_for(&args.key), embedder.as_ref())?;

    // Fail at startup rather than at the agent's first search, where the error arrives as a broken
    // tool call in the middle of somebody's conversation.
    if let Err(e) = embedder.embed("startup probe") {
        anyhow::bail!("{e}");
    }

    eprintln!("nutcracker-mcp: embedder={}", embedder.id());

    let mut tools = MemoryTools::new(root, HttpTransport::new(&args.provider), Some(embedder));

    // stderr, never stdout: stdout is the MCP channel and a stray log line corrupts the stream.
    eprintln!(
        "nutcracker-mcp: provider={} namespace={}",
        args.provider, args.namespace
    );

    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let req: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                writeln!(stdout, "{}", err(serde_json::Value::Null, e.to_string()))?;
                stdout.flush()?;
                continue;
            }
        };
        let id = req.get("id").cloned().unwrap_or(serde_json::Value::Null);
        let method = req["method"].as_str().unwrap_or("");
        let p = &req["params"];

        let response = match method {
            "initialize" => ok(
                id,
                serde_json::json!({
                    "protocolVersion": "2025-03-26",
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "nutcracker", "version": env!("CARGO_PKG_VERSION") }
                }),
            ),
            "notifications/initialized" => continue,
            "tools/list" => ok(
                id,
                serde_json::json!({ "tools": nutcracker_agent::tool_definitions() }),
            ),
            "tools/call" => {
                let name = p["name"].as_str().unwrap_or("");
                let a = &p["arguments"];
                let ns = a["namespace"]
                    .as_str()
                    .unwrap_or(&args.namespace)
                    .to_string();
                match name {
                    "memory.write" => {
                        let text = a["text"].as_str().unwrap_or_default();
                        // Content-addressed by default so the same thought written twice does not
                        // become two memories the user has to notice and reconcile.
                        let id_str =
                            a["item_id"]
                                .as_str()
                                .map(str::to_string)
                                .unwrap_or_else(|| {
                                    format!("m{:016x}", {
                                        let mut h: u64 = 1469598103934665603;
                                        for b in text.as_bytes() {
                                            h ^= *b as u64;
                                            h = h.wrapping_mul(1099511628211);
                                        }
                                        h
                                    })
                                });
                        match tools.write(&ns, &id_str, text, a["expires_at"].as_u64()) {
                            Ok(()) => ok(id, text_result(format!("remembered as {id_str}"))),
                            Err(e) => err(id, e.to_string()),
                        }
                    }
                    "memory.search" => {
                        let q = a["query"].as_str().unwrap_or_default();
                        let limit = a["limit"].as_u64().unwrap_or(10) as usize;
                        match tools.search(&ns, q, limit) {
                            Ok(hits) if hits.is_empty() => {
                                ok(id, text_result("no matching memories"))
                            }
                            Ok(hits) => ok(
                                id,
                                text_result(
                                    hits.iter()
                                        .map(|m| {
                                            format!("[{} {:.2}] {}", m.item_id, m.score, m.text)
                                        })
                                        .collect::<Vec<_>>()
                                        .join("\n"),
                                ),
                            ),
                            Err(e) => err(id, e.to_string()),
                        }
                    }
                    "memory.read" => {
                        match tools.read(&ns, a["item_id"].as_str().unwrap_or_default()) {
                            Ok(m) => ok(id, text_result(m.text)),
                            Err(e) => err(id, e.to_string()),
                        }
                    }
                    "memory.forget" => {
                        match tools.forget(&ns, a["item_id"].as_str().unwrap_or_default()) {
                            Ok(true) => ok(id, text_result("forgotten")),
                            // Said plainly. The provider cannot prove it deleted anything, and neither
                            // can this, so "nothing to forget" is the honest phrasing.
                            Ok(false) => ok(id, text_result("nothing to forget under that id")),
                            Err(e) => err(id, e.to_string()),
                        }
                    }
                    other => err(id, format!("unknown tool: {other}")),
                }
            }
            other => err(id, format!("unknown method: {other}")),
        };

        writeln!(stdout, "{response}")?;
        stdout.flush()?;
    }
    Ok(())
}
