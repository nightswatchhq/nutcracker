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
    tools::{Embedder, MemoryTools},
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
}

/// A placeholder local embedder.
///
/// Search quality is only as good as this, and a bag-of-bytes vector is not a semantic model. It
/// is here so the binary runs end to end with no network dependency; a real deployment swaps in a
/// local sentence-transformer. **It must stay local.** A remote embedding call would ship the
/// plaintext to a third party and undo the entire design, which is the single easiest way to
/// accidentally destroy this product.
struct LocalBagOfBytes;

impl Embedder for LocalBagOfBytes {
    fn embed(&self, text: &str) -> Vec<f32> {
        let mut v = vec![0f32; 64];
        for b in text.to_lowercase().bytes() {
            v[(b % 64) as usize] += 1.0;
        }
        let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt().max(1.0);
        v.iter().map(|x| x / norm).collect()
    }
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
    let mut tools = MemoryTools::new(
        root,
        HttpTransport::new(&args.provider),
        Some(LocalBagOfBytes),
    );

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
