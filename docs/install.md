# Running nutcracker on your own machine

What this sets up: a provider on loopback that holds ciphertext, and an MCP server your agent talks
to that holds your key. Nothing listens on a public interface and nothing leaves the machine.

```sh
cargo install --path crates/nutcracker-provider
cargo install --path crates/nutcracker-agent

mkdir -p ~/.nutcracker && chmod 700 ~/.nutcracker
head -c 32 /dev/urandom > ~/.nutcracker/root.key && chmod 600 ~/.nutcracker/root.key
```

**Back that key up now.** It is the only copy. Losing it loses every memory, by design: any
provider-side recovery is a provider-side copy of the key, and then it was never end to end.

## Keep the provider running (macOS)

`~/Library/LaunchAgents/com.nightswatch.nutcracker-provider.plist`, loaded with
`launchctl load`. It binds `127.0.0.1:8099` only and snapshots to `~/.nutcracker/store.json`.

Remove it with:

```sh
launchctl unload ~/Library/LaunchAgents/com.nightswatch.nutcracker-provider.plist
rm ~/Library/LaunchAgents/com.nightswatch.nutcracker-provider.plist
```

## Point Claude Code at it

```sh
claude mcp add nutcracker --scope user -- \
  ~/.cargo/bin/nutcracker-mcp --key ~/.nutcracker/root.key --provider http://127.0.0.1:8099
```

Use absolute paths: the arguments are passed as argv and nothing expands `~`.

**MCP servers are loaded when a session starts**, so an existing session will not see it. Start a
new one.

Remove with `claude mcp remove nutcracker -s user`.

## What lives where

| Path | What | Contains |
|---|---|---|
| `~/.nutcracker/root.key` | your key, mode 600 | **the only secret** |
| `~/.nutcracker/store.json` | the provider's snapshot | ciphertext and bucket tokens |
| `~/.nutcracker/logs/` | provider stdout/stderr | no memory contents |

The snapshot is safe to back up and safe to lose in the sense that it reveals nothing; it is *not*
safe to lose in the sense that your memories are in it. The key is the opposite: catastrophic to
leak, catastrophic to lose.

## What this build is not

The bundled embedder is a bag-of-bytes placeholder, so search finds near-duplicates well and loose
semantic matches poorly. Swap in a local sentence-transformer for real recall. **It must stay
local**: a remote embedding call ships your plaintext to a third party and undoes everything above.

Storage is a JSON snapshot rewritten on every mutation. Fine for one person's notes, wrong for a
provider selling this — `nutcracker_store::schema` has the Postgres shape for that.

Payment is not wired in. A provider actually charging for this fronts these handlers with TAP
receipt validation and returns 402 without one.
