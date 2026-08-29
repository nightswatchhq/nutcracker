# nutcracker

**End-to-end encrypted, user-owned agent memory as a Horizon data service.**

Named for Clark's nutcracker, which caches tens of thousands of seeds across a mountainside and
recovers them months later.

A reference implementation. The Night's Watch builds these services and does not run them; any
provider can register.

## The problem inside the brief

The Foundation describes its inaugural agentic product as *"end-to-end encrypted, user-owned, and
fully portable memory across heterogeneous models and agents"*.

Four properties. Three of them compose. **End-to-end encryption and semantic recall do not.**
`memory.search` means comparing a query against stored memories; end-to-end encryption means the
provider cannot read stored memories; a provider that cannot read them cannot compare them.

Every design claiming both is quietly giving one up, and the usual one to give up is the
encryption — by storing plaintext embeddings beside the ciphertext. Text embeddings are not
one-way, and a provider holding `(opaque blob, vector)` holds an approximate copy of the memory.

[`docs/design.md`](docs/design.md) works through the three genuine options and picks: **a blind
index over coarse buckets keyed per namespace**, with bounded and tunable leakage, degrading toward
pure client-side search as you tighten it. Plaintext-vector mode exists, must be **named** at write
time, and any namespace containing one such item stops describing itself as end-to-end encrypted.

## Keys

Three layers, because revocation must not mean re-encrypting everything:

```
user root key            held by the user, never sent
  └── namespace key      wraps content keys; one per namespace
        └── content key  one per item
```

Revoking an agent rotates the namespace key and rewraps the content keys. A single-layer scheme
would mean re-encrypting every memory the user ever wrote, which nobody does, which means in
practice nobody revokes.

## The one thing not to fork from compass

compass keys its on-chain registry on subgraph deployments. The mechanical fork keys this one on
memory namespaces. **Do not.** A public registry of namespaces leaks who keeps memory, with which
provider, how much, and since when — permanently, against an address.

**This registry is of providers, never of users.** There is a test named for it.

## What it does not claim

- It cannot prove a provider stores what it says. `slash()` reverts, as in every other community
  data service.
- It cannot prove a provider deleted what it billed for deleting. What it can do is make the claim
  legible: deletions are counted and a provider's forget-to-write ratio is public. Not a proof, but
  a number somebody can ask about.
- It cannot recover a lost root key. User-held means user-held.
- **The published recall figures describe near-duplicate retrieval, not semantic relatedness, and
  they were measured on a geometry no real corpus has.** See below; this is the most load-bearing
  caveat in the document.

## What the recall numbers actually measured

`cargo run -p nutcracker-crypto --example leakage` reports 100% recall at 0.2 perturbation, 94% at
0.5, ~3% false candidates. Those figures are correct and they are a fair characterisation of the LSH
scheme. They are also answering a narrower question than a reader will hear, in two ways, and
`--example geometry` measures both.

**One: uniformly random vectors are not embeddings.** Transformer embeddings crowd into a narrow
cone rather than filling the sphere. Re-running the same index against corpora with that shape:

| corpus | recall | false candidates | mean cos(unrelated) |
|---|---|---|---|
| uniform sphere, loose clusters | 28% | 2% | 0.00 |
| mildly anisotropic (0.3) | 40% | 6% | 0.15 |
| anisotropic (0.6) | 72% | 26% | 0.69 |
| severely anisotropic (0.8) | 100% | 99% | 0.94 |
| ↳ 0.6, mean-centred first | 27% | 4% | 0.00 |
| ↳ 0.8, mean-centred first | 28% | 3% | -0.00 |

Read the false-candidate column. On a realistically anisotropic corpus it is **26%, not 3%** — an
order of magnitude more than published, and that column is the leakage: every false candidate is an
item the provider is asked for and learns was a candidate. At 0.8 the index degenerates entirely and
every item matches every query, which reads as 100% recall and is the scheme telling you nothing.

**Mean-centring fixes it, and restores the uniform-sphere baseline exactly** (27–28% recall against
28%, 3–4% false against 2%). It is not free: the mean must be computed client-side, and it must stay
**fixed for the lifetime of a namespace**, because changing it makes every token computed afterwards
disagree with every token computed before. That is a migration, not a knob. Not yet implemented.

**Two: 0.05 perturbation is a near-duplicate.** Retrieving those is easy and is not what anyone means
by semantic search. On loosely clustered data — related but not nearly identical, which is the real
case — recall at the default 8×8 is around **28%**, not the 94–100% the perturbation table suggests.
Loosening the parameters chases that tail and discloses more; the trade is real and this is its shape.

The honest summary: the blind index is sound and the crypto around it does what it claims. The
retrieval quality has been characterised against synthetic vectors and **not yet against a real
embedding model**, and the placeholder embedder in the agent binary is a bag-of-bytes vector that is
not a semantic model at all. Anyone evaluating this for real work should read that as the open
question it is.

## What is here

| Crate | What it is |
|---|---|
| `nutcracker-crypto` | client-side: three-layer envelope encryption, the keyed blind index |
| `nutcracker-store` | provider-side: opaque ciphertext by namespace handle, searched by bucket token |
| `nutcracker-agent` | the **local** MCP shim: holds the root key, seals before anything leaves the machine |
| `nutcracker-provider` | a runnable provider: HTTP over the sealed store, holds no keys |
| `contracts` | `MemoryDataService.sol` — providers and commitments, never users |

The store's type signatures are the enforcement: **there is no way to hand it a plaintext, even by
accident, because no function accepts one.** Its Postgres schema has a test asserting that no
column can hold a user, a namespace name, a plaintext or an embedding — which caught its own first
draft.

## The MCP server is local, and that is not a detail

compass runs its MCP server at the provider, because subgraph data is public. Copying that here
cannot be end-to-end encrypted, and the reason is worth saying slowly: if the agent talks MCP
straight to the provider, then either it sends plaintext and the provider has it, or the *agent*
holds the root key. "The agent" means Claude, or Cursor, or whatever you are running next month.
Handing a rotating cast of third-party clients the key that protects everything you have ever told
any of them is not user-owned memory.

```
  agent  ──MCP, plaintext, localhost──▶  nutcracker-agent  ──HTTP, sealed──▶  provider
                                         (holds the root key)                 (holds nothing)
```

The agent gets `memory.write("we chose postgres")`. The provider gets opaque bytes and bucket
tokens. **Anything advertising itself as a remote agent-facing memory MCP server is holding your
keys.**

## Run it

```sh
cargo run -p nutcracker-provider                        # a provider on :8099
head -c 32 /dev/urandom > ~/.nutcracker/root.key        # your key. Back it up; nobody can recover it.
cargo run --bin nutcracker-mcp -- --key ~/.nutcracker/root.key
```

`nutcracker-mcp` is an MCP server over stdio. Point an agent at **it**, not at a provider. A real
session:

```
initialize  -> nutcracker v0.1.0
tools/list  -> [memory.write, memory.search, memory.read, memory.forget]
memory.write -> remembered as mdf8f2d65af0e0ab9
memory.search
  [mdf8f2d65af0e0ab9 1.00] Chief decided we develop data services but do not operate them...
  [m488e5949e83ed448 0.89] the DIPS rails went live on Arbitrum One and were wired on 25 August...
```

The provider narrowed that by blinded bucket tokens and could not read either memory. The scores
were computed locally, after decryption — a bucket collision is a hint, not a similarity, so
serving the provider's ordering straight to the agent would surface unrelated memories as matches.

The key is read from a **file**, never a flag or an env var: argv is world-readable on Linux via
`/proc`, and environment blocks leak into crash reports and child processes.

The bundled embedder is a bag-of-bytes placeholder so the binary runs with no network dependency.
Swap in a real local sentence-transformer. **It must stay local** — a remote embedding call ships
the plaintext to a third party and undoes the entire design.

```sh
cargo run -p nutcracker-agent --example http_roundtrip  # the same path without MCP
```

The example seals a memory locally, writes it over HTTP, searches by blinded bucket tokens, and
decrypts what comes back:

```
wrote m1 (77 bytes of ciphertext)
search returned 1 candidate(s)
decrypted: "the blind index keys its hyperplanes off the namespace secret"

The provider stored, indexed and served that back without ever being able to read it.
```

Storage in this build is in memory. A provider actually selling this should back it with the
Postgres schema in `nutcracker_store::schema` — said here rather than shipping something that
looks durable and is not.

Payment is not wired into the provider. A real one fronts these handlers with the TAP receipt
validation compass already implements and returns 402 without one; that belongs in front rather
than half-built inside.

Full setup, including keeping the provider running and pointing Claude Code at it:
[`docs/install.md`](docs/install.md).

## Build

```sh
cd contracts && forge test
```

15 contract tests, 65 Rust tests. `graphprotocol/contracts` is pinned to `2629e646…` (main) — see the gotchas in
`nightswatchhq/horizon-skills`, since the documented `horizon@1.1.0` pin moves several APIs.

Apache-2.0.
