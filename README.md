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

On a realistically anisotropic corpus the false-candidate rate is **26%, not 3%**. At 0.8 the index
degenerates entirely and every item matches every query, which reads as 100% recall and is the scheme
telling you nothing.

> **A correction, because an earlier version of this section got it backwards.** It called the
> false-candidate column "the leakage". It is not. A false candidate is **bandwidth**: the client
> fetches an item, decrypts it, ranks it and discards it, and the provider learns nothing it did not
> already know from the bucket token. The per-item disclosure is **`bits/item` = bands × bits**, and
> the two move in opposite directions. If anything a *higher* false rate helps query privacy, because
> it is cover: the provider cannot tell which of the returned candidates you actually wanted. The
> original `leakage.rs` said this correctly and I overrode it. Read `bits/item` for disclosure and
> the false rate for cost.

**Mean-centring restores the uniform-sphere baseline exactly** (27–28% recall against 28%, 3–4%
false against 2%). It is not free: the mean must be computed client-side, and it must stay **fixed
for the lifetime of a namespace**, because changing it makes every token computed afterwards
disagree with every token computed before. That is a migration, not a knob. Not yet implemented.

### Measured against a real model (2026-08-30)

The synthetic argument above turned out to be a fair predictor, and now there is no need to argue
from it. 48 sentences over 12 topics, embedded by `nomic-embed-text` (768-dim) on a real Ollama
install, with same-topic pairs deliberately **not** near-duplicates. Corpus committed beside
`--example real_embeddings`, so the numbers reproduce without a GPU.

**Unrelated sentences sit at cosine 0.43, not 0.00**, and the distributions overlap: related pairs
average 0.62 but reach down to 0.42, while unrelated pairs reach up to 0.61.

| bands × bits | recall | false candidates | corpus |
|---|---|---|---|
| 8 × 8 (default) | 46% | 22% | as-is |
| 8 × 8 | 17% | 3% | mean-centred |
| 16 × 8 | 69% | 38% | as-is |
| 8 × 4 | 88% | 75% | as-is |
| 16 × 4 | 100% | 96% | as-is |

**Read the two columns together, because they move together.** There is no setting here that buys
good recall and low disclosure at once: 100% recall is bought by returning 96% of unrelated items as
candidates, which is asking the provider for most of the corpus and calling it a search. At the
default the honest summary is **46% of related pairs retrieved, 22% of unrelated ones surfaced** —
a real search with a real cost, and not the shape the perturbation table implies.

Mean-centring cuts disclosure hard (22% → 3%) and costs recall (46% → 17%). That is worse than the
synthetic run predicted, and the reason is instructive: on real embeddings part of the topical signal
genuinely lives along the shared direction, so removing it removes some of the thing you were
searching for. On a 48-sentence corpus the mean is also a poor estimate of itself.

### Centring, on the evidence rather than on theory

A sweep of 14 parameter settings, with and without centring, on the real corpus. A configuration is
**dominated** when another beats it on recall *and* on cost at once; what survives is the frontier.
**11 of 16 frontier points are centred, and 8 as-is configurations are beaten outright.** Centring
moves the frontier; it does not merely slide along it.

The comparison that decides it, once `bits/item` is read as the disclosure it is:

| | recall | candidates | **bits/item** |
|---|---|---|---|
| as-is 8 × 8 *(today's default)* | 46% | 22% | **64** |
| **centred 8 × 4** | **67%** | 36% | **32** |
| centred 24 × 8 | 42% | 9% | 192 |

**`centred 8 × 4` is now the default.** Half the per-item disclosure of the old one, and half again
more recall. It pays in bandwidth — 36% of candidates come back unrelated rather than 22% — which is
the cheap axis, and which buys query cover rather than spending it.

> **It shipped wrong first, and the failure is worth naming.** Centring went in while the default was
> still 8 × 8, and centred 8 × 8 gives **17%** recall — worse than doing neither. For about an hour
> the released configuration was worse than the one it replaced, because two halves of one decision
> were shipped as two decisions. The manifest catches the upgrade rather than corrupting anyone's
> index, which is the only reason this is an inconvenience rather than an incident.

Note the third row as the trap it is. Chasing a low candidate rate (9%) is what an earlier reading of
this table would have recommended, and it triples per-item disclosure to 192 bits to buy *less*
recall than the default. That is paying on the expensive axis to optimise the cheap one.

### It turned out not to need a migration, because the mean belongs to the model

Twice above this document called centring a migration, on the assumption that the mean is a property
of a corpus and must be computed and frozen per namespace. **That was assumed rather than tested,
and it is wrong.**

Two disjoint corpora, 48 sentences each, different topics and different register with no overlap:
their means point in nearly the same direction, `cos = 0.939`. Centring corpus B by corpus **A's**
mean takes B's unrelated-pair cosine from 0.420 to 0.048 — essentially as well as its own mean does
(-0.045). Through the index, on that held-out corpus at 8 × 4: 88% recall and 70% candidates becomes
**81% and 45%**, against the current default's 47% / 21% at twice the per-item disclosure.

So the mean ships as a **per-model constant** (`reference_mean.rs`, estimated from 96 sentences over
24 topics). An index is stable from its first item and a growing corpus never invalidates its own
tokens. For scale: the mean of 96 unit vectors drawn uniformly on a 768-sphere would have norm
~0.10; this one has norm **0.659**, and that number is the cone.

`nutcracker-mcp` applies it now. Revising the constant *would* be a migration, so it is versioned
into the embedder identity as `+centred-v1` and the manifest check refuses a mismatch — no second
mechanism to keep in step. The same manifest now records `bands x band_bits`, because a token is
that many hyperplane signs and changing the shape breaks them exactly as changing the model does:
guarding one and not the other would have left the same trapdoor open with a different label.

One implementation note the measurement forced out: `shared_bands` re-derives every hyperplane
component by hashing `(plane, dimension)`, so comparing per pair is `pairs × planes × dims` hashes.
Tokenise each item once. The first version of the benchmark did not, and ran for twenty minutes.

**Two: 0.05 perturbation is a near-duplicate.** Retrieving those is easy and is not what anyone means
by semantic search. On loosely clustered data — related but not nearly identical, which is the real
case — recall at the default 8×8 is around **28%**, not the 94–100% the perturbation table suggests.
Loosening the parameters chases that tail and discloses more; the trade is real and this is its shape.

The honest summary: the blind index is sound and the crypto around it does what it claims, and the
retrieval quality is now measured rather than assumed. It is modest. Anyone evaluating this for real
work should read the table above rather than the perturbation one.

## The embedder

`nutcracker-mcp` runs **`nomic-embed-text` through a local Ollama by default**. The bag-of-bytes
placeholder is still there as `--embedder bag-of-bytes`, for running with nothing installed, and it
is named for what it is: a histogram of byte values, not a semantic model.

Three refusals, and each of them is a refusal rather than a warning on purpose.

**A non-loopback embedder is refused.** An embedder sees the plaintext of every memory *before* it is
sealed, so a remote one hands your memories to a third party in the clear and leaves the encryption
decorating the trip afterwards. It is the single easiest way to destroy this product, and it would
be one config line. The override is `--i-accept-sending-plaintext-to-a-remote-embedder`, named for
what it costs rather than for what it enables.

**Changing the model is refused.** Bucket tokens are derived from the embedding, so two models are
two disjoint token spaces over the same memories. Swap one and everything stored before becomes
unfindable, everything stored after looks fine, and nothing errors: an assistant that has quietly
forgotten one era of its life. The model is recorded beside the key on first use and checked at
every start, and the refusal explains the damage rather than just saying no. The same hazard is why
the mean-centring fix above is described as a migration and not a knob.

**A failing embedder is refused, never fallen back from.** There is no second embedder to reach for,
because reaching for one would return vectors from a different space and silently corrupt the index.
The binary probes the model at startup and exits with `Is Ollama running?` rather than failing later,
in the middle of somebody's conversation.

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
