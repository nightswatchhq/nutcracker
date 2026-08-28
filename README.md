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

## What is here

| Crate | What it is |
|---|---|
| `nutcracker-crypto` | client-side: three-layer envelope encryption, the keyed blind index |
| `nutcracker-store` | provider-side: opaque ciphertext by namespace handle, searched by bucket token |
| `contracts` | `MemoryDataService.sol` — providers and commitments, never users |

The store's type signatures are the enforcement: **there is no way to hand it a plaintext, even by
accident, because no function accepts one.** Its Postgres schema has a test asserting that no
column can hold a user, a namespace name, a plaintext or an embedding — which caught its own first
draft.

## Build

```sh
cd contracts && forge test
```

15 contract tests, 35 Rust tests. `graphprotocol/contracts` is pinned to `2629e646…` (main) — see the gotchas in
`nightswatchhq/horizon-skills`, since the documented `horizon@1.1.0` pin moves several APIs.

Apache-2.0.
