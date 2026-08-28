# Encrypted agent memory as a data service

> Design note, 2026-08-28. A reference implementation. Named for Clark's nutcracker, which caches
> tens of thousands of seeds across a mountainside and recovers them months later.

## The brief, and the problem inside it

The Foundation describes its inaugural agentic product as:

> "end-to-end encrypted, user-owned, and fully portable memory across heterogeneous models and
> agents… served directly via The Graph Network"

Four properties. Three of them compose. **End-to-end encryption and semantic recall do not**, and
every design that claims both is quietly giving one of them up. This note is mostly about that,
because everything else here is ordinary.

## The tension, stated plainly

`memory.search("what did I decide about the database?")` requires comparing a query against stored
memories. End-to-end encryption means the provider cannot read stored memories. A provider that
cannot read them cannot compare them.

There are exactly three ways out and each costs something real.

### A. Client-side search

The provider stores opaque blobs and knows nothing. The client fetches a namespace and searches
locally.

*Genuinely end to end.* Leaks only sizes, counts and access timing.

Costs: bandwidth grows with the memory, not with the query. Fine at a thousand items, absurd at a
hundred thousand. And it makes the provider a dumb blob store, which raises an awkward commercial
question — why meter this per *call* rather than per byte?

### B. Client-computed embeddings, stored in the clear beside the ciphertext

The client embeds each memory and ships `(ciphertext, plaintext_vector)`. The provider does
approximate nearest-neighbour over the vectors and returns matching ciphertexts. Scales properly,
one round trip, cheap.

**This is not end-to-end encrypted, and calling it that would be a lie.** Text embeddings are not
one-way. Embedding-inversion work has repeatedly shown that a large fraction of the source text can
be reconstructed from the vector alone, without the model that produced it. A provider holding
`(opaque blob, vector)` holds an approximate copy of the memory. The encryption is doing almost no
work.

This option is the obvious one, it is what most products ship, and it is why the phrase
"end-to-end encrypted" in this category deserves suspicion.

### C. Blind index over coarse buckets — **the default here**

The client embeds locally, reduces the vector to a small number of coarse buckets with an LSH
scheme keyed by a **per-namespace secret**, and sends only bucket ids. The provider narrows to
candidates by bucket and returns those ciphertexts. The client decrypts and does the fine ranking
itself.

The provider learns which buckets a namespace occupies and which bucket a query touched. It does
not learn the vector, and without the namespace secret the buckets are not comparable across
namespaces. The leak is **bounded and tunable**: fewer buckets means more privacy and more
candidates to download; more buckets means the opposite. It degrades toward A as you tighten it and
toward B as you loosen it, which is the right shape for a knob.

Costs: recall is approximate, the client does real work, and there is a second round trip.

### What this implementation does

**Default C. Offer A. Refuse to ship B silently.**

A provider may support plaintext-vector mode, because some users genuinely do not need
confidentiality and will want the performance. It must be **named** at write time
(`index_mode: "plaintext_vectors"`), it is recorded per item, and any namespace containing one such
item stops describing itself as end-to-end encrypted. A privacy property that can be lost by a
single default-valued field is not a property, it is a slogan.

## Keys: per user, delegated to agents

"Portable across heterogeneous models and agents" settles the key question on its own. If the key
were per-agent, Claude could not read what Cursor wrote, and portability is the whole point. So:

```
user root key            held by the user, never sent
  └── namespace key      wraps content keys; one per namespace
        └── content key  one per memory item; encrypts the item
```

Three layers rather than two, for one reason: **revocation must not mean re-encrypting everything.**
Revoking an agent rotates the namespace key and rewraps the content keys — small, fast, O(items)
in cheap operations. Rotating a single-layer scheme means re-encrypting every memory the user has
ever written, which nobody will do, which means in practice nobody revokes.

An agent receives a namespace key wrapped to its own key, plus a capability
(`read` | `write` | `search`) and an expiry. The provider enforces nothing about this and cannot:
it holds ciphertext. Enforcement is the client's, and the provider's job is availability and
honest accounting.

## What does NOT go on chain

compass keys its on-chain registry on subgraph deployments, which are public. The obvious fork is
to key this one on memory namespaces. **Do not.**

A namespace is a person's private thing. A public registry of namespaces would leak who keeps
memory, with which provider, how much of it, and when they started — a metadata trail sitting
permanently on a public ledger, attached to an address, describing a user's private notes. That it
is only metadata is not much comfort; metadata is what surveillance is made of.

So the contract registers **providers and their commitments**, not users and their namespaces. It
knows a provider exists, what capacity it claims, and what it has collected. Namespaces are known
only to the user and their provider, and the mapping between them never touches the chain.

This is the one place where forking compass mechanically would have produced something actively
harmful, so it is worth stating twice: **the registry is of providers, never of users.**

## The unit of service, and what is metered

Per call, on compass's rails: TAP v2 / GraphTally in GRT, x402 USDC-on-Base as the secondary. Four
operations, priced differently because they cost differently:

| Operation | Provider work |
|---|---|
| `memory.write` | store a blob and its bucket ids |
| `memory.read` | fetch by id |
| `memory.search` | bucket lookup, return candidate set |
| `memory.forget` | delete, and mean it |

`memory.forget` deserves a note. A provider that bills for deletion and then keeps the data is
committing the ordinary fraud of this industry, and no contract can detect it. What the contract
*can* do is make the claim legible: deletions are counted, and a provider's forget-to-write ratio
is public. That is not a proof. It is a number somebody can ask about.

## What this cannot do, and will not claim to

- **It cannot prove a provider stores what it says.** No POI equivalent exists, so `slash()`
  reverts, exactly as in Dispatch, compass, Seahorn, SDSCE and chain-integration-ds. Availability
  is economic: an unreliable provider stops being paid.
- **It cannot prove a provider deleted anything.** See above.
- **It cannot stop a user losing their root key.** End-to-end encrypted and user-held means exactly
  that: lose the key, lose the memory. Any provider-side recovery is a provider-side copy of the
  key, and then it was never end to end.

Each of these is a real limitation of the honest design. Products that appear not to have them have
usually chosen option B and not mentioned it.
