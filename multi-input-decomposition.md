# Multi-Input Decomposition: Collapsing the Transaction Chain

The chunked verifier (`chunked/`, [multi-step-computation.md](multi-step-computation.md))
splits the Groth16 verifier across a **chain of sequential transactions**, carrying
state forward in an NFT covenant — one block/mempool hop per step, ~93–116 steps.

This note documents an alternative decomposition, prototyped and validated in
[`multi-input/`](multi-input/), that splits the same work across **sibling inputs
of one transaction** instead. It does not reduce total op-cost or bytes; it
collapses the **transaction count** (and hence latency), and runs the verifier's
independent sub-computations in **parallel** rather than serializing them.

## The principle

`multi-step-computation.md` states that computation cannot be shared across the
inputs of one transaction. That is too strong. Anything done in N sequential
transactions can be done in **one transaction with N inputs**:

For `y = f1(f0(x))`, the spender — who computes the whole thing off-chain — supplies
every intermediate in the witnesses, and each input only *checks* one step:

```
input0:  assert  f0(x)  == s1        // s1, s2 pre-supplied by the spender
input1:  assert  f1(s1) == s2
stitch:  assert  s1 (input0's output) == s1 (input1's input)
```

No input runs "first". The dependency `f1∘f0` is enforced not by execution order
but by the **equality constraint** binding input0's published result to input1's
consumed input. Each input is an independent predicate over pre-committed data;
the transaction is valid iff a consistent threading `x → s1 → y` exists — exactly
the computation. Depth drops out of the transaction count; the binding constraint
becomes **transaction size** (≈100 KB standard relay / ≈1 MB consensus), not the
dependency chain.

This is the cross-input aggregation pattern shipping in production in
[Quantumroot](https://blog.bitjson.com/quantumroot): one expensive check (a
quantum signature), many inputs introspecting it. Here it is generalized to
*several independent expensive computations + a fold*.

## How the stitch is realized (and made sound)

The handoff is published to a **shared output** (the in-transaction blackboard
both inputs see) and bound two ways:

- **Producer** chunk: `require(tx.outputs[k].nftCommitment == hash(its result))`
  and `... .tokenCategory == thread` — publishes its result on the covenant thread.
- **Consumer** chunk: `require(tx.outputs[k].nftCommitment == hash(its incoming))`
  and `... .tokenCategory == thread` — what it consumes equals what the producer
  published, on the same thread.

The **token-category (thread) binding** is load-bearing: without it a spender
could satisfy the commitment equality with an output carried by an input from an
*unrelated* computation. `multi-input/assemble_and_grade.mjs` includes a
cross-thread attack and confirms it is rejected.

## Validated results (real BCH 2026 VM)

All on the loosened-then-real BCH 2026 VM, graded against `@noble/curves`.

**vk_x** = IC0 + in0·IC1 + in1·IC2 ([`multi-input/gen_vkx_multiinput.mjs`](multi-input/gen_vkx_multiinput.mjs)):
the two scalar-mult terms run as **parallel arms** (3 chunks each), stitched, with
a fold input. **7 sibling inputs in ONE transaction**, every input ≤ budget
(max 8.02M / 8.03M), fold == noble vk_x. Forged handoff rejected; cross-thread
mixing rejected. Baseline `chunked/shamir`: **3 sequential transactions**.

**Four-pairing boundary** ([`multi-input/four_pairing_layout.mjs`](multi-input/four_pairing_layout.mjs)):
the **fold** combining four independent Fp12 Miller outputs (tree product
`(m1·m2)·(m3·m4)` == golden boundary) validated on the real VM (~2.5M op-cost,
fits one input; tampered Fp12 rejected; the four outputs verified non-degenerate).

## Full-verifier transaction count

Per-arm chunk counts from the **measured** singleton costs (single-pair Miller
~128.8M, final-exp ~141M op-cost):

| stage | chunked (serial) | multi-input |
|---|---|---|
| vk_x | 3 txns | parallel arms, in-tx |
| Miller (4 pairings) | ~59 chunks, 1 chain | 4 × 17 = 68 parallel-arm inputs |
| fold | — | 3 |
| final-exp | ~34 chunks | 18 (serial after fold) |
| **sequential transactions** | **~93** | **~9 standard / 1 consensus** |

The four pairings and two scalar-mult terms stop being a serial chain; they
become parallel sibling inputs. The ~93-step critical path collapses to the
tx-size wall.

## The honest tradeoffs

- **Total op-cost is not reduced** — it rises modestly. The chunked design
  *batches* the four pairings into one shared `f` (one `fp12Sqr`/step across all
  4 pairs, eliminating 3 of every 4 squarings) and shares one Shamir/Straus
  doubling chain for vk_x. The parallel-arm layout gives those up (each arm
  squares its own `f`; separate scalar-mults). The topology change buys
  transaction count, not compute. (These optimizations are *orthogonal* — a
  batched/Shamir arm could itself be split the same way; the prototypes isolate
  the topology change.)
- **Total bytes are similar** — each input still re-ships its function prologue
  and pads to buy its op-cost budget. Multi-input avoids the per-transaction
  skeletons and the cross-transaction state re-hash, but those were already the
  smallest part of the chunking tax.
- **The win is transaction count / latency** (~93 hops → ~9, or 1 on a
  non-standard 1 MB consensus transaction), plus genuine **parallelism** for the
  independent pairings — the dominant user-facing cost of a multi-step on-chain
  verifier.
- **Per-input op-cost budget is per-input, not shared** (BCH chose this
  deliberately), so N sibling inputs genuinely bring N× the compute ceiling in
  one transaction — the reason this works at all. The cost is that each input
  carries its own padding to claim its budget, which is what consumes the
  transaction-size limit.

## Status

`multi-input/` contains: the 2-input stitch PoC, the full vk_x generator (7-input
single-transaction layout, validated + forgery/cross-thread tests), and the
four-pairing layout analysis with the validated Fp12 fold. The per-arm Miller
chunking is mechanically identical to the validated vk_x stitch with a larger
carried state; a full single-pair Miller arm generator is the remaining build-out.
See [`multi-input/README.md`](multi-input/README.md) and
[`multi-input/FOUR_PAIRING.md`](multi-input/FOUR_PAIRING.md).
