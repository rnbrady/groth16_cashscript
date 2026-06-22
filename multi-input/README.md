# multi-input/ — sibling-input decomposition (proof of concept)

An alternative decomposition that improves on the cross-transaction chain in
`../chunked/`. The chunked verifier threads work through a chain of **sequential
transactions** (one NFT covenant, one linear `hash256` chain). This PoC threads
the same work through **sibling inputs of ONE transaction**, stitched by
cross-input introspection — collapsing the chain's *depth* into a single
transaction.

## The principle

Anything done in N sequential transactions can be done in one transaction with N
inputs. For a serial computation `s2 = chunkB(s1)`, `s1 = chunkA(s0)`:

- **input0 (producer, `arm_chunkA.cash`)** computes `s1 = chunkA(s0)`, binds `s0`
  to its own spent NFT commitment (`covIn`), and **requires `tx.outputs[0]`
  commits `hash(s1)`** — publishing its result to a shared blackboard.
- **input1 (consumer, `arm_chunkB.cash`)** computes `s2 = chunkB(s1)`, and
  **requires `tx.outputs[0].nftCommitment == hash(s1)`** — i.e. the `s1` it
  consumes equals the `s1` input0 produced. This is the cross-input stitch.

Both inputs validate against the *same* fixed transaction (witnesses + outputs).
Neither runs "first"; the dependency is enforced by the **equality constraint on
output[0]**, the in-transaction blackboard both inputs read. The spender
pre-supplies every handoff state in the witnesses; the contract only *checks*.

## Measured result (real BCH 2026 VM)

Instance: one vk_x scalar-mult term `in0·IC1` (the BN254 IC1 point), split into
two ~82-bit windows.

| case | input0 (chunkA) | input1 (chunkB) | verdict |
|------|----------------|-----------------|---------|
| **honest** (input1 consumes real s1) | accepted, ~8.01M op | accepted, ~5.90M op | **TX VALID** |
| **forged** (input1 consumes tampered s1) | accepted | **rejected** (`OP_VERIFY`) | **TX REJECTED** |

So ~13.9M op-cost of dependent work — more than one input's ~8.03M budget —
runs in **one transaction**, each input drawing its own per-input budget, and a
forged handoff is caught. The stitch is sound.

Fixed per-chunk overhead (covIn + covOut hashing + pad handling) measured at
**~48K op-cost**, ~0.6% of the per-input budget — confirming the hash-handoff
cost is negligible next to the field arithmetic.

## Why this improves on `../chunked/`

The chunked vk_x needs **3 sequential transactions** (shamir) — 3 block/mempool
hops. The same work as sibling inputs is **1 transaction**. Generalized to the
full verifier: the cross-transaction chain's length equals the verifier's
dependency *depth*, but with sibling-input stitching that depth collapses into a
single transaction, bounded only by transaction size (≈100 KB standard / ≈1 MB
consensus), not by the number of dependency steps. Total op-cost and total bytes
are unchanged — the win is **transaction count / latency**, plus true
parallelism for the independent sub-computations (the four pairings, the two
scalar-mult terms).

## Full generator (`gen_vkx_multiinput.mjs`)

Scales the stitch primitive to the **whole** vk_x = IC0 + in0·IC1 + in1·IC2,
laid out as sibling inputs of ONE transaction, empirically window-sized, graded
on the real BCH 2026 VM against the noble bn254 oracle.

DAG: `term0 = in0·IC1` and `term1 = in1·IC2` are independent (run in parallel
inputs); within a term, chunks stitch serially via the shared-output blackboard;
a final fold input reads both terminal results, computes `IC0 + term0 + term1`,
`jacToAffine`, and asserts `== EXPECTED`.

### Measured result (real VM) — `node assemble_and_grade.mjs`

```
oracle fold == EXPECTED: true
7 sibling inputs in ONE transaction:
  t0_c0 bits[0,82)   accepted op=8,008,992  fits
  t0_c1 bits[82,193) accepted op=7,970,365  fits   (stitched consumer)
  t0_c2 bits[193,254) accepted op=4,404,757 fits
  t1_c0 bits[0,80)   accepted op=8,006,101  fits
  t1_c1 bits[80,191) accepted op=7,969,817  fits   (stitched consumer)
  t1_c2 bits[191,254) accepted op=4,547,399 fits
  fold              accepted op=2,779,345  fits
  -> TX VALID: true   max single-input op-cost 8.02M / 8.03M
FORGED handoff (tamper t0_c1's consumed state):       REJECTED (OP_VERIFY)
CROSS-THREAD (t0_c1 spends an unrelated token category): REJECTED (OP_VERIFY)
```

So the full vk_x — **~41M op-cost of work, 5× one input's budget** — runs in **one
transaction** (7 inputs, each its own budget), vs the chunked/shamir baseline's
**3 sequential transactions**. Forgery is caught by the stitch.

| | chunked/shamir | multi-input (this) |
|---|---|---|
| transactions | 3 (sequential) | **1** |
| block/mempool hops | 3 | **1** |
| inputs | 1/tx | 7 |
| total op-cost | ~13.2M | ~41M¹ |
| max single-input op | ~6.9M | ~8.0M |

¹ Higher total because this PoC runs term0 and term1 as **separate** scalar-mults
(2× the doublings), where shamir shares ONE doubling chain (Shamir/Straus). The
multi-input layout is orthogonal to that optimization — a Shamir/Straus arm could
be split the same way; the comparison isolates the *topology* change (sequential
txns → sibling inputs), not the algorithm. Total op-cost and bytes are not what
this buys; **transaction count / latency** is.

## Window sizes grow mid-term

Note c1 spans ~111 bits vs c0's ~82: as the accumulator `R` fills, the per-bit
`jacAdd` is taken on a non-identity point but the early bits hit the cheap
identity-add fast-path, so later windows fit more bits per budget. The planner
sizes each empirically on the real VM (like `../chunked/`'s `planChunk`).

## Files

| file | role |
|------|------|
| `_vkxmath.mjs` | reference Jacobian math (== noble), instance/VK constants, commit + push + VM helpers |
| `gen_vkx_multiinput.mjs` | plan + emit the arm chunks + fold; empirical window sizing; `probe` mode |
| `assemble_and_grade.mjs` | assemble all chunks into ONE multi-input tx; grade honest + forged on the real VM |
| `generated/` | emitted `t0_c*.cash`, `t1_c*.cash`, `fold.cash`, `manifest.json` |
| `arm_chunkA.cash` / `arm_chunkB.cash` | the original 2-input stitch PoC (hand-written) |
| `stitch_harness.mjs` | drives the 2-input PoC; honest + forged |
| `loose_measure.mjs` | per-chunk true op-cost measurement (window sizing) |

Run: `node gen_vkx_multiinput.mjs && node assemble_and_grade.mjs`

Run (from `multi-input/`): `node stitch_harness.mjs`. Toolchain paths are
env-configurable — set `CASHC` to the forked `cashc-cli.js` and `LIBAUTH_DIR` to
a `node_modules` dir with `@bitauth/libauth` (defaults assume sibling checkouts
`../cashscript-fork` and `../zk-verifier-bench`):

```
export CASHC=/path/to/cashscript-fork/packages/cashc/dist/cashc-cli.js
export LIBAUTH_DIR=/path/to/zk-verifier-bench/node_modules
```

## Full verifier (built + measured)

The complete verifier is built out — see **[FULL_VERIFIER.md](FULL_VERIFIER.md)**:
4 single-pair Miller arms + boundary fold + final-exp = 58 inputs, validated on
the real VM (valid accepts, tampered rejects), **738,977 bytes** (a dead heat
with the verifier.cash 738,099 B chunked record) collapsing **63 sequential
transactions → ~8 standard / 1 consensus**. Generators: `gen_miller_arm.mjs`,
`gen_finalexp_arm.mjs`; grader: `grade_full_verifier.mjs`; verdict:
`soundness_test.mjs`.

## Caveats / next steps

- The stitch primitive and the full per-chunk computation are validated; the one
  mechanical step left to put all 58 inputs in a single transaction is rebasing
  pair-local output indices into the global list (see FULL_VERIFIER.md).
- Soundness: the stitch binds a consumer's consumed state to the producer's
  published output **and** binds the **token thread** (category) across the
  stitched inputs — so a spender cannot satisfy the equality with a forged
  commitment carried by an input from an *unrelated* computation. This is the
  same role the CashToken category plays in Quantumroot's cross-input
  aggregation. The generator (`gen_vkx_multiinput.mjs`) emits, per chunk:
  `require(tx.outputs[stitchIdx].tokenCategory == thread)` (consumer),
  `require(tx.outputs[outIdx].tokenCategory == thread)` (producer), and the same
  for both terminals in the fold. `assemble_and_grade.mjs` includes a
  **cross-thread** attack (a stitched input spending an unrelated category with
  an otherwise-correct handoff) and confirms it is **rejected** — so the category
  binding is load-bearing, not decorative.
- Window sizing here is hand-tuned (~82 bits/chunk ≈ 8.0M op); a real generator
  would size empirically like `../chunked/`'s `planChunk`.
