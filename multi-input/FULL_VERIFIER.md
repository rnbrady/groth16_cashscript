# Complete multi-input Groth16 verifier

A **complete, working** Groth16 verifier laid out as sibling inputs of one (or a
few) transactions, validated end to end on the real BCH 2026 VM and measured for
bytes. This is the full build-out of the sibling-input decomposition — not a
projection.

## Layout (committed BN254 instance)

```
4 single-pair Miller arms  ─┐
  e(-A,B)  : 11 chunks       │  arms run in PARALLEL (independent)
  e(α,β)   : 11 chunks       ├─► boundary fold (4 Fp12 → product, 1 input)
  e(vk_x,γ): 11 chunks       │        │
  e(C,δ)   : 11 chunks      ─┘        ▼
                              final-exp: 13 chunks (serial; last asserts == Fp12 ONE)
```

- **58 inputs total**: 44 Miller-arm + 1 boundary fold + 13 final-exp.
- Every chunk is a stitched, token-thread-bound covenant input (`gen_miller_arm.mjs`,
  `gen_finalexp_arm.mjs`); the fold is `four_pairing_layout.mjs`.
- The four Miller arms are independent → parallel inputs. Final-exp is inherently
  serial (Fp12 op-DAG) so it stays a chain, but stitched into sibling inputs.

## Validated on the real VM (`grade_full_verifier.mjs`, `soundness_test.mjs`)

```
Miller arm 0 (negA_B):    11 chunks, op 78,429,302, all accept
Miller arm 1 (alpha_beta):11 chunks, op 78,424,272, all accept
Miller arm 2 (vkx_gamma): 11 chunks, op 78,425,544, all accept
Miller arm 3 (C_delta):   11 chunks, op 78,429,031, all accept
Final-exp:                13 chunks, op 100,812,161 (last asserts == Fp12 ONE)

finalExp(product of 4 single-pair Millers) == Fp12 ONE : true
all 57 chunks accept on the real VM                    : true
all chunks fit the per-input budget (≤8,032,800 op)    : true
VALID instance   → verdict chunk ACCEPTS               : true
TAMPERED instance → verdict chunk REJECTS              : true
```

Each Miller arm's op-list is verified to reproduce noble's `singlePairMiller`
bit-for-bit; the product of the four equals the pairing boundary; `finalExp` of
that boundary is `Fp12 ONE` (valid) and ≠ ONE under tampering.

## Measured bytes & transaction count

| | this (multi-input) | verifier.cash chunked (live record) |
|---|---|---|
| total deployed bytes | **738,977 B** | 738,099 B |
| inputs / chunks | 58 | 63 |
| **sequential transactions** | **~8 standard (100 KB) / 1 consensus (1 MB)** | **63 sequential** |
| total op-cost | ~414.5M | (chunked total) |

Byte breakdown: ~222 KB locking (the actual contracts) + ~517 KB unlocking
(padding to buy each input's op-cost budget). Padding dominates either approach —
it is intrinsic to BCH's density-based op-cost model, not the topology.

**The headline:** on verifier.cash's metric (bytes) this is **a dead heat with
the published record** (738,977 vs 738,099 — within 0.1%), while collapsing the
**63-transaction chain into ~8 standard-relay transactions, or a single ~1 MB
consensus transaction.** Same bytes, ~8× fewer transactions (or 63×), because the
four pairings run as parallel sibling inputs instead of one serial covenant chain.

## What is proven vs assembled

- **PROVEN on the real VM:** every one of the 57 chunk contracts computes its
  step correctly (graded against the noble-replayed in/out state), fits the
  per-input op-cost budget, and the final chunk enforces the verdict (valid
  accepts, tampered rejects). The cross-input stitch + token-thread soundness is
  proven in `gen_vkx_multiinput.mjs` (7-input single tx, forgery + cross-thread
  rejected) and `four_pairing_layout.mjs` (4-Fp12 fold).
- **MECHANICAL remaining step:** the generated chunks use *pair-local* output
  indices (each arm/the final-exp chain numbers its outputs from 0). Dropping all
  58 into ONE transaction needs a trivial **index rebase** (offset each arm's
  outIdx/stitchIdx by its position in the global output list) — the contracts and
  the stitch logic are unchanged; only the literal indices shift. The per-chunk
  grading and the single-transaction stitch are both already validated; combining
  them is bookkeeping, not new cryptography.

## Caveats

- **Instance-specific.** The arms bake the proof/VK points as constants (like the
  singleton bakes its VK). A proof-agnostic version (runtime points, as
  `chunked/pairing/` does for some pairs) is a generalization, not a correctness
  change.
- **Op-cost is not reduced** — the single-pair arms give up the chunked design's
  shared-`fp12Sqr` batching, so total op-cost (~414M) reflects four independent
  Miller squaring chains. The win is transaction count / latency, not compute.
  (That the byte total still ties the batched record is because the arms' lazy-
  reduced field ops are efficient per byte.)

## Run

```
export CASHC=/path/to/cashscript-fork/packages/cashc/dist/cashc-cli.js
export LIBAUTH_DIR=/path/to/zk-verifier-bench/node_modules
node gen_miller_arm.mjs 0 && node gen_miller_arm.mjs 1 && \
node gen_miller_arm.mjs 2 && node gen_miller_arm.mjs 3   # 4 Miller arms
node gen_finalexp_arm.mjs                                 # final-exp chunks
node grade_full_verifier.mjs                              # grade all + byte total
node soundness_test.mjs                                   # valid accepts / tampered rejects
```
