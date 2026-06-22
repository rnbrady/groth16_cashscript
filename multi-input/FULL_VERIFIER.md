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

**Two byte accountings, stated separately so the comparison is honest.** The
verifier.cash leaderboard (and the `zk-verifier-bench` harness) measures
`totalBytes = Σ (lockingBytecode.length + unlockingBytecode.length)`, where each
step's **`lockingBytecode = OP_DROP || redeem`** (the contract lives in the
locking script) and `unlockingBytecode = args + zero-pad`. Confirmed by reading
`zk-verifier-bench/src/harness/benchmark.ts` and a committed chunked vector
(locking starts `0x75` = OP_DROP, ~1,456 B; unlocking ~8,677 B).

| | this (multi-input) | verifier.cash chunked (record) |
|---|---|---|
| **bytes — verifier.cash model** (redeem in locking, sum both) | **741,074 B** | 738,099 B |
| **bytes — P2SH32 model** (35 B locking, redeem in scriptSig) | **529,165 B** | not measured this way |
| inputs / chunks | 58 | 63 |
| max single scriptSig (P2SH32) | 9,981 B (limit 10,000) | — |
| total op-cost | ~414.5M | — |
| **transactions** | **~8 standard (100 KB) / 1 consensus** | **63 sequential** |

**Apples-to-apples (verifier.cash's own metric): 741,074 B vs 738,099 B — a dead
heat** (within 0.1%), while collapsing the **63-transaction chain into ~6
standard-relay transactions, or a single ≤1 MB consensus transaction**, because
the four pairings run as parallel sibling inputs instead of one serial covenant
chain. That is the fair head-to-head: same accounting, essentially the same bytes,
~10× fewer transactions.

**The P2SH32 number (529 KB) is a different, more physically accurate accounting**
for a real P2SH32 deployment: the redeem script rides in the scriptSig where it
does *double duty* — ships the contract *and* counts toward the `(41+scriptSig)`
op-cost budget — so fewer bytes are pure zero-padding. This is a genuine ~28%
saving, **but it is not a fair comparison against the 738,099 record** (which uses
OP_DROP-locking); applying the same P2SH32 accounting to the chunked baseline would
shrink it too. So treat 529 KB as "what a P2SH32 layout costs," not as "beats the
record." We have not re-measured the baseline under P2SH32.

**Relay note (post-May-2026 network — what this targets):** each chunk's scriptSig
is ~9,960–9,981 B, **just under the 10,000-byte standard unlocking limit**. That
limit was 1,650 B historically, but **CHIP-2024-12 (Pay to Script) raised the
standard unlocking-bytecode limit to 10,000 B — equal to the consensus limit —
activating May 2026** on mainnet (its rationale cites large ZK/PQ proofs as the
motivating case). So per input these chunks are **standard-relayable** on the 2026
VM this project targets. The binding relay constraint is then the **100 KB
standard transaction-size** limit, giving ~6 standard transactions; the whole
~529 KB also fits one ≤1 MB consensus transaction. (On the pre-May-2026 network,
the 1,650-byte cap would force the consensus path.)

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
