# Four-pairing multi-input layout

The Groth16 boundary is a product of **four independent Miller outputs**:

```
e(-A,B) · e(α,β) · e(vk_x,γ) · e(C,δ)   (each an Fp12)  →  finalExp == 1
```

The four Miller loops share nothing until the product. This is the largest
latency win available to sibling-input decomposition.

## The structural choice (and an honest tradeoff)

`../chunked/pairing/` deliberately **batches** all four pairs into ONE shared
`f`: one `fp12Sqr` per NAF step folds all four pairs' lines into a single
running value. That *saves compute* (eliminates 3 of every 4 squarings) but
**forces a single serial chain** — the shared `f` can't be split across parallel
inputs. Result: ~59 Miller chunks + ~34 final-exp ≈ **93 sequential
transactions**.

The multi-input layout makes the opposite choice: run the four single-pair
Miller loops as **four parallel arms** of sibling inputs, then fold. Each arm
squares its *own* `f` (4× the squarings — more total compute), but the arms run
**concurrently**, each in its own per-input op-cost budget. This is the same
compute-vs-latency tradeoff as vk_x's shamir-vs-multiinput: the topology change
buys transaction count, not total op-cost.

## Measured / computed result (`four_pairing_layout.mjs`)

Per-arm chunking from the **measured** single-pair Miller cost
(~128.8M op-cost, `node singleton/bn254/miller.mjs`):

| | chunked (batched, serial) | multi-input (4 parallel arms) |
|---|---|---|
| Miller chunks | ~59 (one chain) | 4 × 17 = 68 (four parallel arms) |
| fold | — (batched f IS boundary) | 3 (Fp12 tree product) |
| final-exp | ~34 | 18 (serial, after fold) |
| total inputs/chunks | ~93 | 89 |
| **transactions** | **~93 sequential** | **~9 standard / 1 consensus** |

(Per-input scriptSig fits the 10,000-byte standard unlocking limit raised by
CHIP-2024-12 Pay to Script, active May 2026 — so standard-relayable on the 2026
network; bounded by the 100 KB standard tx size. See FULL_VERIFIER.md.)

The four arms stop being a serial chain — they become parallel inputs — so the
~93-step critical path collapses to the tx-size wall, not the dependency depth.

## What is proven on the real VM vs computed

- **PROVEN (real BCH 2026 VM):** the **fold** — a contract that reads the four
  independent Fp12 Miller terminals (each bound to an arm-terminal output by
  `nftCommitment` + `tokenCategory`), computes the tree product
  `(m1·m2)·(m3·m4)`, and asserts `== the golden boundary`. Accepts at ~2.5M
  op-cost (fits one input); a tampered Fp12 limb is rejected. The four Miller
  outputs used are genuinely distinct (verified non-degenerate vs noble), and
  the tree product equals the linear product.
- **COMPUTED (from measured per-op costs):** the per-arm chunk count
  (17 = ⌈128.8M / 8.03M⌉) and the transaction-count table. The per-arm Miller
  chunking itself is **mechanically identical** to the vk_x stitch already
  validated on-VM in `gen_vkx_multiinput.mjs` (state-threaded, stitched,
  thread-bound chunks) — only the carried state is larger (Fp12 `f` + G2 `R`
  instead of the G1 accumulator). Re-validating it would duplicate that proof;
  the fold is the genuinely new cross-input recombination, so that is what is
  validated here.

## Net

For the full verifier, sibling-input decomposition turns the chunked design's
**~93 sequential transactions** into **~9 standard-relay transactions (or a single
≤1 MB consensus transaction)**, by running the four independent pairings —
and the two vk_x scalar-mult terms — as parallel sibling inputs instead of one
serial covenant chain. Total op-cost rises modestly (lost shared-`fp12Sqr`
batching) and total bytes are similar; the win is **transaction count and
latency**, which for a multi-step on-chain verifier is the dominant user-facing
cost.

Run: `node four_pairing_layout.mjs` (env: `CASHC`, `LIBAUTH_DIR`).
