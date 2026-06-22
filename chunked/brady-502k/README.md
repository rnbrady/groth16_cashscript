# brady-502k — the standard-relayable Groth16 verifier

A third deployment of the BN254 Groth16 verifier, alongside the sequential
covenant ([`../pairing`](../pairing)) and the single-transaction
[`../intratx`](../intratx). brady is the **standard-relayable** form: the whole
verifier deployed as a **sequence of standard (≤100,000 B) transactions**.

## Why brady exists

`../intratx` packs all 63 inputs into **one** transaction by having every input
forward-check `tx.inputs[i+1].unlockingBytecode` — but that introspection only
resolves *within a single transaction*, so the chain is inseparable and the
transaction (~502 KB) **exceeds the 100,000-byte standard relay limit**. It is
valid (< 1 MB consensus) but **non-standard**: it must be handed to a miner, not
relayed through the p2p network.

brady keeps intratx's cheap in-transaction links *within* a band of inputs, and
adds a covenant handoff *between* bands so the chain can be cut at standard-tx
boundaries:

```
band k  (one standard tx, ≤100 KB):
  [first input]  covenant-CHECK:  hash256(inBlob) == this input's spent NFT   (k>0)
  [middle inputs] forward-check:  outBlob == tx.inputs[i+1].unlockingBytecode  (intratx)
  [last input]   covenant-COMMIT: tx.outputs[0].nftCommitment == hash256(outBlob)  (k<last)
```

So it is a **hybrid: intra-tx cooperation within a band, inter-tx covenant
between bands.** Within a band there is no hashing (intratx); only at the 5 band
boundaries does it pay one `hash256`-out + one `hash256`-in — the same handoff as
the sequential covenant build, but only ~5 times instead of ~62.

## Result (real BCH 2026 VM, committed BN254 instance)

The full Groth16 verifier (G2 input validation → vk_x → batched 4-pair Miller →
final exponentiation → assert == 1), as the inputs of **6 standard transactions**:

```
63 inputs in 6 STANDARD txns, accepted=true fits=true
totalBytes=498,285  totalOp=393,957,700  maxLock=23  maxUnlock=9,876
  band 0: 17 inputs, tx 94,281 B  ≤100KB
  band 1: 11 inputs, tx 99,085 B  ≤100KB
  band 2: 10 inputs, tx 94,661 B  ≤100KB
  band 3: 12 inputs, tx 97,280 B  ≤100KB
  band 4: 11 inputs, tx 99,118 B  ≤100KB
  band 5:  2 inputs, tx 15,720 B  ≤100KB
invalid runs rejected: true,true
```

- **6 standard transactions, 498,285 B total (under 500 KB)** — every tx ≤100 KB,
  **relayable through the normal p2p network**, no miner submission needed.
- **Sound:** tampering any input's blob fails its band (the predecessor's
  forward-check or the covenant check).
- **Runtime-general:** a second proof under the same VK verifies through the same
  scripts (498,227 B).
- Carries the lazy-`fp2Mul`/`fp2Sqr` reduction plus a tuned op-cost padding margin
  (32 B, down from the intratx default 96) — the two together bring it under 500 KB.

The trade-off vs the single non-standard intratx tx: **5 sequential block/mempool
hops** (one per band boundary) — the price of standard relay.

## Files

- `transform_brady.mjs` — wraps `../intratx/transform.mjs`'s `transformChunk` to
  produce the band-boundary variants: band-first gains a covenant-check prologue,
  band-last replaces its forward-check with a covenant-commit epilogue. The
  arithmetic body is untouched.
- `build_vectors.mjs` — measures each input's op-cost, greedily packs the chain
  into the fewest ≤100 KB bands, compiles boundary inputs with covenant ops, and
  evaluates every input in its band's own transaction on the real VM. Writes
  `verifier/src/bch/groth16-brady-vectors.json`.

Run (after `../pairing` generators have populated `generated/`):

```
node build_vectors.mjs
```

Paths in `build_vectors.mjs` follow the repo convention (`C:/Users/mathi/...`);
repoint to your local `cashscript` fork + `verifier` checkout to run.
