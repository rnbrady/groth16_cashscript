// brady: the STANDARD-RELAYABLE hybrid verifier.
//
// The intratx verifier (../intratx) is ONE non-standard transaction: every chunk
// forward-checks tx.inputs[i+1] (in-transaction introspection), so the 63-input
// chain is inseparable. To deploy as a sequence of STANDARD (<=100,000 B)
// transactions, brady keeps the cheap intra-tx forward-check WITHIN each band of
// inputs, and adds a covenant (NFT hash256) handoff BETWEEN bands:
//
//   band k (one standard tx):
//     [first input]  covenant-CHECK: hash256(inBlob) == this input's spent NFT     (genesis of band, k>0)
//     [middle inputs] forward-check: outBlob == tx.inputs[i+1].unlockingBytecode    (unchanged intratx)
//     [last input]   covenant-COMMIT: tx.outputs[0].nftCommitment == hash256(outBlob)  (band boundary, k<last)
//
// So within a band it is intratx (no hashing); only at the 5 band boundaries does
// it pay one hash256-in + one hash256-out, exactly the chunked-covenant handoff.
//
// This module post-processes the intratx-transformed chunk source (from
// ../intratx/transform.mjs transformChunk) to swap the epilogue/prologue for the
// boundary inputs. The arithmetic body is untouched.
import { transformChunk, headerSize } from '../intratx/transform.mjs';

const PRIME = '21888242871839275222246405745257275088696311157297823662689037894645226208583';

// Identify the lines transformChunk emits so we can splice boundary variants.
const FWD_RE = /^\s*require\(.*tx\.inputs\[this\.activeInputIndex \+ 1\]\.unlockingBytecode.*\);\s*$/;
const OUTBLOB_RE = /^\s*bytes outBlob = (.+);\s*$/;

/**
 * Produce a brady chunk for one input.
 *   src, cfg          same as intratx transformChunk (W, prime, forward)
 *   role.bandFirst    true -> prepend covenant-check (hash256(inBlob) == spent NFT)
 *   role.bandLast     true -> replace forward-check with covenant-commit
 *                            (tx.outputs[0].nftCommitment == hash256(outBlob))
 * The cfg.forward passed in is the INTRA-band forward (null for the band-last input,
 * since its successor lives in the next tx; brady supplies the covenant instead).
 */
export function transformBrady(src, cfg, role) {
  // For a band-last input we want transformChunk to still REBUILD outBlob but NOT
  // emit a tx.inputs[i+1] forward-check (its successor is in another tx). Passing
  // forward=null makes transformChunk emit `require(outBlob.length == N)` (the
  // "stage-final" tautology) — we then replace THAT with the covenant-commit.
  const baseForward = role.bandLast ? null : cfg.forward;
  const t = transformChunk(src, { ...cfg, forward: baseForward });
  let lines = t.src.split('\n');

  // ---- band-last: replace the tautological length-check with covenant-commit ----
  if (role.bandLast && t.outNames) {
    // find the `bytes outBlob = ...;` line, then the line after it (the tautology).
    const obIdx = lines.findIndex((l) => OUTBLOB_RE.test(l));
    if (obIdx < 0) throw new Error('brady: no outBlob to commit for band-last input');
    // remove any `require(outBlob.length == N);` immediately following
    let j = obIdx + 1;
    if (/require\(outBlob\.length ==/.test(lines[j] ?? '')) lines.splice(j, 1);
    // insert covenant-commit: output[0] NFT commits hash256(outBlob)
    lines.splice(obIdx + 1, 0,
      `        require(tx.outputs[0].nftCommitment == hash256(outBlob)); // band-boundary covenant out`);
  }

  // ---- band-first (k>0): prepend covenant-check binding inBlob to the spent NFT ----
  if (role.bandFirst) {
    const sigIdx = lines.findIndex((l) => /function spend\(/.test(l));
    if (sigIdx < 0) throw new Error('brady: no spend()');
    lines.splice(sigIdx + 1, 0,
      `        require(tx.inputs[this.activeInputIndex].nftCommitment == hash256(inBlob)); // band-boundary covenant in`);
  }

  return { ...t, src: lines.join('\n'), bandFirst: !!role.bandFirst, bandLast: !!role.bandLast };
}
