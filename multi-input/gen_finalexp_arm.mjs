// Final-exponentiation chunk generator for the multi-input verifier.
//
// finalExp(boundary) == Fp12 ONE is the Groth16 verdict. It is an inherently
// SERIAL Fp12 op-DAG (cyc/mul/conj/frob/inv) — so it stays a chain — but here the
// chain is stitched into sibling inputs (depth collapse) instead of sequential
// transactions, and chunk 0 stitches to the boundary FOLD's output. The last
// chunk asserts result == ONE (no output token; the thread ends).
//
// Reuses the proven trace/liveness from chunked/pairing (the per-op Fp12 math ==
// noble, validated there). Differs only in the covenant: stitch + token-thread
// binding instead of the single-thread covIn/covOut.
//
//   node gen_finalexp_arm.mjs        plan + emit finalexp chunks
//   node gen_finalexp_arm.mjs probe  quick op-cost probe
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const PAIRING = join(here, '..', 'chunked', 'pairing');
const MM = pathToFileURL(join(PAIRING, '_millermath.mjs')).href;
const { Fp12, Fp2, bn254, vec, fnExtractor, f12limbs, decl, finalexpTrace } = await import(MM);
import { compile, unlockOf, commit as commitBin, tok, realVm, looseVm, P, OP_BUDGET } from './_vkxmath.mjs';

const GEN = join(here, 'generated');
mkdirSync(GEN, { recursive: true });

const ext = fnExtractor(join(here, '..', 'singleton', 'bn254', 'finalexp.cash'));
const FNS = ['addFp', 'subFp', 'mulFp', 'inverseFp', 'fp2Add', 'fp2Sub', 'fp2Neg', 'fp2Scale', 'fp2Mul', 'fp2Sqr', 'fp2MulXi', 'fp2Conj', 'fp2Inv', 'fp6Add', 'fp6Sub', 'fp6Neg', 'fp6MulByV', 'fp6Mul', 'fp6Inv', 'fp6FrobOdd', 'fp6FrobEven', 'fp6MulByFp2', 'fp12Mul', 'fp12Conj', 'fp12Inv', 'fp12Frob1', 'fp12Frob2', 'fp12Frob3', 'fp4Square', 'cycSqr'];
const PROLOGUE = FNS.map(ext).join('\n');
const OP_FN = { cyc: 'cycSqr', mul: 'fp12Mul', conj: 'fp12Conj', f1: 'fp12Frob1', f2: 'fp12Frob2', f3: 'fp12Frob3', inv: 'fp12Inv' };

// boundary for the committed instance (noble pairing product, no final-exp)
const g1 = (o) => bn254.G1.Point.fromAffine({ x: BigInt(o.x), y: BigInt(o.y) });
const g2 = (o) => bn254.G2.Point.fromAffine({ x: Fp2.fromBigTuple([BigInt(o.x.c0), BigInt(o.x.c1)]), y: Fp2.fromBigTuple([BigInt(o.y.c0), BigInt(o.y.c1)]) });
const vk = { alpha: g1(vec.vk.alpha), beta: g2(vec.vk.beta), gamma: g2(vec.vk.gamma), delta: g2(vec.vk.delta), ic: vec.vk.ic.map(g1) };
const proof = { a: g1(vec.proof.a), b: g2(vec.proof.b), c: g1(vec.proof.c) };
let vkx = vk.ic[0]; vec.publicInputs.map(BigInt).forEach((s, i) => { vkx = vkx.add(vk.ic[i + 1].multiply(s)); });
const boundaryVal = bn254.pairingBatch([{ g1: proof.a.negate(), g2: proof.b }, { g1: vk.alpha, g2: vk.beta }, { g1: vkx, g2: vk.gamma }, { g1: proof.c, g2: vk.delta }], false);

const { ops, liveAt, limbs12, resultId, result } = finalexpTrace(boundaryVal);
if (!Fp12.eql(result, Fp12.ONE)) throw new Error('traced finalExp(boundary) != ONE');
console.error(`final-exp: ${ops.length} ops; finalExp(boundary)==ONE OK`);

const vnames = (id) => Array.from({ length: 12 }, (_, j) => `w${id}_${j}`);
const ser = (names) => names.map((n) => `toPaddedBytes(${n}, 40)`).join(' + ');
const serRed = (names) => names.map((n) => `toPaddedBytes(${n} % P, 40)`).join(' + ');

// emit chunk ops [s,e). outIdx/stitchIdx index the multi-input layout (boundary fold
// output for chunk 0; previous chunk for later ones). last chunk asserts ==ONE.
function buildChunkSrc(s, e, outIdx, stitchIdx) {
  const liveIn = liveAt(s);
  const isLast = e === ops.length;
  const liveOut = isLast ? [] : liveAt(e);
  const inLimbs = liveIn.flatMap(limbs12).map((n) => ((BigInt(n) % P) + P) % P);
  const params = liveIn.flatMap(vnames);
  const name = new Map(); liveIn.forEach((id) => name.set(id, vnames(id)));
  let uid = 0; const fresh = () => Array.from({ length: 12 }, () => `t${uid++}`);
  const L = [];
  L.push('pragma cashscript ^0.13.0;');
  L.push(`// multi-input final-exp chunk ops [${s},${e}) out=${outIdx} stitch=${stitchIdx} final=${isLast}`);
  L.push('contract FinalExpChunk() {');
  L.push(PROLOGUE);
  L.push(`    function spend(${decl(params)}) {`);
  L.push('        int P = 21888242871839275222246405745257275088696311157297823662689037894645226208583;');
  L.push(`        bytes inc = hash256(${ser(liveIn.flatMap(vnames))});`);
  L.push('        bytes thread = tx.inputs[this.activeInputIndex].tokenCategory;');
  L.push('        require(tx.inputs[this.activeInputIndex].nftCommitment == inc);');
  if (stitchIdx != null) {
    L.push(`        require(tx.outputs[${stitchIdx}].nftCommitment == inc);`);
    L.push(`        require(tx.outputs[${stitchIdx}].tokenCategory == thread);`);
  }
  for (let i = s; i < e; i++) {
    const o = ops[i];
    const argVars = o.args.flatMap((a) => name.get(a));
    const out = fresh();
    L.push(`        (${decl(out)}) = ${OP_FN[o.op]}(${argVars.join(',')});`);
    name.set(o.id, out);
  }
  if (isLast) {
    const rv = name.get(resultId);
    L.push(`        require(${rv[0]} % P == 1); ` + Array.from({ length: 11 }, (_, j) => `require(${rv[j + 1]} % P == 0);`).join(' '));
  } else {
    const outNames = liveOut.flatMap((id) => name.get(id));
    L.push(`        require(tx.outputs[${outIdx}].nftCommitment == hash256(${serRed(outNames)}));`);
    L.push(`        require(tx.outputs[${outIdx}].tokenCategory == thread);`);
  }
  L.push('    }');
  L.push('}');
  const outLimbs = isLast ? [] : liveOut.flatMap(limbs12).map((n) => ((BigInt(n) % P) + P) % P);
  return { src: L.join('\n') + '\n', inLimbs, outLimbs, isLast };
}

const TMP = join(GEN, '_tmp_fe.cash');
function measure(src, inLimbs, outLimbs, outIdx, stitchIdx, isLast, vm = looseVm) {
  let redeem; try { writeFileSync(TMP, src); redeem = compile(TMP); } catch (e) { return { ok: false, op: Infinity, lockBytes: Infinity, err: String(e?.message ?? e) }; }
  const locking = Uint8Array.from([0x75, ...redeem]);
  const maxOut = isLast ? (stitchIdx ?? 0) : Math.max(outIdx, stitchIdx ?? 0);
  const outs = [];
  for (let i = 0; i <= maxOut; i++) outs.push({ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(new Uint8Array(32)) });
  if (!isLast) outs[outIdx] = { lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commitBin(outLimbs)) };
  if (stitchIdx != null) outs[stitchIdx] = { lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commitBin(inLimbs)) };
  if (outs.length === 0) outs.push({ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(new Uint8Array(32)) });
  const st = vm.evaluate({ inputIndex: 0, sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commitBin(inLimbs)) }],
    transaction: { version: 2, inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlockOf(inLimbs) }], outputs: outs, locktime: 0 } });
  const top = st.stack[st.stack.length - 1];
  return { ok: st.error === undefined && st.stack.length === 1 && top?.length === 1 && top[0] === 1, op: st.metrics.operationCost, lockBytes: locking.length, err: st.error ?? null };
}

if (process.argv[2] === 'probe') {
  for (const e of [1, 2, 3, 5]) { const c = buildChunkSrc(0, e, 0, null); const m = measure(c.src, c.inLimbs, c.outLimbs, 0, null, c.isLast); console.error(`ops[0,${e}): op=${m.op.toLocaleString()} fits=${m.op <= OP_BUDGET} lock=${m.lockBytes}B ${m.err ?? ''}`); }
  process.exit(0);
}

// plan. outBase = output index where final-exp chunks publish; stitch chunk0 to the
// boundary fold output (index passed via env, default 0 for standalone testing).
const OUT_BASE = Number(process.env.FE_OUT_BASE ?? 0);
const BOUNDARY_OUT = process.env.FE_BOUNDARY_OUT != null ? Number(process.env.FE_BOUNDARY_OUT) : null;
console.error(`planning final-exp chunks (outBase=${OUT_BASE}, boundaryStitch=${BOUNDARY_OUT})...`);
const chunks = []; let s = 0, k = 0;
while (s < ops.length) {
  const outIdx = OUT_BASE + k;
  const stitchIdx = k === 0 ? BOUNDARY_OUT : OUT_BASE + k - 1;
  let best = null;
  for (let e = s + 1; e <= ops.length; e++) {
    const c = buildChunkSrc(s, e, outIdx, stitchIdx);
    const m = measure(c.src, c.inLimbs, c.outLimbs, outIdx, stitchIdx, c.isLast);
    if (m.ok && m.op <= OP_BUDGET && m.lockBytes <= 10000) best = { hi: e, op: m.op, src: c.src, lockBytes: m.lockBytes, isLast: c.isLast };
    else break;
  }
  if (!best) throw new Error(`final-exp: no fitting window at op ${s}`);
  writeFileSync(join(GEN, `finalexp_c${k}.cash`), best.src);
  chunks.push({ k, opLo: s, opHi: best.hi, outIdx, stitchIdx, op: best.op, lockBytes: best.lockBytes, final: best.isLast });
  console.error(`  finalexp c${k}: ops[${s},${best.hi}) out=${outIdx} stitch=${stitchIdx} op=${best.op.toLocaleString()} lock=${best.lockBytes}B final=${best.isLast}`);
  s = best.hi; k++;
}
console.error(`final-exp: ${chunks.length} chunks, total op ${chunks.reduce((a, c) => a + c.op, 0).toLocaleString()}`);
writeFileSync(join(GEN, 'finalexp_manifest.json'), JSON.stringify({ numChunks: chunks.length, numOps: ops.length, outBase: OUT_BASE, boundaryStitch: BOUNDARY_OUT, chunks }, null, 2));
