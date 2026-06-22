// Single-pair Miller arm generator for the multi-input layout.
//
// One Groth16 pairing e(P,Q) is a single-pair optimal-ate Miller loop. We expose
// it as a FLAT op list (sqr / double-line / add-line / postPrecompute) — exactly
// like chunked/pairing's batched version but for ONE pair — and slice it into
// budget-fitting chunks that thread state (f:12 + R:6 = 18 limbs) through stitched,
// thread-bound sibling inputs. Reuses the proven op primitives + fnExtractor from
// chunked/pairing/_millermath.mjs (the per-step math == noble, bit-for-bit).
//
//   node gen_miller_arm.mjs <pairIndex>   plan+emit arm chunks for pair j (0..3)
//   node gen_miller_arm.mjs probe         quick op-cost probe
import { writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const PAIRING = join(here, '..', 'chunked', 'pairing');
const MM = pathToFileURL(join(PAIRING, '_millermath.mjs')).href;
const {
  Fp, Fp2, Fp6, Fp12, ATE_NAF, pointDouble, pointAdd, postPrecompute,
  f12limbs, r6limbs, fnExtractor, pairsFor, vec, decl,
  OP_BUDGET, commit, singlePairMiller,
} = await import(MM);
// exact line math, lifted verbatim from chunked/pairing/_millermath.mjs (internal there)
const scalarFp2 = (x, k) => Fp2.fromBigTuple([Fp.mul(x.c0, k), Fp.mul(x.c1, k)]);
function mul034fn(f, o0, o3, o4) {
  const A = Fp6.create({ c0: Fp2.mul(f.c0.c0, o0), c1: Fp2.mul(f.c0.c1, o0), c2: Fp2.mul(f.c0.c2, o0) });
  const B = Fp6.mul01(f.c1, o3, o4);
  const E = Fp6.mul01(Fp6.add(f.c0, f.c1), Fp2.add(o0, o3), o4);
  return Fp12.create({ c0: Fp6.add(Fp6.mulByNonresidue(B), A), c1: Fp6.sub(E, Fp6.add(A, B)) });
}
const lineFnRef = (f, c0, c1, c2, Px, Py) => mul034fn(f, scalarFp2(c2, Py), scalarFp2(c1, Px), c0);
// our own real-VM measurer + commit helpers (thread-bound covenant, not the batched one)
import { compile, unlockOf, commit as commitBin2, tok, CATEGORY, realVm, P, OP_BUDGET as BUDGET } from './_vkxmath.mjs';

const GEN = join(here, 'generated');
mkdirSync(GEN, { recursive: true });
const MILLER_CASH = join(here, '..', 'singleton', 'bn254', 'miller.cash');
const ext = fnExtractor(MILLER_CASH);
const BASE_FNS = ['addFp', 'subFp', 'mulFp', 'fp2Add', 'fp2Sub', 'fp2Neg', 'fp2Mul', 'fp2Sqr', 'fp2Scale', 'fp2MulXi', 'fp2MulByB', 'fp2Half', 'fp6Add', 'fp6Sub', 'fp6MulByV', 'fp6Mul', 'fp6Mul01', 'fp12Sqr', 'mul034', 'line', 'pointDouble', 'pointAdd'];
const PP_FNS = ['fp2Conj', 'psi'];

// ---- single-pair op list (1-pair analog of millerBatchOps) ----
function singlePairOps(pair) {
  const Qa = pair.Q.toAffine(), Pa = pair.P.toAffine();
  const pd = { Qx: Qa.x, Qy: Qa.y, negQy: Fp2.neg(Qa.y), Px: Pa.x, Py: Pa.y };
  const ops = [];
  for (let k = 0; k < ATE_NAF.length; k++) {
    ops.push({ t: 'sqr' });
    ops.push({ t: 'dl' });
    if (ATE_NAF[k]) ops.push({ t: 'al', neg: ATE_NAF[k] === -1 });
  }
  ops.push({ t: 'pp' });
  // replay to get states before each op (line math == _millermath.mjs exactly)
  const states = []; let f = Fp12.ONE; let R = { x: pd.Qx, y: pd.Qy, z: Fp2.ONE };
  for (const op of ops) {
    states.push({ f, R });
    if (op.t === 'sqr') f = Fp12.sqr(f);
    else if (op.t === 'dl') { const d = pointDouble(R.x, R.y, R.z); R = d.R; f = lineFnRef(f, d.coeffs[0], d.coeffs[1], d.coeffs[2], pd.Px, pd.Py); }
    else if (op.t === 'al') { const a = pointAdd(R.x, R.y, R.z, pd.Qx, op.neg ? pd.negQy : pd.Qy); R = a.R; f = lineFnRef(f, a.coeffs[0], a.coeffs[1], a.coeffs[2], pd.Px, pd.Py); }
    else { const res = postPrecompute(f, R, pd.Qx, pd.Qy, pd.Px, pd.Py); f = res.f; R = res.R; }
  }
  states.push({ f, R });
  return { ops, states, pd, result: f };
}

const stateLimbs = (s) => [...f12limbs(s.f), ...r6limbs(s.R)];

// ---- emit one chunk over op window [lo,hi) with stitch+thread binding ----
// outIdx/stitchIdx are placeholders here; the assembler rewrites indices per layout.
// We generate with symbolic OUT/STITCH that the assembler patches, OR pass them in.
function genChunk(ops, pd, lo, hi, outIdx, stitchIdx, hasPP) {
  const fns = [...BASE_FNS, ...(hasPP ? PP_FNS : [])].map(ext).join('\n');
  const inF = Array.from({ length: 12 }, (_, i) => `f${i}`);
  const inR = ['Rxa', 'Rxb', 'Rya', 'Ryb', 'Rza', 'Rzb'];
  const STATE = [...inF, ...inR];
  const ser = (names) => names.map((n) => `toPaddedBytes(${n}, 40)`).join(' + ');
  const serRed = (names) => names.map((n) => `toPaddedBytes(${n} % P, 40)`).join(' + ');
  const L = [];
  L.push('pragma cashscript ^0.13.0;');
  L.push(`// single-pair Miller arm chunk: ops [${lo},${hi}); out=${outIdx} stitch=${stitchIdx}`);
  L.push('contract MillerArmChunk() {');
  L.push(fns);
  L.push(`    function spend(${decl(STATE)}) {`);
  L.push('        int P = 21888242871839275222246405745257275088696311157297823662689037894645226208583;');
  L.push(`        bytes inc = hash256(${ser(STATE)});`);
  L.push('        bytes thread = tx.inputs[this.activeInputIndex].tokenCategory;');
  L.push('        require(tx.inputs[this.activeInputIndex].nftCommitment == inc);');
  if (stitchIdx != null) {
    L.push(`        require(tx.outputs[${stitchIdx}].nftCommitment == inc);`);
    L.push(`        require(tx.outputs[${stitchIdx}].tokenCategory == thread);`);
  }
  // emit straight-line SSA ops
  let f = inF.slice(); let r = inR.slice(); let uid = 0;
  const fresh = (n) => Array.from({ length: n }, () => `v${uid++}`);
  const Pxe = `${pd.Px}`, Pye = `${pd.Py}`, Qxae = `${pd.Qx.c0}`, Qxbe = `${pd.Qx.c1}`, Qyae = `${pd.Qy.c0}`, Qybe = `${pd.Qy.c1}`;
  const negQ = pd.negQy;
  for (let i = lo; i < hi; i++) {
    const op = ops[i];
    if (op.t === 'sqr') { const sf = fresh(12); L.push(`        (${decl(sf)}) = fp12Sqr(${f.join(',')});`); f = sf; }
    else if (op.t === 'dl') {
      const dco = fresh(6), dr = fresh(6);
      L.push(`        (${decl([...dco, ...dr])}) = pointDouble(${r.join(',')});`); r = dr;
      const gf = fresh(12); L.push(`        (${decl(gf)}) = line(${f.join(',')}, ${dco.join(',')}, ${Pxe}, ${Pye});`); f = gf;
    } else if (op.t === 'al') {
      const Y = op.neg ? [`${negQ.c0}`, `${negQ.c1}`] : [Qyae, Qybe];
      const aco = fresh(6), ar = fresh(6);
      L.push(`        (${decl([...aco, ...ar])}) = pointAdd(${r.join(',')}, ${Qxae}, ${Qxbe}, ${Y[0]}, ${Y[1]});`); r = ar;
      const hf = fresh(12); L.push(`        (${decl(hf)}) = line(${f.join(',')}, ${aco.join(',')}, ${Pxe}, ${Pye});`); f = hf;
    } else { // pp
      const q1 = fresh(4); L.push(`        (${decl(q1)}) = psi(${Qxae}, ${Qxbe}, ${Qyae}, ${Qybe});`);
      const bco = fresh(6), br = fresh(6);
      L.push(`        (${decl([...bco, ...br])}) = pointAdd(${r.join(',')}, ${q1.join(',')});`); r = br;
      const iff = fresh(12); L.push(`        (${decl(iff)}) = line(${f.join(',')}, ${bco.join(',')}, ${Pxe}, ${Pye});`); f = iff;
      const q2 = fresh(4); L.push(`        (${decl(q2)}) = psi(${q1.join(',')});`);
      const q2ny = fresh(2); L.push(`        (${decl(q2ny)}) = fp2Neg(${q2[2]}, ${q2[3]}, 64);`);
      const cco = fresh(6), cr = fresh(6);
      L.push(`        (${decl([...cco, ...cr])}) = pointAdd(${r.join(',')}, ${q2[0]}, ${q2[1]}, ${q2ny[0]}, ${q2ny[1]});`); r = cr;
      const jf = fresh(12); L.push(`        (${decl(jf)}) = line(${f.join(',')}, ${cco.join(',')}, ${Pxe}, ${Pye});`); f = jf;
    }
  }
  const outNames = [...f, ...r];
  L.push(`        require(tx.outputs[${outIdx}].nftCommitment == hash256(${serRed(outNames)}));`);
  L.push(`        require(tx.outputs[${outIdx}].tokenCategory == thread);`);
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}

// ---- measure one chunk (loose for true op, then plan to budget) ----
import { looseVm } from './_vkxmath.mjs';
function measure(src, inLimbs, outLimbs, outIdx, stitchIdx, vm = looseVm) {
  let redeem; try { redeem = compile2(src); } catch (e) { return { ok: false, op: Infinity, lockBytes: Infinity, err: String(e?.message ?? e) }; }
  const locking = Uint8Array.from([0x75, ...redeem]);
  const maxOut = Math.max(outIdx, stitchIdx ?? 0);
  const outs = [];
  for (let i = 0; i <= maxOut; i++) outs.push({ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(new Uint8Array(32)) });
  outs[outIdx] = { lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commitBin2(outLimbs)) };
  if (stitchIdx != null) outs[stitchIdx] = { lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commitBin2(inLimbs)) };
  const st = vm.evaluate({ inputIndex: 0, sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commitBin2(inLimbs)) }],
    transaction: { version: 2, inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlockOf(inLimbs) }], outputs: outs, locktime: 0 } });
  const top = st.stack[st.stack.length - 1];
  return { ok: st.error === undefined && st.stack.length === 1 && top?.length === 1 && top[0] === 1, op: st.metrics.operationCost, lockBytes: locking.length, err: st.error ?? null };
}
const TMP = join(GEN, '_tmp_miller.cash');
function compile2(src) { writeFileSync(TMP, src); return compile(TMP); }

// ---- plan a single pair into chunks ----
function planPair(pairIdx, outBase) {
  const pairs = pairsFor(vec.publicInputs);
  const pair = pairs[pairIdx];
  const { ops, states, pd } = singlePairOps(pair);
  const chunks = []; let lo = 0, k = 0;
  while (lo < ops.length) {
    const outIdx = outBase + k, stitchIdx = k === 0 ? null : outBase + k - 1;
    const inLimbs = stateLimbs(states[lo]).map((n) => ((n % P) + P) % P);
    let best = null;
    // grow window; ops are coarse (~each op is sqr or line) so step 1
    for (let cand = lo + 1; cand <= ops.length; cand++) {
      const hasPP = ops.slice(lo, cand).some((o) => o.t === 'pp');
      const outLimbs = stateLimbs(states[cand]).map((n) => ((n % P) + P) % P);
      const src = genChunk(ops, pd, lo, cand, outIdx, stitchIdx, hasPP);
      const m = measure(src, inLimbs, outLimbs, outIdx, stitchIdx);
      if (m.ok && m.op <= BUDGET && m.lockBytes <= 10000) best = { hi: cand, op: m.op, src, lockBytes: m.lockBytes, outLimbs };
      else break;
    }
    if (!best) throw new Error(`pair${pairIdx}: no fitting window at op ${lo}`);
    writeFileSync(join(GEN, `miller${pairIdx}_c${k}.cash`), best.src);
    chunks.push({ pairIdx, k, opLo: lo, opHi: best.hi, outIdx, stitchIdx, op: best.op, lockBytes: best.lockBytes });
    console.error(`  pair${pairIdx} c${k}: ops[${lo},${best.hi}) out=${outIdx} op=${best.op.toLocaleString()} lock=${best.lockBytes}B`);
    lo = best.hi; k++;
  }
  return chunks;
}

if (process.argv[2] === 'probe') {
  const pairs = pairsFor(vec.publicInputs);
  const { ops, states, pd } = singlePairOps(pairs[0]);
  console.error(`single-pair: ${ops.length} ops`);
  for (const [a, b] of [[0, 2], [0, 4], [0, 6]]) {
    const inL = stateLimbs(states[a]).map((n) => ((n % P) + P) % P);
    const outL = stateLimbs(states[b]).map((n) => ((n % P) + P) % P);
    const m = measure(genChunk(ops, pd, a, b, 0, null, false), inL, outL, 0, null);
    console.error(`ops[${a},${b}): op=${m.op.toLocaleString()} fits=${m.op <= BUDGET} lock=${m.lockBytes}B ${m.err ?? ''}`);
  }
  process.exit(0);
}

const pairIdx = Number(process.argv[2] ?? 0);
console.error(`planning single-pair Miller arm for pair ${pairIdx}...`);
const chunks = planPair(pairIdx, 0);
const totalOp = chunks.reduce((s, c) => s + c.op, 0);
console.error(`pair ${pairIdx}: ${chunks.length} chunks, total op ${totalOp.toLocaleString()}`);
writeFileSync(join(GEN, `miller${pairIdx}_manifest.json`), JSON.stringify({ pairIdx, numChunks: chunks.length, chunks }, null, 2));
