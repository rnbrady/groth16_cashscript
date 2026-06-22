// Generator: lay the full vk_x = IC0 + in0*IC1 + in1*IC2 out as SIBLING INPUTS
// of ONE transaction, stitched by cross-input introspection, replacing the
// 3-sequential-transaction chunked/shamir baseline.
//
// DAG:
//   term0 = in0*IC1   (serial: chunks t0c0 -> t0c1 -> ... internally stitched)
//   term1 = in1*IC2   (serial: chunks t1c0 -> ...)            term0 || term1 independent
//   fold  = IC0 + term0 + term1, jacToAffine, == EXPECTED
//
// LAYOUT (one tx): [t0 chunks...] [t1 chunks...] [fold]. Each chunk is one input
// with its own ~8.03M op-cost budget. Within a term, chunk k+1 stitches to chunk
// k via the shared output[k] blackboard (consumer asserts output[i].nftCommitment
// == hash(its incoming state)). The fold input reads both terms' terminal outputs.
//
//   node gen_vkx_multiinput.mjs          plan + emit + grade
//   node gen_vkx_multiinput.mjs probe    quick op-cost probe at a few window sizes
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  P, OP_BUDGET, TARGET_UNLOCK, INPUT0, INPUT1, IC0, IC1, IC2, EXPECTED,
  jacAdd, jacToAffine, armRange, commit, compile, unlockOf, le40,
  looseVm, realVm, tok, CATEGORY, binToHex,
} from './_vkxmath.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
mkdirSync(GEN, { recursive: true });
const PRIME = '21888242871839275222246405745257275088696311157297823662689037894645226208583';

// ---- shared reusable-function prologue (the EC Jacobian group law) ----
const PROLOGUE = `    internal function addFp(int x, int y) returns (int) { return (x + y) % ${PRIME}; }
    internal function subFp(int x, int y) returns (int) { return (x - y + ${PRIME}) % ${PRIME}; }
    internal function mulFp(int x, int y) returns (int) { return (x * y) % ${PRIME}; }
    internal function sqrFp(int x) returns (int) { return (x * x) % ${PRIME}; }
    internal function jacDouble(int x, int y, int z) returns (int, int, int) {
        int a=sqrFp(x); int b=sqrFp(y); int c=sqrFp(b);
        int d=mulFp(2,subFp(subFp(sqrFp(addFp(x,b)),a),c)); int e=mulFp(3,a); int f=sqrFp(e);
        int nx=subFp(f,mulFp(2,d)); int ny=subFp(mulFp(e,subFp(d,nx)),mulFp(8,c)); int nz=mulFp(2,mulFp(y,z));
        return nx,ny,nz;
    }
    internal function jacAdd(int aX,int aY,int aZ,int bX,int bY,int bZ) returns (int,int,int) {
        int rx=bX; int ry=bY; int rz=bZ;
        if (aZ != 0) {
            int z1z1=sqrFp(aZ); int z2z2=sqrFp(bZ); int u1=mulFp(aX,z2z2); int u2=mulFp(bX,z1z1);
            int s1=mulFp(mulFp(aY,bZ),z2z2); int s2=mulFp(mulFp(bY,aZ),z1z1);
            if (u1==u2 && s1==s2) {
                int da=sqrFp(aX); int db=sqrFp(aY); int dc=sqrFp(db);
                int dd=mulFp(2,subFp(subFp(sqrFp(addFp(aX,db)),da),dc)); int de=mulFp(3,da); int df=sqrFp(de);
                int dnx=subFp(df,mulFp(2,dd)); int dny=subFp(mulFp(de,subFp(dd,dnx)),mulFp(8,dc)); int dnz=mulFp(2,mulFp(aY,aZ));
                rx=dnx; ry=dny; rz=dnz;
            } else {
                int h=subFp(u2,u1); int i2=sqrFp(mulFp(2,h)); int jj=mulFp(h,i2); int rr=mulFp(2,subFp(s2,s1)); int vv=mulFp(u1,i2);
                int anx=subFp(subFp(sqrFp(rr),jj),mulFp(2,vv)); int any=subFp(mulFp(rr,subFp(vv,anx)),mulFp(2,mulFp(s1,jj)));
                int anz=mulFp(subFp(subFp(sqrFp(addFp(aZ,bZ)),z1z1),z2z2),h);
                rx=anx; ry=any; rz=anz;
            }
        }
        return rx,ry,rz;
    }`;

const ser = (names) => names.map((n) => `toPaddedBytes(${n}, 40)`).join(' + ');
const serRed = (names) => names.map((n) => `toPaddedBytes(${n} % P, 40)`).join(' + ');
const STATE = ['rX', 'rY', 'rZ', 'cX', 'cY', 'cZ', 'scalar'];

// An arm chunk over bit window [lo,hi). `selfIdx`/`outIdx` are the input/output
// indices this chunk occupies in the multi-input tx. `stitchIdx`: if set, the
// chunk additionally requires output[stitchIdx].nftCommitment == hash(incoming)
// — binding its consumed state to the producer chunk's published result.
function genArmChunk(lo, hi, outIdx, stitchIdx) {
  const L = [];
  L.push('pragma cashscript ^0.13.0;');
  L.push(`// vk_x arm chunk: bits [${lo},${hi}); output index ${outIdx}${stitchIdx != null ? `; stitches to output[${stitchIdx}]` : ' (term head)'}.`);
  L.push('contract VkxArm() {');
  L.push(PROLOGUE);
  L.push(`    function spend(${STATE.map((n) => `int ${n}`).join(', ')}) {`);
  L.push(`        bytes inc = hash256(${ser(STATE)});`);
  L.push('        bytes thread = tx.inputs[this.activeInputIndex].tokenCategory;');
  L.push('        require(tx.inputs[this.activeInputIndex].nftCommitment == inc);');
  if (stitchIdx != null) {
    L.push(`        // stitch: what we consume == the producer's published result, AND the`);
    L.push(`        // producer output is on the SAME token thread (so it can't be a forged`);
    L.push(`        // commitment from an unrelated input the spender slotted at this index).`);
    L.push(`        require(tx.outputs[${stitchIdx}].nftCommitment == inc);`);
    L.push(`        require(tx.outputs[${stitchIdx}].tokenCategory == thread);`);
  }
  L.push(`        for (int i = ${lo}; i < ${hi}; i = i + 1) {`);
  L.push('            if (((scalar >> i) % 2) == 1) { (int ax,int ay,int az)=jacAdd(rX,rY,rZ,cX,cY,cZ); rX=ax; rY=ay; rZ=az; }');
  L.push('            if (cZ != 0 && cY != 0) { (int dx,int dy,int dz)=jacDouble(cX,cY,cZ); cX=dx; cY=dy; cZ=dz; }');
  L.push('        }');
  L.push(`        int P = ${PRIME};`);
  L.push(`        require(tx.outputs[${outIdx}].nftCommitment == hash256(${serRed(STATE)}));`);
  L.push(`        require(tx.outputs[${outIdx}].tokenCategory == thread); // our published result stays on-thread`);
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}

// The fold chunk: reads term0's terminal result (output[t0Idx]) and term1's
// (output[t1Idx]) by re-supplying both terminal states (bound to those outputs),
// computes IC0 + term0 + term1, jacToAffine, asserts == EXPECTED affine point.
function genFoldChunk(t0Idx, t1Idx) {
  const T0 = ['a0rX', 'a0rY', 'a0rZ', 'a0cX', 'a0cY', 'a0cZ', 'a0s'];
  const T1 = ['a1rX', 'a1rY', 'a1rZ', 'a1cX', 'a1cY', 'a1cZ', 'a1s'];
  const L = [];
  L.push('pragma cashscript ^0.13.0;');
  L.push(`// vk_x FOLD: IC0 + term0(out[${t0Idx}]) + term1(out[${t1Idx}]) -> affine == EXPECTED.`);
  L.push('contract VkxFold() {');
  L.push(PROLOGUE);
  L.push('    internal function inverseFp(int x) returns (int) {');
  L.push(`        int p = ${PRIME}; int q = p - 2; int result = 1; int current = x % p;`);
  L.push('        for (int i = 0; i < 254; i = i + 1) { if (((q >> i) % 2) == 1) { result = (result * current) % p; } current = (current * current) % p; }');
  L.push('        return result;');
  L.push('    }');
  L.push(`    function spend(${[...T0, ...T1].map((n) => `int ${n}`).join(', ')}) {`);
  // bind both terminal results to their producer outputs, on the SAME token thread
  // as this fold input (so neither terminal can be a forged commitment from an
  // unrelated input slotted at t0Idx/t1Idx).
  L.push('        bytes thread = tx.inputs[this.activeInputIndex].tokenCategory;');
  L.push(`        require(tx.outputs[${t0Idx}].nftCommitment == hash256(${ser(T0)}));`);
  L.push(`        require(tx.outputs[${t0Idx}].tokenCategory == thread);`);
  L.push(`        require(tx.outputs[${t1Idx}].nftCommitment == hash256(${ser(T1)}));`);
  L.push(`        require(tx.outputs[${t1Idx}].tokenCategory == thread);`);
  // IC0 + term0 (jacAdd: IC0 affine z=1, plus term0 jacobian)
  L.push(`        (int x1,int y1,int z1) = jacAdd(${IC0[0]}, ${IC0[1]}, 1, a0rX, a0rY, a0rZ);`);
  L.push('        (int vx,int vy,int vz) = jacAdd(x1, y1, z1, a1rX, a1rY, a1rZ);');
  // jacToAffine
  L.push('        int zi = inverseFp(vz); int zi2 = mulFp(zi, zi); int zi3 = mulFp(zi2, zi);');
  L.push(`        require(mulFp(vx, zi2) == ${EXPECTED[0]});`);
  L.push(`        require(mulFp(vy, zi3) == ${EXPECTED[1]});`);
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}

// ---- measurement: one chunk in isolation, on the loose VM (true op-cost) ----
// We measure a single covenant input with a synthetic spent UTXO == hash(in) and
// the relevant outputs present, so the introspection resolves. For arm chunks the
// stitch output is set to the same incoming hash (honest), output[outIdx]=hash(out).
function measureArm(src, inState, outState, outIdx, stitchIdx, vm = looseVm) {
  let redeem; try { redeem = compile2(src); } catch (e) { return { ok: false, op: Infinity, lockBytes: Infinity, err: String(e?.message ?? e) }; }
  const locking = Uint8Array.from([0x75, ...redeem]);
  const inC = commit(inState);
  const outs = [];
  const maxOut = Math.max(outIdx, stitchIdx ?? 0, 0);
  for (let i = 0; i <= maxOut; i++) outs.push({ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(new Uint8Array(32)) });
  outs[outIdx] = { lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commit(outState)) };
  if (stitchIdx != null) outs[stitchIdx] = { lockingBytecode: locking, valueSatoshis: 1000n, token: tok(inC) };
  const unlocking = unlockOf(inState);
  const st = vm.evaluate({ inputIndex: 0, sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(inC) }],
    transaction: { version: 2, inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }], outputs: outs, locktime: 0 } });
  const top = st.stack[st.stack.length - 1];
  return { ok: st.error === undefined && st.stack.length === 1 && top?.length === 1 && top[0] === 1, op: st.metrics.operationCost, lockBytes: locking.length, err: st.error ?? null };
}
// compile from a source string (write temp + compile)
const TMP = join(GEN, '_tmp.cash');
function compile2(src) { writeFileSync(TMP, src); return compile(TMP); }

// ---- plan one term into budget-fitting windows ----
// outIdxBase: the output index of this term's FIRST chunk. Each chunk k writes
// output[outIdxBase+k] and (for k>0) stitches to output[outIdxBase+k-1].
function planTerm(scalar, base, bits, outIdxBase, label) {
  const s0 = [0n, 1n, 0n, base[0], base[1], 1n, scalar];
  const chunks = []; let lo = 0, k = 0, state = s0;
  while (lo < bits) {
    const outIdx = outIdxBase + k;
    const stitchIdx = k === 0 ? null : outIdxBase + k - 1;
    // grow window until budget exceeded; step ~6 bits to keep compiles cheap
    let hi = Math.min(bits, lo + 1), best = null;
    for (let cand = lo + 1; cand <= bits; cand++) {
      const outState = armRange(state, lo, cand);
      const src = genArmChunk(lo, cand, outIdx, stitchIdx);
      const m = measureArm(src, state, outState, outIdx, stitchIdx);
      if (m.ok && m.op <= OP_BUDGET && m.lockBytes <= 10000) { best = { hi: cand, op: m.op, outState, src, lockBytes: m.lockBytes }; }
      else break;
      if (cand - lo > 120) break; // safety
    }
    if (!best) throw new Error(`${label}: no fitting window at bit ${lo}`);
    writeFileSync(join(GEN, `${label}_c${k}.cash`), best.src);
    chunks.push({ label, k, lo, hi: best.hi, outIdx, stitchIdx, op: best.op, lockBytes: best.lockBytes, inState: state, outState: best.outState });
    console.error(`  ${label} c${k}: bits[${lo},${best.hi}) out=${outIdx} stitch=${stitchIdx} op=${best.op.toLocaleString()} lock=${best.lockBytes}B`);
    state = best.outState; lo = best.hi; k++;
  }
  return chunks;
}

if (process.argv[2] === 'probe') {
  const s0 = [0n, 1n, 0n, IC1[0], IC1[1], 1n, INPUT0];
  for (const w of [40, 60, 80, 82]) {
    const out = armRange(s0, 0, w);
    const m = measureArm(genArmChunk(0, w, 0, null), s0, out, 0, null);
    console.error(`window ${w}b: op=${m.op.toLocaleString()} fits=${m.op <= OP_BUDGET} lock=${m.lockBytes}B`);
  }
  process.exit(0);
}

// ---- plan both terms (independent) then the fold ----
console.error('planning multi-input vk_x...');
console.error('term0 = in0*IC1:');
const t0 = planTerm(INPUT0, IC1, 254, 0, 't0');
const t1Base = t0.length;
console.error('term1 = in1*IC2:');
const t1 = planTerm(INPUT1, IC2, 254, t1Base, 't1');
const t0TermOut = t0[t0.length - 1].outIdx; // terminal output idx of term0
const t1TermOut = t1[t1.length - 1].outIdx;
const foldOutIdx = t1Base + t1.length;
const foldSrc = genFoldChunk(t0TermOut, t1TermOut);
writeFileSync(join(GEN, 'fold.cash'), foldSrc);
console.error(`fold: reads out[${t0TermOut}] + out[${t1TermOut}], asserts == EXPECTED`);

const totalChunks = t0.length + t1.length + 1;
const totalOp = [...t0, ...t1].reduce((s, c) => s + c.op, 0);
console.error(`\nLAYOUT: ${totalChunks} inputs in ONE transaction (${t0.length} + ${t1.length} arm chunks + 1 fold)`);
console.error(`term0 + term1 run in PARALLEL (independent); within a term, chunks stitch serially.`);
console.error(`arm op-cost total ~${totalOp.toLocaleString()} (each input has its own ${OP_BUDGET.toLocaleString()} budget)`);

writeFileSync(join(GEN, 'manifest.json'), JSON.stringify({
  instance: { input0: String(INPUT0), input1: String(INPUT1), expected: EXPECTED.map(String) },
  layout: 'single-transaction, sibling inputs',
  term0Chunks: t0.length, term1Chunks: t1.length, foldChunks: 1, totalInputs: totalChunks,
  t0TermOut, t1TermOut, foldOutIdx,
  chunks: [...t0, ...t1].map((c) => ({ label: c.label, k: c.k, lo: c.lo, hi: c.hi, outIdx: c.outIdx, stitchIdx: c.stitchIdx, op: c.op, lockBytes: c.lockBytes })),
}, null, 2));
console.error('wrote generated/manifest.json + chunk contracts');
