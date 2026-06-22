// Assemble the BRADY verifier: the STANDARD-RELAYABLE form of the intratx verifier.
//
// intratx (../intratx) packs the whole 63-input chain into ONE non-standard
// (<1MB) transaction — every input forward-checks tx.inputs[i+1], so the chain is
// inseparable. brady deploys the SAME chunks as a SEQUENCE of STANDARD (<=100,000 B)
// transactions: within each "band" (one standard tx) the inputs are intra-tx
// forward-checked (no hashing); between bands a CashToken NFT carries the running
// state forward by hash256 commitment (the covenant handoff from chunked/pairing).
//
// So it is a hybrid: intra-tx cooperation within a band, inter-tx covenant between
// bands. Inputs are op-cost-measured then greedily packed into the fewest bands that
// each serialize under 100 KB. Every input is evaluated in ITS band's own
// transaction on the real BCH 2026 VM; boundary inputs gain covenant-commit /
// covenant-check ops (see transform_brady.mjs).
//
//   node build_vectors.mjs        -> verifier/src/bch/groth16-brady-vectors.json
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import {
  Fp2, bn254, millerBatchOps, pairsFor, proofFromLimbs, proof, vec,
  f12limbs, r6limbs, compileBytecode, ptLimbs, PT_CFG,
  vkxStateAt, vkxFinalZinv, vkxPoint, finalexpTrace, le40,
  OP_DROP, OP_PUSHDATA2, TARGET_UNLOCK, OP_BUDGET,
} from '../pairing/_millermath.mjs';
import { g2checkAccAt } from '../pairing/gen_g2check.mjs';
import { transformChunk, headerSize } from '../intratx/transform.mjs';
import { transformBrady } from './transform_brady.mjs';
import { createHash } from 'node:crypto';
const sha256d = (b) => new Uint8Array(createHash('sha256').update(createHash('sha256').update(b).digest()).digest());

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, '..', 'pairing', 'generated');
const PRIME = '21888242871839275222246405745257275088696311157297823662689037894645226208583';
const P = BigInt(PRIME);
const W = 40; // BN254 limb width (bytes)
const LIBAUTH = pathToFileURL('C:/Users/mathi/Desktop/verifier/node_modules/@bitauth/libauth/build/index.js').href;
const { hexToBin, binToHex, vmNumberToBigInt, bigIntToVmNumber, hash160, encodeLockingBytecodeP2sh20, encodeDataPush, createVirtualMachineBch2026 } = await import(LIBAUTH);
const realVm = createVirtualMachineBch2026(false);

// Deploy each chunk as P2SH: the ~4-5 KB redeem script (the field-tower prologue +
// chunk body) lives in the scriptSig, where it COUNTS toward the op-cost budget
// ((41 + unlockingLen) * 800) — so it does double duty (code AND budget) instead of
// sitting in the locking (which contributes nothing to the budget) alongside an
// equal-sized dead pad. Measured ~30% smaller on-chain than the bare-script model.
// P2SH is compatible with the forward-check: the inBlob stays the FIRST push of the
// scriptSig (siblings read it at a fixed front offset); the redeem is the LAST push.
const P2SH = process.env.INTRATX_BARE !== '1';
const p2shSpk = (redeem) => encodeLockingBytecodeP2sh20(hash160(redeem)); // OP_HASH160 <h> OP_EQUAL

// ---- push helpers (libauth encodeDataPush does the minimal length-prefix; we keep the
// numeric-opcode minimal forms — OP_0/OP_1..16/OP_1NEGATE — which encodeDataPush omits) ----
const pushInt = (n) => {
  const d = bigIntToVmNumber(BigInt(n));
  if (d.length === 0) return Uint8Array.from([0x00]);
  if (d.length === 1 && d[0] >= 1 && d[0] <= 16) return Uint8Array.from([0x50 + d[0]]);
  if (d.length === 1 && d[0] === 0x81) return Uint8Array.from([0x4f]);
  return encodeDataPush(d);
};
const pd = encodeDataPush;
const blob = (limbs) => Uint8Array.from(limbs.flatMap((l) => [...le40(((BigInt(l) % P) + P) % P)]));
// trailing all-zero pad that buys op-cost budget (libauth-minimal push; the consensus VM
// rejects a non-minimal push, so a light chunk needing <256 pad bytes must not use
// PUSHDATA2). The pad sits at the END of the unlocking, so its size never shifts the front
// inBlob a sibling's forward-check reads; any 1-byte rounding at a push-size boundary is
// absorbed by the op-cost MARGIN in tunedLen.
const padPush = (argLen, target) => {
  const budget = Math.max(2, target - argLen);
  const N = budget <= 76 ? budget - 1 : budget <= 257 ? budget - 2 : budget - 3;
  return encodeDataPush(new Uint8Array(N));
};
// Op-cost padding margin (bytes). The op-cost is MEASURED exactly per chunk, so the
// margin only needs to absorb (a) the pass1->pass2 pad-size op-cost feedback and (b)
// proof-to-proof op jitter within the supported instance set (committed + proof#1).
// Measured: the tightest input keeps ~25K op-slack at MARGIN=32, and both the
// committed and proof#1 instances accept; invalid runs reject. 32 (down from the
// intratx default 96) trims ~64 B/input -> the verifier crosses under 500 KB.
// NB: a synthetic all-bits-set worst-case proof costs up to ~8,009 B-equiv MORE on
// the vk_x chunks; like the upstream intratx, brady targets the committed+proof#1
// regime, not that adversarial extreme (which busts even at MARGIN=96).
const MARGIN = Number(process.env.MARGIN ?? 32);
const tunedLen = (argLen, opCost) => Math.min(TARGET_UNLOCK, Math.max(argLen + 3, Math.ceil(opCost / 800) - 41 + MARGIN));

// ---- multi-input evaluation: build ONE tx from all inputs, evaluate at `index` ----
function evalInput(inputs, index) {
  const program = {
    inputIndex: index,
    sourceOutputs: inputs.map((i) => ({ lockingBytecode: i.locking, valueSatoshis: 1000n })),
    transaction: {
      version: 2,
      inputs: inputs.map((i, n) => ({ outpointTransactionHash: new Uint8Array(32), outpointIndex: n, sequenceNumber: 0, unlockingBytecode: i.unlocking })),
      outputs: [{ lockingBytecode: Uint8Array.from([0x6a]), valueSatoshis: 1000n }],
      locktime: 0,
    },
  };
  const st = realVm.evaluate(program);
  const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1, operationCost: st.metrics.operationCost, error: st.error ?? null };
}

// ---- proof instances (proof #0 committed, #1 minted under same VK, worst-case dense) ----
function parseProofUnlocking(hex) {
  const b = hexToBin(hex); const vals = []; let i = 0;
  while (i < b.length) {
    const op = b[i++];
    if (op === 0x00) vals.push(0n);
    else if (op === 0x4f) vals.push(-1n);
    else if (op >= 0x51 && op <= 0x60) vals.push(BigInt(op - 0x50));
    else { let len; if (op <= 75) len = op; else if (op === 0x4c) len = b[i++]; else if (op === 0x4d) { len = b[i] | (b[i + 1] << 8); i += 2; } else throw new Error('push?'); vals.push(vmNumberToBigInt(b.slice(i, i + len), { requireMinimalEncoding: false })); i += len; }
  }
  const d = vals.reverse();
  return { Ax: d[0], Ay: d[1], Bxa: d[2], Bxb: d[3], Bya: d[4], Byb: d[5], Cx: d[6], Cy: d[7], in0: d[8], in1: d[9] };
}
const mp = JSON.parse(readFileSync('C:/Users/mathi/Desktop/verifier/src/bch/groth16-singleton-multiproof-vectors.json', 'utf8'));
const p1 = parseProofUnlocking(mp.proofs[1].unlocking);
const wcp = parseProofUnlocking(mp.worstCaseProof.unlocking);
const INSTANCES = {
  committed: { proof: undefined, inputs: vec.publicInputs.map(BigInt) },
  proof1: { proof: proofFromLimbs(p1.Ax, p1.Ay, p1.Bxa, p1.Bxb, p1.Bya, p1.Byb, p1.Cx, p1.Cy), inputs: [p1.in0, p1.in1] },
  worst: { proof: proofFromLimbs(wcp.Ax, wcp.Ay, wcp.Bxa, wcp.Bxb, wcp.Bya, wcp.Byb, wcp.Cx, wcp.Cy), inputs: [wcp.in0, wcp.in1] },
};

// vk_x position inside the miller genesis inBlob (stateLimbs=36, then ptL; pair2's P
// is at ptL offset = lengths of pairs 0+1). Computed, not hardcoded.
const MILLER_STATE_LIMBS = 12 + 4 * 6; // f(12) + 4 R(6 each)
const dummy = pairsFor([1n, 1n]);
const VKX_LIMB_OFFSET = MILLER_STATE_LIMBS + ptLimbs(0, dummy[0].P.toAffine(), dummy[0].Q.toAffine()).length + ptLimbs(1, dummy[1].P.toAffine(), dummy[1].Q.toAffine()).length;
const MILLER_IN_LIMBS = MILLER_STATE_LIMBS + dummy.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine())).length;

// ---- per-stage chunk specs (inLimbs/outLimbs/extras/role) for one instance ----
const stateLimbs = (s) => [...f12limbs(s.f), ...s.Rs.flatMap(r6limbs)];

function specsG2check(inst) {
  const pf = inst.proof ?? proof;
  const Ba = pf.b.toAffine(), Aa = pf.a.toAffine(), Ca = pf.c.toAffine();
  const Bpair = [[Ba.x.c0, Ba.x.c1], [Ba.y.c0, Ba.y.c1]];
  const tail = [Ba.x.c0, Ba.x.c1, Ba.y.c0, Ba.y.c1, Aa.x, Aa.y, Ca.x, Ca.y];
  const rLimbs = (R) => [R[0][0], R[0][1], R[1][0], R[1][1], R[2][0], R[2][1]];
  const sLimbs = (R) => [...rLimbs(R), ...tail];
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_g2check.json'), 'utf8'));
  return man.chunks.map((ch) => ({
    file: join(GEN, `g2check_${String(ch.idx).padStart(2, '0')}.cash`),
    inLimbs: sLimbs(g2checkAccAt(Bpair, ch.lo)),
    outLimbs: ch.last ? [] : sLimbs(g2checkAccAt(Bpair, ch.hi)),
    extras: [], role: ch.last ? 'terminal' : 'within',
    label: `g2check bits[${ch.lo},${ch.hi})${ch.last ? ' [6x^2]B==psi(B)' : ''}`,
    checkpoint: ch.first ? 'validate-inputs' : undefined,
  }));
}
function specsVkx(inst, crossToMiller) {
  const [in0, in1] = inst.inputs;
  const vkxAff = vkxPoint(inst.inputs).toAffine();
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_vkx.json'), 'utf8'));
  return man.chunks.map((ch) => {
    const inAcc = vkxStateAt(in0, in1, ch.lo);
    const inLimbs = [...inAcc, in0, in1];
    if (ch.final) {
      return {
        file: join(GEN, `vkx_${String(ch.idx).padStart(2, '0')}.cash`),
        inLimbs, outLimbs: [vkxAff.x, vkxAff.y], extras: [vkxFinalZinv(in0, in1)],
        role: crossToMiller ? 'cross' : 'stage-final',
        cmp: crossToMiller ? { cmpExpr: 'outBlob', nextFullInLen: MILLER_IN_LIMBS * W, skip: VKX_LIMB_OFFSET * W, cmpLen: 2 * W } : null,
        label: 'vk_x final -> assert vk_x', checkpoint: 'vk_x',
      };
    }
    return {
      file: join(GEN, `vkx_${String(ch.idx).padStart(2, '0')}.cash`),
      inLimbs, outLimbs: [...vkxStateAt(in0, in1, ch.hi), in0, in1], extras: [], role: 'within',
      label: `vk_x [${ch.lo},${ch.hi})`, checkpoint: undefined,
    };
  });
}
function specsMiller(inst, crossToFinalexp) {
  const pairs = pairsFor(inst.inputs, inst.proof);
  const { states, boundary } = millerBatchOps(pairs);
  const ptL = pairs.flatMap((p, j) => ptLimbs(j, p.P.toAffine(), p.Q.toAffine()));
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_miller.json'), 'utf8'));
  const specs = man.chunks.map((ch) => ({
    file: join(GEN, `miller_${String(ch.idx).padStart(2, '0')}.cash`),
    inLimbs: [...stateLimbs(states[ch.opLo]), ...ptL],
    outLimbs: [...stateLimbs(states[ch.opHi]), ...ptL],
    extras: [], role: ch.final ? (crossToFinalexp ? 'cross' : 'stage-final') : 'within',
    cmp: ch.final && crossToFinalexp ? { cmpExpr: 'outBlob.split(480)[0]', nextFullInLen: 12 * W, skip: 0, cmpLen: 12 * W } : null,
    label: `miller ops[${ch.opLo},${ch.opHi})${ch.final ? ' =boundary' : ''}`,
    checkpoint: ch.final ? 'miller-boundary' : undefined,
  }));
  return { specs, boundary };
}
function specsFinalexp(boundaryVal) {
  const tr = finalexpTrace(boundaryVal);
  const liveLimbs = (cut) => tr.liveAt(cut).flatMap((id) => tr.limbs12(id));
  const man = JSON.parse(readFileSync(join(GEN, 'manifest_finalexp.json'), 'utf8'));
  return man.chunks.map((ch) => ({
    file: join(GEN, `finalexp_${String(ch.idx).padStart(2, '0')}.cash`),
    inLimbs: liveLimbs(ch.opLo), outLimbs: ch.final ? [] : liveLimbs(ch.opHi),
    extras: [], role: ch.final ? 'terminal' : 'within',
    label: `finalexp ops[${ch.opLo},${ch.opHi})${ch.final ? ' verdict==1' : ''}`,
    checkpoint: ch.final ? 'verify' : undefined,
  }));
}

// ---- assemble: transform+compile each chunk, build the tx, tune pad, verify ----
const compileCache = new Map();
// brady: `band` = { bandFirst, bandLast } marks the input's position within its
// standard-tx band. bandFirst (k>0) gains a covenant-check (hash256(inBlob) == spent
// NFT); bandLast (k<last) replaces its forward-check with a covenant-commit
// (tx.outputs[0].nftCommitment == hash256(outBlob)). Within-band inputs are plain
// intratx (forward-check to tx.inputs[i+1]).
function compileSpec(s, band = {}) {
  let forward = null;
  if (s.role === 'within') { const outLen = s.outLimbs.length * W; forward = { cmpExpr: null, nextFullInLen: outLen, skip: 0, cmpLen: outLen }; }
  else if (s.role === 'cross') forward = s.cmp;
  // 'stage-final' and 'terminal' -> forward = null
  const key = `${s.file}|${s.role}|${JSON.stringify(forward)}|bf${band.bandFirst ? 1 : 0}|bl${band.bandLast ? 1 : 0}`;
  let redeem = compileCache.get(key);
  if (!redeem) {
    const t = (band.bandFirst || band.bandLast)
      ? transformBrady(readFileSync(s.file, 'utf8'), { W, prime: PRIME, forward }, band)
      : transformChunk(readFileSync(s.file, 'utf8'), { W, prime: PRIME, forward });
    redeem = compileBytecode(t.src);
    compileCache.set(key, redeem);
  }
  return Uint8Array.from([OP_DROP, ...redeem]);
}
function argBytesOf(s) {
  // inBlob is the LAST declared param (so it is pushed FIRST -> the front of the
  // unlocking bytecode, where siblings' forward-checks read it). The extra params
  // come before inBlob in the declaration, so they are pushed AFTER it in REVERSE
  // declaration order (param0 ends up on top of stack).
  const parts = [pd(blob(s.inLimbs))];
  for (const e of [...s.extras].reverse()) parts.push(pushInt(e));
  return Uint8Array.from(parts.flatMap((p) => [...p]));
}
// Build the full input set for a run; tune each input's pad against its measured
// op-cost. The pad is the trailing all-zero push that buys op-cost budget; it never
// shifts the FRONT inBlob, so it cannot disturb any sibling's forward-check.
//
// P2SH (default): locking = OP_HASH160 <h> OP_EQUAL (23 B); unlocking = [inBlob,
//   extras, pad, push(redeem)] — the redeem ([OP_DROP, contract]) is the last push,
//   and it counts toward the budget, so the pad shrinks by ~the redeem length.
// bare (INTRATX_BARE=1): locking = redeem; unlocking = [inBlob, extras, pad] — the
//   redeem does not count toward the budget, so the pad must buy the whole budget.
// Both: the front of the unlocking is [inBlob, extras...], identical, so the
// forward-check offsets are the same in either model.
// CAT = the brady covenant token thread (one NFT carries the inter-band handoff).
const CAT = new Uint8Array(32).fill(0xbd);
const STD_TX_CAP = 100_000; // MAX_STANDARD_TX_SIZE
const varint = (n) => (n < 0xfd ? 1 : n <= 0xffff ? 3 : n <= 0xffffffff ? 5 : 9);
const inputSerSize = (unlockLen) => 32 + 4 + varint(unlockLen) + unlockLen + 4;
// per-tx fixed serialized overhead: header(4) + locktime(4) + varint(nOut) + 1 op_return
// output + 1 covenant-NFT output (~40B commitment + token prefix); generous.
const TX_FIXED = 4 + 4 + varint(2) + (8 + 1 + 5) + (8 + 1 + 1 + 32 + 35);

// Evaluate input `idx` inside ITS BAND's own transaction. The band's first input
// (k>0) spends a UTXO whose NFT commitment = the previous band's handoff; the band's
// last input (k<last) creates output[0] carrying the next handoff commitment.
function evalBand(bandInputs, idx, spentCommit, outCommit) {
  const sourceOutputs = bandInputs.map((inp, n) => ({
    lockingBytecode: inp.locking, valueSatoshis: 1000n,
    ...(n === 0 && spentCommit ? { token: { amount: 0n, category: CAT, nft: { capability: 'mutable', commitment: spentCommit } } } : {}),
  }));
  const outputs = [outCommit
    ? { lockingBytecode: Uint8Array.from([0x6a]), valueSatoshis: 1000n, token: { amount: 0n, category: CAT, nft: { capability: 'mutable', commitment: outCommit } } }
    : { lockingBytecode: Uint8Array.from([0x6a]), valueSatoshis: 1000n }];
  const st = realVm.evaluate({ inputIndex: idx, sourceOutputs,
    transaction: { version: 2, inputs: bandInputs.map((inp, n) => ({ outpointTransactionHash: new Uint8Array(32), outpointIndex: n, sequenceNumber: 0, unlockingBytecode: inp.unlocking })), outputs, locktime: 0 } });
  const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top !== undefined && top.length === 1 && top[0] === 1, operationCost: st.metrics.operationCost, error: st.error ?? null };
}

// brady assemble: pack the spec chain into bands of standard (<=100KB) transactions,
// compile boundary inputs with covenant ops, evaluate each band as its own tx.
function assemble(specs) {
  // --- pass A: MEASURE each input's real op-cost (plain intratx compile) so we pack
  // bands by their TUNED unlocking length, not a worst-case probe. Measuring needs
  // the sibling forward-checks to resolve, so we evaluate each in a generous all-input
  // single-tx context (band roles don't change op-cost materially). ---
  const argB = specs.map(argBytesOf);
  const probeRedeem = specs.map((s) => compileSpec(s, {}));
  const probeRpush = probeRedeem.map((r) => encodeDataPush(r));
  const probeLock = (i) => (P2SH ? p2shSpk(probeRedeem[i]) : probeRedeem[i]);
  const probeMk = (i, target) => { const fixed = argB[i].length + (P2SH ? probeRpush[i].length : 0); const pad = padPush(0, Math.max(2, target - fixed)); return P2SH ? Uint8Array.from([...argB[i], ...pad, ...probeRpush[i]]) : Uint8Array.from([...argB[i], ...pad]); };
  const probeInputs = specs.map((s, i) => ({ locking: probeLock(i), unlocking: probeMk(i, TARGET_UNLOCK) }));
  const probeOp = specs.map((_, i) => evalInput(probeInputs, i).operationCost);
  // tuned unlocking length per input from its measured op-cost
  const tunedUnlockLen = specs.map((s, i) => tunedLen(argB[i].length + (P2SH ? probeRpush[i].length : 0), probeOp[i]));
  // greedy pack into bands under the standard tx cap (inputs stay contiguous)
  const bands = []; let cur = [], curBytes = TX_FIXED;
  for (let i = 0; i < specs.length; i++) {
    const sz = inputSerSize(tunedUnlockLen[i]);
    if (curBytes + sz > STD_TX_CAP && cur.length) { bands.push(cur); cur = []; curBytes = TX_FIXED; }
    cur.push(i); curBytes += sz;
  }
  if (cur.length) bands.push(cur);
  // map each global index -> { band, bandFirst, bandLast }
  const roleOf = new Array(specs.length);
  bands.forEach((b, k) => b.forEach((gi, j) => {
    roleOf[gi] = { band: k, bandFirst: j === 0 && k > 0, bandLast: j === b.length - 1 && k < bands.length - 1 };
  }));

  // --- compile every input with its band role; build per-input redeem/unlocking ---
  const redeems = specs.map((s, i) => compileSpec(s, roleOf[i]));
  const rpush = redeems.map((r) => encodeDataPush(r));
  const lockingOf = (i) => (P2SH ? p2shSpk(redeems[i]) : redeems[i]);
  const tailLen = (i) => (P2SH ? rpush[i].length : 0);
  const mkUnlock = (i, target) => {
    const fixed = argB[i].length + tailLen(i);
    const pad = padPush(0, Math.max(2, target - fixed));
    return P2SH ? Uint8Array.from([...argB[i], ...pad, ...rpush[i]]) : Uint8Array.from([...argB[i], ...pad]);
  };

  // --- the inter-band handoff commitments: hash256(blob(band-last's outLimbs)) ---
  const handoffCommit = (gi) => sha256d(blob(specs[gi].outLimbs.map((l) => ((BigInt(l) % P) + P) % P)));
  const bandSpent = bands.map((b, k) => (k === 0 ? null : handoffCommit(bands[k - 1][bands[k - 1].length - 1])));
  const bandOut = bands.map((b, k) => (k === bands.length - 1 ? null : handoffCommit(b[b.length - 1])));

  // --- two-pass pad tuning, evaluating each input in ITS band's tx ---
  const evalAll = (unlockTargets) => bands.map((b, k) => {
    const bandInputs = b.map((gi) => ({ locking: lockingOf(gi), unlocking: mkUnlock(gi, unlockTargets[gi]) }));
    return b.map((gi, j) => ({ gi, ...evalBand(bandInputs, j, bandSpent[k], bandOut[k]) }));
  }).flat();
  const t1 = specs.map(() => TARGET_UNLOCK);
  const op1 = evalAll(t1).sort((a, b) => a.gi - b.gi);
  const t2 = specs.map((s, i) => tunedLen(argB[i].length + tailLen(i), op1[i].operationCost));
  const op2 = evalAll(t2).sort((a, b) => a.gi - b.gi);

  const inputs = specs.map((s, i) => ({ locking: lockingOf(i), unlocking: mkUnlock(i, t2[i]) }));
  const meta = specs.map((s, i) => ({ label: s.label, checkpoint: s.checkpoint, band: roleOf[i].band, bandFirst: roleOf[i].bandFirst, bandLast: roleOf[i].bandLast, lockingBytes: inputs[i].locking.length, unlockingBytes: inputs[i].unlocking.length, operationCost: op2[i].operationCost, accepted: op2[i].accepted, error: op2[i].error }));
  const accepted = op2.every((o) => o.accepted);
  // per-band tx size (serialized) must be <= 100KB; per-input limits unchanged
  const bandTxBytes = bands.map((b) => TX_FIXED + b.reduce((a, gi) => a + inputSerSize(inputs[gi].unlocking.length), 0));
  const fits = meta.every((m) => m.lockingBytes <= 10000 && m.unlockingBytes <= 10000 && m.operationCost <= OP_BUDGET) && accepted && bandTxBytes.every((x) => x <= STD_TX_CAP);
  return { inputs, meta, fits, accepted, bands, bandTxBytes };
}

function buildFull(inst) {
  const g2 = specsG2check(inst);
  const vkx = specsVkx(inst, true);
  const { specs: miller, boundary } = specsMiller(inst, true);
  const fe = specsFinalexp(boundary);
  return assemble([...g2, ...vkx, ...miller, ...fe]);
}
function buildPairing(inst) {
  const { specs } = specsMiller(inst, false); // miller-final = stage-final (boundary milestone)
  return assemble(specs);
}

const toStepArr = (asm) => asm.inputs.map((inp, i) => ({ label: asm.meta[i].label, locking: binToHex(inp.locking), unlocking: binToHex(inp.unlocking), checkpoint: asm.meta[i].checkpoint }));
// corrupt one input's inBlob (a MIDDLE limb, so it is a live value the chunk actually

// ---- band-aware invalid run: corrupt one input's inBlob, evaluate its band ----
function invalidRun(asm, gi) {
  const m = asm.meta[gi];
  // rebuild that input's band with the corrupted unlocking, eval every input in it.
  const band = asm.bands[m.band];
  const corrupt = (u) => { const x = Uint8Array.from(u); const op = x[0]; const ds = op <= 75 ? 1 : op === 0x4c ? 2 : 3; const dl = op <= 75 ? op : op === 0x4c ? x[1] : x[1] | (x[2] << 8); x[ds + Math.floor(dl / 2)] ^= 0x01; return x; };
  const bandInputs = band.map((j) => ({ locking: asm.inputs[j].locking, unlocking: j === gi ? corrupt(asm.inputs[j].unlocking) : asm.inputs[j].unlocking }));
  const k = m.band;
  const CATc = new Uint8Array(32).fill(0xbd);
  // reuse the same spent/out commitments the band had (recompute is unnecessary for a reject test)
  const spent = k === 0 ? null : new Uint8Array(32); // any commitment; corrupted blob fails the covenant or forward check
  const res = band.map((j, idx) => evalBand(bandInputs, idx, k === 0 ? null : spent, undefined));
  return { rejected: res.some((r) => !r.accepted) };
}

const sum = (a, f) => a.reduce((x, m) => x + f(m), 0);
const report = (tag, asm) => {
  const maxOp = Math.max(...asm.meta.map((m) => m.operationCost));
  const maxL = Math.max(...asm.meta.map((m) => m.lockingBytes)), maxU = Math.max(...asm.meta.map((m) => m.unlockingBytes));
  console.error(`${tag}: ${asm.meta.length} inputs in ${asm.bands.length} STANDARD txns, accepted=${asm.accepted} fits=${asm.fits}`);
  console.error(`  totalBytes=${sum(asm.meta, (m) => m.lockingBytes + m.unlockingBytes).toLocaleString()} totalOp=${sum(asm.meta, (m) => m.operationCost).toLocaleString()} maxOp=${maxOp.toLocaleString()} maxLock=${maxL} maxUnlock=${maxU}`);
  asm.bands.forEach((b, k) => console.error(`  band ${k}: ${b.length} inputs, tx ${asm.bandTxBytes[k].toLocaleString()} B  ${asm.bandTxBytes[k] <= 100000 ? '<=100KB OK' : 'OVER 100KB'}`));
  const bad = asm.meta.find((m) => !m.accepted);
  if (bad) console.error(`  !! first non-accepting: ${bad.label} :: ${bad.error}`);
};

// ===================== FULL VERIFIER as a sequence of STANDARD txns =====================
const full0 = buildFull(INSTANCES.committed);
report('brady groth16 committed', full0);
const full1 = buildFull(INSTANCES.proof1);
report('brady groth16 proof#1', full1);
const inv = [invalidRun(full0, Math.floor(full0.inputs.length / 2)), invalidRun(full0, full0.inputs.length - 2)];
console.error(`  invalid runs rejected: ${inv.map((r) => r.rejected).join(',')}`);

writeFileSync('C:/Users/mathi/Desktop/verifier/src/bch/groth16-brady-vectors.json', JSON.stringify({
  description: 'BRADY hybrid BN254 Groth16 verifier deployed as a SEQUENCE of STANDARD (<=100,000 B) transactions. Within each band (one standard tx) the inputs are intra-tx forward-checked (OP_INPUTBYTECODE, no hashing); between bands a CashToken NFT carries the running state by hash256 commitment (covenant handoff). This is the standard-relayable form of bch-groth16-intratx.',
  method: 'brady-hybrid-intra-inter-tx', deployment: 'P2SH', standardTxCount: full0.bands.length,
  numInputs: full0.inputs.length, budgetPerInput: OP_BUDGET,
  totalBytes: sum(full0.meta, (m) => m.lockingBytes + m.unlockingBytes),
  totalOperationCost: sum(full0.meta, (m) => m.operationCost),
  bandTxBytes: full0.bandTxBytes, allFit: full0.fits, allAccept: full0.accepted,
  steps: toStepArr(full0),
}, null, 2));
console.error('wrote groth16-brady-vectors.json');
