// Assemble the generated vk_x chunks into ONE multi-input transaction and grade
// it on the REAL BCH 2026 VM: every input must accept (honest), and a forged
// handoff must be rejected. Also verifies the fold reproduces the oracle EXPECTED.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import {
  P, OP_BUDGET, INPUT0, INPUT1, IC1, IC2, EXPECTED,
  armRange, jacAdd, jacToAffine, commit, compile, unlockOf, tok, realVm, CATEGORY,
} from './_vkxmath.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
const manifest = JSON.parse(readFileSync(join(GEN, 'manifest.json'), 'utf8'));

// Rebuild every chunk's (inState,outState) by replaying the windows.
const STATE0 = (base, scalar) => [0n, 1n, 0n, base[0], base[1], 1n, scalar];
function termStates(base, scalar, chunks) {
  let st = STATE0(base, scalar); const out = [];
  for (const c of chunks) { const o = armRange(st, c.lo, c.hi); out.push({ ...c, inState: st, outState: o }); st = o; }
  return out;
}
const t0c = manifest.chunks.filter((c) => c.label === 't0');
const t1c = manifest.chunks.filter((c) => c.label === 't1');
const t0 = termStates(IC1, INPUT0, t0c);
const t1 = termStates(IC2, INPUT1, t1c);

// terminal states feed the fold
const t0Term = t0[t0.length - 1].outState;
const t1Term = t1[t1.length - 1].outState;

// compile lockings
const lockOf = (file) => Uint8Array.from([0x75, ...compile(join(GEN, file))]);
const armLock = (label, k) => lockOf(`${label}_c${k}.cash`);
const foldLock = lockOf('fold.cash');

// ---- build the ONE transaction ----
// inputs[i] spends a UTXO committing chunk i's inState; outputs[i] commits its outState.
// fold input spends a placeholder; fold reads outputs[t0TermOut]/[t1TermOut].
const allArms = [...t0, ...t1];
const N = allArms.length;            // 6 arm inputs
const foldIdx = N;                   // fold is input/last
const totalInputs = N + 1;

const ALT_CAT = new Uint8Array(32).fill(0x99); // an unrelated token thread
const tokc = (commitment, cat) => ({ amount: 0n, category: cat, nft: { capability: 'mutable', commitment } });

// mode: 'honest' | 'forgeHandoff' | 'crossThread'
function buildTx(mode) {
  const sourceOutputs = [], inputs = [], outputs = [];
  // arm inputs/outputs
  for (let i = 0; i < N; i++) {
    const c = allArms[i];
    let inState = c.inState;
    // forgeHandoff: tamper the consumed state of t0_c1 (a stitched consumer)
    if (mode === 'forgeHandoff' && c.label === 't0' && c.k === 1) { inState = [...c.inState]; inState[0] = (inState[0] + 1n) % P; }
    // crossThread: put t0_c1's spent UTXO on an UNRELATED token category (so its
    // `thread` differs from the on-thread output it must stitch to).
    const inCat = (mode === 'crossThread' && c.label === 't0' && c.k === 1) ? ALT_CAT : CATEGORY;
    sourceOutputs.push({ lockingBytecode: c.label === 't0' ? armLock('t0', c.k) : armLock('t1', c.k), valueSatoshis: 1000n, token: tokc(commit(c.inState), inCat) });
    inputs.push({ outpointTransactionHash: new Uint8Array(32), outpointIndex: i, sequenceNumber: 0, unlockingBytecode: unlockOf(inState) });
  }
  // fold input
  sourceOutputs.push({ lockingBytecode: foldLock, valueSatoshis: 1000n, token: tok(new Uint8Array(32).fill(0xab)) });
  inputs.push({ outpointTransactionHash: new Uint8Array(32), outpointIndex: foldIdx, sequenceNumber: 0, unlockingBytecode: unlockOf([...t0Term, ...t1Term]) });
  // outputs: output[i] = chunk i's published outState (the shared blackboard)
  for (let i = 0; i < N; i++) {
    const c = allArms[i];
    outputs.push({ lockingBytecode: c.label === 't0' ? armLock('t0', c.k) : armLock('t1', c.k), valueSatoshis: 1000n, token: tok(commit(c.outState)) });
  }
  outputs.push({ lockingBytecode: foldLock, valueSatoshis: 1000n, token: tok(new Uint8Array(32).fill(0xab)) });
  return { sourceOutputs, transaction: { version: 2, inputs, outputs, locktime: 0 } };
}

function evalInput(prog, idx) {
  const st = realVm.evaluate({ inputIndex: idx, sourceOutputs: prog.sourceOutputs, transaction: prog.transaction });
  const top = st.stack[st.stack.length - 1];
  return { accepted: st.error === undefined && st.stack.length === 1 && top?.length === 1 && top[0] === 1, op: st.metrics.operationCost, err: st.error ?? null };
}

// sanity: fold's affine result == EXPECTED (pure JS oracle)
const x1 = jacAdd(15723390722547469201346605927630336729729463607293657950235977012003655267936n, 14617976463853845616027311884626760527376622737858716767193455441349641383825n, 1n, t0Term[0], t0Term[1], t0Term[2]);
const vfin = jacAdd(x1[0], x1[1], x1[2], t1Term[0], t1Term[1], t1Term[2]);
const aff = jacToAffine(vfin[0], vfin[1], vfin[2]);
console.log('oracle fold == EXPECTED:', aff[0] === EXPECTED[0] && aff[1] === EXPECTED[1], '\n');

console.log(`=== HONEST: ${totalInputs} sibling inputs in ONE transaction ===`);
const good = buildTx('honest');
let allOk = true, maxOp = 0;
for (let i = 0; i < totalInputs; i++) {
  const r = evalInput(good, i);
  const name = i < N ? `${allArms[i].label}_c${allArms[i].k} (bits[${allArms[i].lo},${allArms[i].hi}))` : 'fold';
  console.log(`  input ${i} ${name}: accepted=${r.accepted} op=${r.op.toLocaleString()} fits=${r.op <= OP_BUDGET} ${r.err ?? ''}`);
  allOk = allOk && r.accepted && r.op <= OP_BUDGET; maxOp = Math.max(maxOp, r.op);
}
console.log(`  -> TX VALID: ${allOk}   max single-input op-cost: ${maxOp.toLocaleString()} / ${OP_BUDGET.toLocaleString()}\n`);

console.log('=== FORGED: tamper the handoff state consumed by t0_c1 ===');
const bad = buildTx('forgeHandoff');
const rbad = evalInput(bad, 1); // t0_c1 is input index 1
console.log(`  input 1 (t0_c1, the stitched consumer): accepted=${rbad.accepted} ${rbad.err ? '(' + String(rbad.err).slice(0, 60) + ')' : ''}`);
console.log(`  -> forgery REJECTED: ${!rbad.accepted}\n`);

console.log('=== CROSS-THREAD: t0_c1 spends a UTXO on an UNRELATED token category ===');
console.log('    (handoff value is correct, but the input is off-thread — the token-');
console.log('     category binding must reject it so unrelated threads cannot be mixed)');
const xt = buildTx('crossThread');
const rxt = evalInput(xt, 1);
console.log(`  input 1 (t0_c1): accepted=${rxt.accepted} ${rxt.err ? '(' + String(rxt.err).slice(0, 60) + ')' : ''}`);
console.log(`  -> cross-thread mixing REJECTED: ${!rxt.accepted}\n`);

// summary vs baseline
console.log('=== SUMMARY ===');
console.log(`multi-input vk_x: ${totalInputs} inputs in 1 TRANSACTION (term0 || term1, 3 chunks each, + fold)`);
console.log(`baseline chunked/shamir: 3 SEQUENTIAL TRANSACTIONS`);
console.log(`transaction count: 3 -> 1  (latency: 3 hops -> 1 hop)`);
const totalArmOp = allArms.reduce((s, c) => s + c.op, 0);
console.log(`total arm op-cost ~${totalArmOp.toLocaleString()} (vs shamir ~13.2M; higher because no shared-doubling — see README tradeoff)`);
