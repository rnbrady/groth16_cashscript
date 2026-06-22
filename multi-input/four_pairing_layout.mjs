// Four-pairing multi-input layout: analysis + validated fold.
//
// The Groth16 boundary is e(-A,B)*e(alpha,beta)*e(vk_x,gamma)*e(C,delta), i.e. a
// product of FOUR Miller outputs (Fp12 each), then one final exponentiation. The
// four Miller loops are INDEPENDENT — they share nothing until the product. The
// chunked/pairing design deliberately BATCHES them into one shared `f` (one
// fp12Sqr per NAF step across all 4 pairs), which saves compute but forces a
// single serial chain of ~59 chunks.
//
// This module shows the alternative: run the four single-pair Miller loops as
// FOUR PARALLEL ARMS of sibling inputs, then a fold input combining m1*m2*m3*m4.
//   - The per-arm Miller chunking is mechanically identical to the vk_x stitch
//     already validated in gen_vkx_multiinput.mjs (state-threaded chunks,
//     stitched + thread-bound), applied to a larger state (Fp12 f + G2 R).
//   - The NEW piece is the FOLD: combining four independent Fp12 values. That is
//     validated here on the real VM (a contract that reads the 4 arm terminals
//     and asserts their product == the golden boundary).
//
// Run: node four_pairing_layout.mjs   (needs CASHC + LIBAUTH_DIR env, like the rest)
import { writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { OP_BUDGET, compile, pushInt, unlockOf, commit, le40, tok, CATEGORY, realVm, P } from './_vkxmath.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const GEN = join(here, 'generated');
mkdirSync(GEN, { recursive: true });
const PRIME = '21888242871839275222246405745257275088696311157297823662689037894645226208583';

// ---- measured single-pair Miller cost (from the confirmed baseline grading) ----
const SINGLE_PAIR_MILLER_OP = 128_839_421; // measured: node singleton/bn254/miller.mjs
const FINALEXP_OP = 141_105_085;           // measured: node singleton/bn254/finalexp.mjs

// =====================================================================
// PART 1 — transaction-count analysis (depth collapse)
// =====================================================================
const perArmChunks = Math.ceil(SINGLE_PAIR_MILLER_OP / OP_BUDGET);
const finalexpChunks = Math.ceil(FINALEXP_OP / OP_BUDGET);
const armChunksTotal = 4 * perArmChunks;        // all four arms' chunks (inputs)
const foldChunks = 3;                            // 3 fp12Mul to combine 4 Fp12 (tree or linear)

console.log('=== FOUR-PAIRING LAYOUT ANALYSIS ===\n');
console.log(`single-pair Miller op-cost (measured): ${SINGLE_PAIR_MILLER_OP.toLocaleString()}`);
console.log(`per-input budget:                       ${OP_BUDGET.toLocaleString()}`);
console.log(`chunks per pairing arm:                 ${perArmChunks}`);
console.log(`final-exp op-cost (measured):           ${FINALEXP_OP.toLocaleString()} -> ${finalexpChunks} chunks\n`);

console.log('CHUNKED (batched, serial — README): ~59 Miller chunks + ~34 final-exp = ~93 total,');
console.log('   all SEQUENTIAL -> ~93 transactions (one shared f forces a single chain).\n');

console.log('MULTI-INPUT (4 parallel arms):');
console.log(`   arm chunks (inputs): 4 x ${perArmChunks} = ${armChunksTotal}`);
console.log(`   fold (Fp12 product): ${foldChunks} chunks`);
console.log(`   final-exp: ${finalexpChunks} chunks (serial after the fold)`);
const totalInputs = armChunksTotal + foldChunks + finalexpChunks;
console.log(`   total inputs: ${totalInputs}`);
// critical path (dependency depth): one arm's chunks, then fold, then finalexp
const criticalDepth = perArmChunks + foldChunks + finalexpChunks;
console.log(`   CRITICAL PATH (min sequential txns if depth-bound): ${criticalDepth}`);
console.log('   (the four arms run in PARALLEL — their ~16 chunks each overlap, not stack)\n');

// transaction count if we pack sibling inputs up to the tx-size wall
const ARM_LOCK = 5000; // measured chunked Miller chunks are ~5 KB; arm chunks similar
const STD_TX = 100_000, CONS_TX = 1_000_000;
const perTxStd = Math.floor(STD_TX / 10_000);   // each input ~maxed unlocking (10 KB) -> ~10/tx... but op-bound chunks pad less
console.log('TRANSACTION COUNT (packing arm-chunks as sibling inputs):');
console.log(`   By DEPTH (your N-inputs-1-tx argument): the whole DAG can collapse toward its`);
console.log(`   critical path; independent arms become parallel inputs. Bounded by tx SIZE, not depth.`);
console.log(`   standard 100 KB tx, ~${perTxStd} maxed inputs/tx -> ceil(${totalInputs}/${perTxStd}) = ${Math.ceil(totalInputs / perTxStd)} txns`);
console.log(`   consensus 1 MB tx -> ceil(${totalInputs}/${Math.floor(CONS_TX / 10000)}) = ${Math.ceil(totalInputs / Math.floor(CONS_TX / 10000))} txn(s)\n`);
console.log('   vs chunked ~93 SEQUENTIAL txns. The independent pairings stop being a serial chain.\n');

// =====================================================================
// PART 2 — validate the FOLD on the real VM (the genuinely new piece)
// =====================================================================
// Get the four golden Miller outputs for the committed pairing instance from noble,
// reproduce the boundary, and prove a contract folds them == golden boundary.
const NOBLE = pathToFileURL((process.env.LIBAUTH_DIR ? join(process.env.LIBAUTH_DIR, '@noble/curves/bn254.js') : '../zk-verifier-bench/node_modules/@noble/curves/bn254.js')).href;
const { bn254 } = await import(NOBLE);
const Fp12 = bn254.fields.Fp12;

// Self-contained instance: four DISTINCT, non-degenerate single-pair Miller
// outputs from the generators (the FOLD math is identical regardless of the
// specific points — it just multiplies four Fp12 values). m_i = Miller output
// with no final exponentiation.
const g1 = bn254.G1.Point.BASE, g2 = bn254.G2.Point.BASE;
function millerOf(Pp, Qp) { return bn254.pairing(Pp, Qp, false); }
const m = [
  millerOf(g1, g2),
  millerOf(g1.multiply(2n), g2),
  millerOf(g1.multiply(3n), g2),
  millerOf(g1.multiply(4n), g2),
];
const boundary = m.reduce((a, b) => Fp12.mul(a, b), Fp12.ONE);

// Serialize an Fp12 to our 12-limb (noble toBytes order) form used by the .cash fp12.
// We mirror singleton/bn254 fp12 limb order: 12 ints. Use noble's toBigint coercion.
function fp12limbs(x) {
  // noble Fp12 = { c0: Fp6, c1: Fp6 }, Fp6 = { c0,c1,c2: Fp2 }, Fp2 = { c0,c1: bigint }
  const f6 = (s) => [s.c0.c0, s.c0.c1, s.c1.c0, s.c1.c1, s.c2.c0, s.c2.c1];
  return [...f6(x.c0), ...f6(x.c1)].map((v) => ((v % P) + P) % P);
}
const mL = m.map(fp12limbs);
const bL = fp12limbs(boundary);

// ---- emit a FOLD contract: read 4 Fp12 (each bound to an arm-terminal output by
// commitment + thread), compute product, assert == boundary. We validate it as a
// single covenant input (4 producer outputs present, on-thread). ----
function genFold() {
  const FP12 = (p) => Array.from({ length: 12 }, (_, i) => `${p}${i}`);
  const A = FP12('a'), B = FP12('b'), C = FP12('c'), D = FP12('d');
  const ser = (names) => names.map((n) => `toPaddedBytes(${n}, 40)`).join(' + ');
  // include the fp2/fp6/fp12 mul prologue (lifted from singleton fp12.cash shape)
  const prologue = readFileSync(join(here, '..', 'singleton', 'bn254', 'fp12.cash'), 'utf8')
    .split('\n').filter((l) => /internal function (mulFp|addFp|subFp|fp2|fp6|fp12)/.test(l) || true);
  // Simpler: reuse the singleton fp12.cash body between the contract braces.
  const fp12src = readFileSync(join(here, '..', 'singleton', 'bn254', 'fp12.cash'), 'utf8');
  const bodyMatch = fp12src.match(/contract \w+\([^)]*\)\s*\{([\s\S]*)\n\}\s*$/);
  let body = bodyMatch ? bodyMatch[1] : '';
  // strip any existing spend() so we can inject our own
  body = body.replace(/\n\s*function spend\([\s\S]*$/, '\n');
  const L = [];
  L.push('pragma cashscript ^0.13.0;');
  L.push('contract FourPairFold() {');
  L.push(body);
  L.push(`    function spend(${[...A, ...B, ...C, ...D].map((n) => `int ${n}`).join(', ')}) {`);
  L.push('        bytes thread = tx.inputs[this.activeInputIndex].tokenCategory;');
  // bind each Fp12 to its arm-terminal output, on-thread
  for (const [idx, names] of [[0, A], [1, B], [2, C], [3, D]]) {
    L.push(`        require(tx.outputs[${idx}].nftCommitment == hash256(${ser(names)}));`);
    L.push(`        require(tx.outputs[${idx}].tokenCategory == thread);`);
  }
  // product (tree: (A*B)*(C*D))
  L.push(`        (${A.map((_, i) => `int ab${i}`).join(',')}) = fp12Mul(${A.join(',')}, ${B.join(',')});`);
  L.push(`        (${C.map((_, i) => `int cd${i}`).join(',')}) = fp12Mul(${C.join(',')}, ${D.join(',')});`);
  L.push(`        (${A.map((_, i) => `int pr${i}`).join(',')}) = fp12Mul(${A.map((_, i) => `ab${i}`).join(',')}, ${C.map((_, i) => `cd${i}`).join(',')});`);
  for (let i = 0; i < 12; i++) L.push(`        require(pr${i} == ${bL[i]});`);
  L.push('    }');
  L.push('}');
  return L.join('\n') + '\n';
}

const foldSrc = genFold();
writeFileSync(join(GEN, 'four_pair_fold.cash'), foldSrc);
let redeem;
try { redeem = compile(join(GEN, 'four_pair_fold.cash')); }
catch (e) { console.log('FOLD compile FAILED:', String(e.message ?? e).slice(0, 200)); process.exit(1); }
const locking = Uint8Array.from([0x75, ...redeem]);

// build a covenant tx: input0 = fold; outputs 0..3 carry the 4 arm terminals on-thread
const outs = mL.map((limbs) => ({ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commit(limbs)) }));
const args = [...mL[0], ...mL[1], ...mL[2], ...mL[3]];
const unlocking = unlockOf(args);
const prog = {
  inputIndex: 0,
  sourceOutputs: [{ lockingBytecode: locking, valueSatoshis: 1000n, token: tok(new Uint8Array(32).fill(0xab)) }],
  transaction: { version: 2, inputs: [{ outpointTransactionHash: new Uint8Array(32), outpointIndex: 0, sequenceNumber: 0, unlockingBytecode: unlocking }], outputs: outs, locktime: 0 },
};
const st = realVm.evaluate(prog);
const top = st.stack[st.stack.length - 1];
const ok = st.error === undefined && st.stack.length === 1 && top?.length === 1 && top[0] === 1;
console.log('=== FOUR-PAIRING FOLD (real VM) ===');
console.log(`  fold contract: ${redeem.length}B redeem`);
console.log(`  product of 4 Fp12 arm-terminals == golden boundary: accepted=${ok} op=${st.metrics.operationCost.toLocaleString()} fits=${st.metrics.operationCost <= OP_BUDGET} ${st.error ?? ''}`);

// tamper one limb -> must reject
const badArgs = [...args]; badArgs[0] = (badArgs[0] + 1n) % P;
const badProg = { ...prog, transaction: { ...prog.transaction, inputs: [{ ...prog.transaction.inputs[0], unlockingBytecode: unlockOf(badArgs) }] } };
// also fix output[0] commitment to match tampered input so covIn passes but product fails
badProg.transaction.outputs = [...outs];
badProg.transaction.outputs[0] = { lockingBytecode: locking, valueSatoshis: 1000n, token: tok(commit([badArgs[0], ...mL[0].slice(1)])) };
const stb = realVm.evaluate(badProg);
const topb = stb.stack[stb.stack.length - 1];
const okb = stb.error === undefined && stb.stack.length === 1 && topb?.length === 1 && topb[0] === 1;
console.log(`  tampered Fp12 input -> rejected: ${!okb} (${stb.error ? String(stb.error).slice(0, 50) : 'accepted!'})`);
