// Shared reference math + helpers for the multi-input vk_x generator.
// vk_x = IC0 + in0*IC1 + in1*IC2 (BN254 G1), reproduced bit-for-bit against the
// CashScript Jacobian ops so committed limbs == what the contracts compute.
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';

// Toolchain paths are env-configurable (the forked cashc + a libauth install).
// Defaults match a sibling-checkout layout: ../cashscript-fork and
// ../zk-verifier-bench next to this repo. Override with CASHC / LIBAUTH_DIR.
export const CASHC = process.env.CASHC || '../cashscript-fork/packages/cashc/dist/cashc-cli.js';
const LIBAUTH_DIR = process.env.LIBAUTH_DIR || '../zk-verifier-bench/node_modules';
const LIBAUTH = pathToFileURL(`${LIBAUTH_DIR}/@bitauth/libauth/build/index.js`).href;
export const {
  hexToBin, binToHex, bigIntToVmNumber,
  createVirtualMachine, createInstructionSetBch2026, createVirtualMachineBch2026,
  ConsensusBch2025, ripemd160, secp256k1, sha1, sha256,
} = await import(LIBAUTH);

export const P = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
export const OP_BUDGET = (41 + 10_000) * 800; // 8,032,800
export const TARGET_UNLOCK = 10_000;

// ---- the committed instance (matches chunked/shamir/manifest.json) ----
export const INPUT0 = 123456789n;
export const INPUT1 = 987654321n;
export const IC0 = [15723390722547469201346605927630336729729463607293657950235977012003655267936n, 14617976463853845616027311884626760527376622737858716767193455441349641383825n];
export const IC1 = [9269869340829791644953940526610795845982127221382366381974052273854848284744n, 12340830433822638848259976740304056841548514693917037023437897137808450264577n];
export const IC2 = [6442706084407552401539720969529928260622245802604045626376932056434206076947n, 13805589277496019078136496656829548863642318729315912795941464570275337353000n];
// vk_x = IC0 + in0*IC1 + in1*IC2 for the SINGLETON's VK (verified == noble bn254 G1).
// NB: the chunked/shamir manifest's `expected` is a DIFFERENT VK instance, so it does
// not match these IC constants — this value is the noble ground truth for IC0/1/2 above.
export const EXPECTED = [15644294921145430921988747181028790891044364236415587227003079383627226619184n, 11385045911468846228213180368542598923845582755170526843843255644868172648193n];

// ---- field + Jacobian reference (exactly mirrors the .cash bodies) ----
const m = (a, b) => (a * b) % P, s = (a) => (a * a) % P, ad = (a, b) => (a + b) % P, sb = (a, b) => ((a - b) % P + P) % P;
export function jacDouble(x, y, z) {
  const a = s(x), b = s(y), c = s(b);
  const d = m(2n, sb(sb(s(ad(x, b)), a), c));
  const e = m(3n, a), f = s(e);
  const nx = sb(f, m(2n, d));
  const ny = sb(m(e, sb(d, nx)), m(8n, c));
  const nz = m(2n, m(y, z));
  return [nx, ny, nz];
}
export function jacAdd(aX, aY, aZ, bX, bY, bZ) {
  let rx = bX, ry = bY, rz = bZ;
  if (aZ !== 0n) {
    const z1 = s(aZ), z2 = s(bZ), u1 = m(aX, z2), u2 = m(bX, z1), s1 = m(m(aY, bZ), z2), s2 = m(m(bY, aZ), z1);
    if (u1 === u2 && s1 === s2) {
      const da = s(aX), db = s(aY), dc = s(db);
      const dd = m(2n, sb(sb(s(ad(aX, db)), da), dc)), de = m(3n, da), df = s(de);
      rx = sb(df, m(2n, dd)); ry = sb(m(de, sb(dd, rx)), m(8n, dc)); rz = m(2n, m(aY, aZ));
    } else {
      const h = sb(u2, u1), i2 = s(m(2n, h)), jj = m(h, i2), rr = m(2n, sb(s2, s1)), vv = m(u1, i2);
      rx = sb(sb(s(rr), jj), m(2n, vv)); ry = sb(m(rr, sb(vv, rx)), m(2n, m(s1, jj))); rz = m(sb(sb(s(ad(aZ, bZ)), z1), z2), h);
    }
  }
  return [rx, ry, rz];
}
// Fermat inverse for jacToAffine (final fold only)
function inv(x) { let r = 1n, b = x % P, e = P - 2n; while (e > 0n) { if (e & 1n) r = (r * b) % P; b = (b * b) % P; e >>= 1n; } return r; }
export function jacToAffine(x, y, z) { const zi = inv(z), zi2 = (zi * zi) % P, zi3 = (zi2 * zi) % P; return [(x * zi2) % P, (y * zi3) % P]; }

// One term's per-bit step (LSB-first, base-doubling), over a bit window [lo,hi).
// state = [rX,rY,rZ,cX,cY,cZ,scalar]
export function armRange(st, lo, hi) {
  let [rX, rY, rZ, cX, cY, cZ, scalar] = st;
  for (let i = lo; i < hi; i++) {
    if (((scalar >> BigInt(i)) & 1n) === 1n) { [rX, rY, rZ] = jacAdd(rX, rY, rZ, cX, cY, cZ); }
    if (cZ !== 0n && cY !== 0n) { [cX, cY, cZ] = jacDouble(cX, cY, cZ); }
  }
  return [rX, rY, rZ, cX, cY, cZ, scalar];
}

// ---- serialization / commitment (matches cash hash256(toPaddedBytes(.,40))) ----
export const le40 = (n) => { let x = ((n % P) + P) % P; const b = Buffer.alloc(40); for (let i = 0; i < 40; i++) { b[i] = Number(x & 0xffn); x >>= 8n; } return b; };
const H = (b) => createHash('sha256').update(b).digest();
export const commit = (limbs) => new Uint8Array(H(H(Buffer.concat(limbs.map(le40)))));

// ---- compile + push helpers ----
export const compile = (file) => hexToBin(execFileSync('node', [CASHC, file, '-h'], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }).trim());
export const pushInt = (n) => {
  const d = bigIntToVmNumber(n);
  if (d.length === 0) return Uint8Array.from([0x00]);
  if (d.length === 1 && d[0] >= 1 && d[0] <= 16) return Uint8Array.from([0x50 + d[0]]);
  if (d.length === 1 && d[0] === 0x81) return Uint8Array.from([0x4f]);
  if (d.length <= 75) return Uint8Array.from([d.length, ...d]);
  if (d.length <= 255) return Uint8Array.from([0x4c, d.length, ...d]);
  return Uint8Array.from([0x4d, d.length & 0xff, (d.length >> 8) & 0xff, ...d]);
};
// build an unlocking: arg pushes (decl order, reversed) + zero-pad to `target`
export const unlockOf = (args, target = TARGET_UNLOCK) => {
  const ab = Uint8Array.from(args.slice().reverse().flatMap((a) => [...pushInt(a)]));
  const N = target - ab.length - 3;
  return Uint8Array.from([...ab, 0x4d, N & 0xff, (N >> 8) & 0xff, ...new Uint8Array(N)]);
};

// ---- loose VM (no budget) for true op-cost; real VM for the fits-check ----
const HUGE = Number.MAX_SAFE_INTEGER;
const loose = { ...ConsensusBch2025, baseInstructionCost: 100, maximumFunctionIdentifierLength: 7, maximumMemorySlots: HUGE, maximumStandardLockingBytecodeLength: -1, maximumStandardUnlockingBytecodeLength: HUGE, maximumTokenCommitmentLength: 128, operationCostBudgetPerByte: HUGE, maximumStackItemLength: HUGE, maximumVmNumberByteLength: HUGE, maximumStackDepth: HUGE, maximumControlStackDepth: HUGE, maximumBytecodeLength: HUGE, maximumOperationCount: HUGE };
export const looseVm = createVirtualMachine(createInstructionSetBch2026(false, { consensus: loose, ripemd160, secp256k1, sha1, sha256 }));
export const realVm = createVirtualMachineBch2026(false);
export const CATEGORY = new Uint8Array(32).fill(0xcd);
export const tok = (c) => ({ amount: 0n, category: CATEGORY, nft: { capability: 'mutable', commitment: c } });
