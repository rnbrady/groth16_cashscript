import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { compile, unlockOf, commit, tok, realVm, P } from './_vkxmath.mjs';
const here = dirname(fileURLToPath(import.meta.url));
const MM = new URL('../chunked/pairing/_millermath.mjs', import.meta.url).href;
const { Fp2, Fp12, bn254, vec, finalexpTrace, pairsFor, Fp, Fp6, ATE_NAF, pointDouble, pointAdd, postPrecompute } = await import(MM);
const GEN = join(here, 'generated');
const scalarFp2=(x,k)=>Fp2.fromBigTuple([Fp.mul(x.c0,k),Fp.mul(x.c1,k)]);
function mul034fn(f,o0,o3,o4){const A=Fp6.create({c0:Fp2.mul(f.c0.c0,o0),c1:Fp2.mul(f.c0.c1,o0),c2:Fp2.mul(f.c0.c2,o0)});const B=Fp6.mul01(f.c1,o3,o4);const E=Fp6.mul01(Fp6.add(f.c0,f.c1),Fp2.add(o0,o3),o4);return Fp12.create({c0:Fp6.add(Fp6.mulByNonresidue(B),A),c1:Fp6.sub(E,Fp6.add(A,B))});}
const lineFnRef=(f,c0,c1,c2,Px,Py)=>mul034fn(f,scalarFp2(c2,Py),scalarFp2(c1,Px),c0);
function spm(pair){const Qa=pair.Q.toAffine(),Pa=pair.P.toAffine();const pd={Qx:Qa.x,Qy:Qa.y,negQy:Fp2.neg(Qa.y),Px:Pa.x,Py:Pa.y};const ops=[];for(let k=0;k<ATE_NAF.length;k++){ops.push({t:'sqr'});ops.push({t:'dl'});if(ATE_NAF[k])ops.push({t:'al',neg:ATE_NAF[k]===-1});}ops.push({t:'pp'});let f=Fp12.ONE,R={x:pd.Qx,y:pd.Qy,z:Fp2.ONE};for(const op of ops){if(op.t==='sqr')f=Fp12.sqr(f);else if(op.t==='dl'){const d=pointDouble(R.x,R.y,R.z);R=d.R;f=lineFnRef(f,d.coeffs[0],d.coeffs[1],d.coeffs[2],pd.Px,pd.Py);}else if(op.t==='al'){const a=pointAdd(R.x,R.y,R.z,pd.Qx,op.neg?pd.negQy:pd.Qy);R=a.R;f=lineFnRef(f,a.coeffs[0],a.coeffs[1],a.coeffs[2],pd.Px,pd.Py);}else{const res=postPrecompute(f,R,pd.Qx,pd.Qy,pd.Px,pd.Py);f=res.f;R=res.R;}}return f;}
const pairs=pairsFor(vec.publicInputs);
const validB=pairs.map(spm).reduce((a,b)=>Fp12.mul(a,b),Fp12.ONE);
const tampB=Fp12.mul(validB, bn254.pairing(bn254.G1.Point.BASE, bn254.G2.Point.BASE, false));
const man=JSON.parse(readFileSync(GEN+'/finalexp_manifest.json','utf8'));
const last=man.chunks[man.chunks.length-1];
const lock=Uint8Array.from([0x75,...compile(GEN+'/finalexp_c'+last.k+'.cash')]);
function runLast(boundary){
  const fe=finalexpTrace(boundary);
  const inLimbs=fe.liveAt(last.opLo).flatMap(fe.limbs12).map(n=>((BigInt(n)%P)+P)%P);
  const inCommit=commit(inLimbs);
  // build outputs up to stitchIdx; output[stitchIdx]=hash(incoming)
  const maxOut=last.stitchIdx??0; const outs=[];
  for(let i=0;i<=maxOut;i++)outs.push({lockingBytecode:lock,valueSatoshis:1000n,token:tok(new Uint8Array(32))});
  if(last.stitchIdx!=null)outs[last.stitchIdx]={lockingBytecode:lock,valueSatoshis:1000n,token:tok(inCommit)};
  const st=realVm.evaluate({inputIndex:0,sourceOutputs:[{lockingBytecode:lock,valueSatoshis:1000n,token:tok(inCommit)}],transaction:{version:2,inputs:[{outpointTransactionHash:new Uint8Array(32),outpointIndex:0,sequenceNumber:0,unlockingBytecode:unlockOf(inLimbs)}],outputs:outs,locktime:0}});
  const top=st.stack[st.stack.length-1];
  return {ok:st.error===undefined&&st.stack.length===1&&top?.length===1&&top[0]===1, err:st.error};
}
const v=runLast(validB), t=runLast(tampB);
console.log('VALID    -> accepts (verdict==ONE):', v.ok, v.err?('('+String(v.err).slice(0,50)+')'):'');
console.log('TAMPERED -> REJECTS:', !t.ok);
