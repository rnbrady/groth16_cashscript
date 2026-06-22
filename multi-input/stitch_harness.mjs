import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
const LIBAUTH = pathToFileURL((process.env.LIBAUTH_DIR || '../zk-verifier-bench/node_modules') + '/@bitauth/libauth/build/index.js').href;
const { hexToBin, bigIntToVmNumber, createVirtualMachineBch2026 } = await import(LIBAUTH);
const vm = createVirtualMachineBch2026(false);
const H=(b)=>createHash('sha256').update(b).digest();
const P=21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const pushInt=(n)=>{const d=bigIntToVmNumber(n);if(d.length===0)return Uint8Array.from([0x00]);if(d.length===1&&d[0]>=1&&d[0]<=16)return Uint8Array.from([0x50+d[0]]);if(d.length<=75)return Uint8Array.from([d.length,...d]);if(d.length<=255)return Uint8Array.from([0x4c,d.length,...d]);return Uint8Array.from([0x4d,d.length&0xff,(d.length>>8)&0xff,...d]);};
const le40=(n)=>{let x=((n%P)+P)%P;const b=new Uint8Array(40);for(let i=0;i<40;i++){b[i]=Number(x&0xffn);x>>=8n;}return b;};
const commit=(limbs)=>new Uint8Array(H(H(Buffer.concat(limbs.map(le40)))));
function jacDouble(x,y,z){const m=(a,b)=>(a*b)%P,s=a=>(a*a)%P,ad=(a,b)=>(a+b)%P,sb=(a,b)=>((a-b)%P+P)%P;const a=s(x),b=s(y),c=s(b);const d=m(2n,sb(sb(s(ad(x,b)),a),c));const e=m(3n,a);const f=s(e);const nx=sb(f,m(2n,d));const ny=sb(m(e,sb(d,nx)),m(8n,c));const nz=m(2n,m(y,z));return[nx,ny,nz];}
function jacAdd(aX,aY,aZ,bX,bY,bZ){const m=(a,b)=>(a*b)%P,s=a=>(a*a)%P,ad=(a,b)=>(a+b)%P,sb=(a,b)=>((a-b)%P+P)%P;let rx=bX,ry=bY,rz=bZ;if(aZ!==0n){const z1=s(aZ),z2=s(bZ),u1=m(aX,z2),u2=m(bX,z1),s1=m(m(aY,bZ),z2),s2=m(m(bY,aZ),z1);if(u1===u2&&s1===s2){const da=s(aX),db=s(aY),dc=s(db);const dd=m(2n,sb(sb(s(ad(aX,db)),da),dc));const de=m(3n,da);const df=s(de);rx=sb(df,m(2n,dd));ry=sb(m(de,sb(dd,rx)),m(8n,dc));rz=m(2n,m(aY,aZ));}else{const h=sb(u2,u1),i2=s(m(2n,h)),jj=m(h,i2),rr=m(2n,sb(s2,s1)),vv=m(u1,i2);rx=sb(sb(s(rr),jj),m(2n,vv));ry=sb(m(rr,sb(vv,rx)),m(2n,m(s1,jj)));rz=m(sb(sb(s(ad(aZ,bZ)),z1),z2),h);}}return[rx,ry,rz];}
function armRange(st,lo,hi){let[rX,rY,rZ,cX,cY,cZ,scalar]=st;for(let i=lo;i<hi;i++){if(((scalar>>BigInt(i))&1n)===1n){[rX,rY,rZ]=jacAdd(rX,rY,rZ,cX,cY,cZ);}if(cZ!==0n&&cY!==0n){[cX,cY,cZ]=jacDouble(cX,cY,cZ);}}return[rX,rY,rZ,cX,cY,cZ,scalar];}

const CAT=new Uint8Array(32).fill(0xcd);const tok=(c)=>({amount:0n,category:CAT,nft:{capability:'mutable',commitment:c}});
const redeemA=hexToBin(readFileSync('/tmp/chunkA.hex','utf8').trim());const lockA=Uint8Array.from([0x75,...redeemA]);
const redeemB=hexToBin(readFileSync('/tmp/chunkB.hex','utf8').trim());const lockB=Uint8Array.from([0x75,...redeemB]);

const scalar=123456789n,bx=9269869340829791644953940526610795845982127221382366381974052273854848284744n,by=12340830433822638848259976740304056841548514693917037023437897137808450264577n;
const s0=[0n,1n,0n,bx,by,1n,scalar];
const s1=armRange(s0,0,82);
const s2=armRange(s1,82,164);

function unlockOf(state){const ab=Uint8Array.from(state.slice().reverse().flatMap(a=>[...pushInt(a)]));const N=10000-ab.length-3;return Uint8Array.from([...ab,0x4d,N&0xff,(N>>8)&0xff,...new Uint8Array(N)]);}

// ONE tx, TWO inputs. output[0]=hash(s1) (shared blackboard), output[1]=hash(s2).
function run(s1_consumed){
  const inputs=[
    {outpointTransactionHash:new Uint8Array(32),outpointIndex:0,sequenceNumber:0,unlockingBytecode:unlockOf(s0)},        // input0 chunkA
    {outpointTransactionHash:new Uint8Array(32),outpointIndex:1,sequenceNumber:0,unlockingBytecode:unlockOf(s1_consumed)}, // input1 chunkB
  ];
  const sourceOutputs=[
    {lockingBytecode:lockA,valueSatoshis:1000n,token:tok(commit(s0))},
    {lockingBytecode:lockB,valueSatoshis:1000n,token:tok(commit(s1_consumed))},
  ];
  const outputs=[
    {lockingBytecode:lockA,valueSatoshis:1000n,token:tok(commit(s1))},  // output[0] = producer's s1
    {lockingBytecode:lockB,valueSatoshis:1000n,token:tok(commit(s2))},  // output[1] = final s2
  ];
  const r={};
  for (const idx of [0,1]){
    const st=vm.evaluate({inputIndex:idx,sourceOutputs,transaction:{version:2,inputs,outputs,locktime:0}});
    const top=st.stack[st.stack.length-1];
    r[idx]={accepted:st.error===undefined&&st.stack.length===1&&top?.length===1&&top[0]===1,op:st.metrics.operationCost,err:st.error??null};
  }
  return r;
}

console.log('=== HONEST: input1 consumes the real s1 ===');
const good=run(s1);
console.log(`  input0(chunkA): accepted=${good[0].accepted} op=${good[0].op.toLocaleString()} ${good[0].err??''}`);
console.log(`  input1(chunkB): accepted=${good[1].accepted} op=${good[1].op.toLocaleString()} ${good[1].err??''}`);
console.log(`  TX VALID (both inputs accept): ${good[0].accepted && good[1].accepted}`);

console.log('\\n=== FORGED: input1 consumes a tampered s1 (flip one limb) ===');
const fake=[...s1]; fake[0]=(fake[0]+1n)%P;
const bad=run(fake);
console.log(`  input0(chunkA): accepted=${bad[0].accepted} ${bad[0].err? '('+String(bad[0].err).slice(0,60)+')':''}`);
console.log(`  input1(chunkB): accepted=${bad[1].accepted} ${bad[1].err? '('+String(bad[1].err).slice(0,70)+')':''}`);
console.log(`  TX REJECTED (stitch catches forgery): ${!(bad[0].accepted && bad[1].accepted)}`);
