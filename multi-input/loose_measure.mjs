import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
const LIBAUTH = pathToFileURL((process.env.LIBAUTH_DIR || '../zk-verifier-bench/node_modules') + '/@bitauth/libauth/build/index.js').href;
const { hexToBin, bigIntToVmNumber, createVirtualMachine, createInstructionSetBch2026, ConsensusBch2025, ripemd160, secp256k1, sha1, sha256 } = await import(LIBAUTH);
import { createHash } from 'node:crypto';
const H=(b)=>createHash('sha256').update(b).digest();
const P=21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const HUGE=Number.MAX_SAFE_INTEGER;
const loose={...ConsensusBch2025,baseInstructionCost:100,maximumFunctionIdentifierLength:7,maximumMemorySlots:HUGE,maximumStandardLockingBytecodeLength:-1,maximumStandardUnlockingBytecodeLength:HUGE,maximumTokenCommitmentLength:128,operationCostBudgetPerByte:HUGE,maximumStackItemLength:HUGE,maximumVmNumberByteLength:HUGE,maximumStackDepth:HUGE,maximumControlStackDepth:HUGE,maximumBytecodeLength:HUGE,maximumOperationCount:HUGE};
const vm=createVirtualMachine(createInstructionSetBch2026(false,{consensus:loose,ripemd160,secp256k1,sha1,sha256}));
const pushInt=(n)=>{const d=bigIntToVmNumber(n);if(d.length===0)return Uint8Array.from([0x00]);if(d.length===1&&d[0]>=1&&d[0]<=16)return Uint8Array.from([0x50+d[0]]);if(d.length<=75)return Uint8Array.from([d.length,...d]);if(d.length<=255)return Uint8Array.from([0x4c,d.length,...d]);return Uint8Array.from([0x4d,d.length&0xff,(d.length>>8)&0xff,...d]);};
const le40=(n)=>{let x=((n%P)+P)%P;const b=new Uint8Array(40);for(let i=0;i<40;i++){b[i]=Number(x&0xffn);x>>=8n;}return b;};
const commit=(limbs)=>new Uint8Array(H(H(Buffer.concat(limbs.map(le40)))));
function jacDouble(x,y,z){const m=(a,b)=>(a*b)%P,s=a=>(a*a)%P,ad=(a,b)=>(a+b)%P,sb=(a,b)=>((a-b)%P+P)%P;const a=s(x),b=s(y),c=s(b);const d=m(2n,sb(sb(s(ad(x,b)),a),c));const e=m(3n,a);const f=s(e);return[sb(f,m(2n,d)),sb(m(e,sb(d,sb(f,m(2n,d)))),m(8n,c)),m(2n,m(y,z))];}
function jacAdd(aX,aY,aZ,bX,bY,bZ){const m=(a,b)=>(a*b)%P,s=a=>(a*a)%P,ad=(a,b)=>(a+b)%P,sb=(a,b)=>((a-b)%P+P)%P;let rx=bX,ry=bY,rz=bZ;if(aZ!==0n){const z1=s(aZ),z2=s(bZ),u1=m(aX,z2),u2=m(bX,z1),s1=m(m(aY,bZ),z2),s2=m(m(bY,aZ),z1);if(u1===u2&&s1===s2){const da=s(aX),db=s(aY),dc=s(db);const dd=m(2n,sb(sb(s(ad(aX,db)),da),dc));const de=m(3n,da);const df=s(de);rx=sb(df,m(2n,dd));ry=sb(m(de,sb(dd,rx)),m(8n,dc));rz=m(2n,m(aY,aZ));}else{const h=sb(u2,u1),i2=s(m(2n,h)),jj=m(h,i2),rr=m(2n,sb(s2,s1)),vv=m(u1,i2);rx=sb(sb(s(rr),jj),m(2n,vv));ry=sb(m(rr,sb(vv,rx)),m(2n,m(s1,jj)));rz=m(sb(sb(s(ad(aZ,bZ)),z1),z2),h);}}return[rx,ry,rz];}
function armRange(st,lo,hi){let[rX,rY,rZ,cX,cY,cZ,scalar]=st;for(let i=lo;i<hi;i++){if(((scalar>>BigInt(i))&1n)===1n){[rX,rY,rZ]=jacAdd(rX,rY,rZ,cX,cY,cZ);}if(cZ!==0n&&cY!==0n){[cX,cY,cZ]=jacDouble(cX,cY,cZ);}}return[rX,rY,rZ,cX,cY,cZ,scalar];}
const CAT=new Uint8Array(32).fill(0xcd);const tok=(c)=>({amount:0n,category:CAT,nft:{capability:'mutable',commitment:c}});
const redeem=hexToBin(readFileSync('/tmp/chunkA.hex','utf8').trim());const locking=Uint8Array.from([0x75,...redeem]);
const bits=Number(process.argv[2]??110);
const scalar=123456789n,bx=9269869340829791644953940526610795845982127221382366381974052273854848284744n,by=12340830433822638848259976740304056841548514693917037023437897137808450264577n;
const s0=[0n,1n,0n,bx,by,1n,scalar];const s1=armRange(s0,0,bits);
const argBytes=Uint8Array.from(s0.slice().reverse().flatMap(a=>[...pushInt(a)]));const N=10000-argBytes.length-3;
const unlock=Uint8Array.from([...argBytes,0x4d,N&0xff,(N>>8)&0xff,...new Uint8Array(N)]);
const st=vm.evaluate({inputIndex:0,sourceOutputs:[{lockingBytecode:locking,valueSatoshis:1000n,token:tok(commit(s0))}],transaction:{version:2,inputs:[{outpointTransactionHash:new Uint8Array(32),outpointIndex:0,sequenceNumber:0,unlockingBytecode:unlock}],outputs:[{lockingBytecode:locking,valueSatoshis:1000n,token:tok(commit(s1))}],locktime:0}});
const top=st.stack[st.stack.length-1];const ok=st.error===undefined&&st.stack.length===1&&top?.length===1&&top[0]===1;
console.log(`bits=${bits} trueOp=${st.metrics.operationCost.toLocaleString()} accepted=${ok} budget=8,032,800 fits=${st.metrics.operationCost<=8032800} ${st.error??''}`);
