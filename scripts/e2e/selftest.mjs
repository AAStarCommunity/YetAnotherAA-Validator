// DVT node self-test: hit the 3 running nodes (/node/info + /signature/sign) and assert
// the Stage-1 gate (bad ownerAuth -> 403). Usage: node scripts/e2e/selftest.mjs
import { ethers } from "ethers";
import { readFileSync } from "fs";
const strip=s=>s.replace(/^["']|["']$/g,"");
const env=Object.fromEntries(readFileSync(".env.sepolia","utf8").split("\n").filter(l=>l.includes("=")).map(l=>{const i=l.indexOf("=");return[l.slice(0,i).trim(),strip(l.slice(i+1).trim())]}));
const provider=new ethers.JsonRpcProvider(env.SEPOLIA_RPC_URL);
const ENTRY=env.ENTRY_POINT_ADDRESS||env.ENTRYPOINT_ADDRESS;
const ACCOUNT="0x45Dfe3D5938fDf5a8D30641C3FDA9c9fb1F31ba9";
const owner=new ethers.Wallet(env.PRIVATE_KEY_SUPPLIER);
const userOp={sender:ACCOUNT,nonce:"0",initCode:"0x",callData:"0x",accountGasLimits:"0x"+"00".repeat(32),preVerificationGas:"0",gasFees:"0x"+"00".repeat(32),paymasterAndData:"0x",signature:"0x"};
const ep=new ethers.Contract(ENTRY,["function getUserOpHash((address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData,bytes signature) userOp) view returns (bytes32)"],provider);
const uoh=await ep.getUserOpHash(userOp);
const ownerAuth=await owner.signMessage(ethers.getBytes(uoh));
for(const p of [3001,3002,3003]){
  const info=await (await fetch(`http://localhost:${p}/node/info`)).json();
  const r=await fetch(`http://localhost:${p}/signature/sign`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({userOp,ownerAuth})});
  const ok=r.ok; const j=ok?await r.json():await r.text();
  console.log(`:${p} info.nodeId=${(info.nodeId||"?").slice(0,12)}.. | sign ${ok?"✅ "+(j.message===uoh?"hash-bound":"??"):"❌ "+j}`);
}
const bad=await fetch(`http://localhost:3001/signature/sign`,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({userOp,ownerAuth:"0x"+"ab".repeat(65)})});
console.log(`:3001 bad ownerAuth -> HTTP ${bad.status} ${bad.status===403?"✅ fail-closed":"❌"}`);
