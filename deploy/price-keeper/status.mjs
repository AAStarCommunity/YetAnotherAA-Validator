// Reads the outcome the keeper exists for: are the on-chain price caches fresh?
// A running process proves nothing; the last keeper ran for weeks while every RPC call returned 403.
// Exit 0 = every cache fresh and the keeper can pay gas. Exit 1 = not. Exit 2 = could not tell.
import { createRequire } from "node:module";
import { homedir } from "node:os";
import { readFileSync } from "node:fs";

const home = homedir();
const require = createRequire(`${home}/Dev/aastar/aastar-sdk-price-keeper/packages/core/package.json`);
const { createPublicClient, http, parseAbi, formatEther } = require("viem");

const rpc = readFileSync(`${home}/.config/aastar-price-keeper/rpc.env`, "utf8")
  .match(/^RPC_URL=["']?([^"'\n]+)/m)?.[1];
const keeper = readFileSync(`${home}/.config/aastar-price-keeper/address`, "utf8").trim();
const targets = {
  SuperPaymaster: process.env.KEEPER_SUPERPAYMASTER || "0x09DF0d2e3722EC0e401fE3819E64278a42ae4DE9",
  PaymasterV4: process.env.KEEPER_PAYMASTER || "0x2118e9a404C15F70B1D4f53b400c8a566A5ea4B6",
};
const abi = parseAbi([
  "function cachedPrice() view returns (int256, uint256)",
  "function priceStalenessThreshold() view returns (uint256)",
]);
const MIN_BALANCE_WEI = 10_000_000_000_000_000n; // 0.01 ETH

try {
  const client = createPublicClient({ transport: http(rpc) });
  const { timestamp } = await client.getBlock();
  let ok = true;
  for (const [name, address] of Object.entries(targets)) {
    const [, updatedAt] = await client.readContract({ address, abi, functionName: "cachedPrice" });
    const limit = await client.readContract({ address, abi, functionName: "priceStalenessThreshold" });
    const age = timestamp - updatedAt;
    const fresh = age <= limit;
    ok &&= fresh;
    console.log(`${fresh ? "FRESH" : "STALE"} ${name} ${address} age=${age}s limit=${limit}s`);
  }
  const balance = await client.getBalance({ address: keeper });
  const funded = balance >= MIN_BALANCE_WEI;
  ok &&= funded;
  console.log(`${funded ? "FUNDED" : "LOW_GAS"} keeper ${keeper} balance=${formatEther(balance)} ETH`);
  process.exit(ok ? 0 : 1);
} catch (error) {
  console.log(`UNDETERMINED ${error.shortMessage ?? error.message}`);
  process.exit(2);
}
