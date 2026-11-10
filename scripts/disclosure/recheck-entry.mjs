#!/usr/bin/env node
// Recheck one DisclosureRegistry entry from public RPC data only (M0 §4.4, §9 item 6).
//
//   RPC_URL=https://... node scripts/disclosure/recheck-entry.mjs --registry 0x.. --entry 3 [--from-block N]
//
// Reads: the registry's Disclosed log and disclose() calldata, the action tx and receipt it names,
// the aggregator's domainSeparator / validatorAtSlot / proposalSignersCommitment, and one block hash.
// Uses no DVT node state, no keys, and no registry view other than AGGREGATOR (an immutable; pass
// --aggregator to take it from the release manifest instead). Exit 0 = entry matches; 1 = mismatch
// or unrecoverable; 2 = usage/RPC error. Sends no transaction.
import { ethers } from "ethers";
import { KIND_NAME, regIface, recheckEntry } from "./recheck-lib.mjs";

function arg(name) {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : undefined;
}
function usage(msg) {
  console.error(
    `error: ${msg}\nusage: RPC_URL=.. recheck-entry.mjs --registry <addr> --entry <id> [--aggregator <addr>] [--from-block <n>]`
  );
  process.exit(2);
}

const rpc = process.env.RPC_URL || usage("RPC_URL not set");
const registry = arg("registry");
const entry = arg("entry");
if (!registry || !ethers.isAddress(registry)) usage("--registry <address> required");
if (!entry || !/^\d+$/.test(entry)) usage("--entry <id> required");

try {
  const chain = new ethers.JsonRpcProvider(rpc);
  let aggregator = arg("aggregator");
  if (aggregator && !ethers.isAddress(aggregator)) usage("--aggregator must be an address");
  if (!aggregator) {
    const ret = await chain.call({
      to: registry,
      data: regIface.encodeFunctionData("AGGREGATOR", []),
    });
    aggregator = regIface.decodeFunctionResult("AGGREGATOR", ret)[0];
  }
  const r = await recheckEntry(chain, {
    registry: ethers.getAddress(registry),
    aggregator,
    entryId: BigInt(entry),
    fromBlock: Number(arg("from-block") ?? 0),
  });
  const out = {
    entryId: entry,
    registry,
    aggregator,
    ok: r.ok,
    reasons: r.reasons,
    diffs: r.diffs,
    rebuilt: r.rebuilt && {
      ...r.rebuilt,
      kind: KIND_NAME[r.rebuilt.kind],
      key: r.rebuilt.key.toString(),
      proposalId: r.rebuilt.proposalId.toString(),
      signerMask: "0x" + r.rebuilt.signerMask.toString(16),
    },
  };
  console.log(JSON.stringify(out, null, 2));
  console.error(r.ok ? `MATCH entry ${entry}` : `MISMATCH entry ${entry}`);
  process.exit(r.ok ? 0 : 1);
} catch (e) {
  console.error(`rpc error: ${e.shortMessage ?? e.message}`);
  process.exit(2);
}
