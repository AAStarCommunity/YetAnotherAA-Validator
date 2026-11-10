#!/usr/bin/env node
// Recheck one DisclosureRegistry entry from public RPC data only (M0 §4.4, §9 item 6).
//
//   RPC_URL=https://... node scripts/disclosure/recheck-entry.mjs --registry 0x.. --entry 3 \
//     --from-block <registry deploy block> [--aggregator 0x..] [--confirmations 12]
//
// Reads: the registry's Disclosed log and disclose() calldata, the action tx and receipt it names,
// the aggregator's domainSeparator / validatorAtSlot / proposalSignersCommitment, and block hashes,
// all against one snapshot (head - confirmations), with canonical-inclusion checks before and after.
// Uses no DVT node state, no keys, and no registry view other than AGGREGATOR (an immutable; pass
// --aggregator to take it from the release manifest instead). Logs are paged from --from-block.
// Exit 0 = MATCH (verified fields only; subjectToken, ruleset and record stay unverified claims),
// 1 = MISMATCH, 3 = INCONCLUSIVE (cannot be decided from the tx's own data), 2 = usage/RPC error.
// Sends no transaction.
import { ethers } from "ethers";
import { KIND_NAME, regIface, recheckEntry } from "./recheck-lib.mjs";

function arg(name) {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : undefined;
}
function usage(msg) {
  console.error(
    `error: ${msg}\nusage: RPC_URL=.. recheck-entry.mjs --registry <addr> --entry <id> --from-block <n> [--aggregator <addr>] [--confirmations <n>]`
  );
  process.exit(2);
}

const rpc = process.env.RPC_URL || usage("RPC_URL not set");
const registry = arg("registry");
const entry = arg("entry");
if (!registry || !ethers.isAddress(registry)) usage("--registry <address> required");
if (!entry || !/^\d+$/.test(entry)) usage("--entry <id> required");
const fromBlock = arg("from-block");
if (!fromBlock || !/^\d+$/.test(fromBlock)) usage("--from-block <registry deploy block> required");
const confirmations = arg("confirmations") ?? "12";
if (!/^\d+$/.test(confirmations)) usage("--confirmations must be a non-negative integer");

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
    fromBlock: Number(fromBlock),
    confirmations: Number(confirmations),
  });
  const out = {
    entryId: entry,
    registry,
    aggregator,
    status: r.status,
    reasons: r.reasons,
    diffs: r.diffs,
    unverified: r.unverified,
    rebuilt: r.rebuilt && {
      ...r.rebuilt,
      kind: KIND_NAME[r.rebuilt.kind],
      key: r.rebuilt.key.toString(),
      proposalId: r.rebuilt.proposalId.toString(),
      signerMask: "0x" + r.rebuilt.signerMask.toString(16),
    },
  };
  console.log(JSON.stringify(out, null, 2));
  console.error(`${r.status} entry ${entry}`);
  process.exit({ MATCH: 0, MISMATCH: 1, INCONCLUSIVE: 3 }[r.status] ?? 2);
} catch (e) {
  console.error(`rpc error: ${e.shortMessage ?? e.message}`);
  process.exit(2);
}
