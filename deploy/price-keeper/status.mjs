// Reads the outcome the keeper exists for: are the on-chain price caches fresh?
// A running process proves nothing; the last keeper ran for weeks while every RPC call returned 403.
// Exit 0 = every cache fresh and the keeper can pay gas. Exit 1 = not. Exit 2 = could not tell.
//
// One entry per run: the directory this file is installed in (~/.config/aastar-price-keeper-<entry>/),
// nothing else. The entry's files are checked by the same rules as run.sh (which refuses to start on
// any of them), so a setup run.sh refuses is UNDETERMINED here, never FRESH or STALE.
import { createRequire } from "node:module";
import { homedir } from "node:os";
import { existsSync, lstatSync, readFileSync, realpathSync, statSync } from "node:fs";
import { basename, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ENTRY_FIELDS = new Set([
  "KEEPER_ENTRY",
  "KEEPER_NETWORK",
  "KEEPER_SDK_DIR",
  "KEEPER_SUPERPAYMASTER",
  "KEEPER_PAYMASTER",
  "KEEPER_HARD_MAX_FEE_GWEI",
  "KEEPER_MIN_BALANCE_WEI",
  "KEEPER_ETHUSD_URL",
  "KEEPER_POLL_INTERVAL",
  "KEEPER_SAFETY_MARGIN",
  "KEEPER_HEALTH_INTERVAL",
  "KEEPER_CHAINLINK_STALE_SEC",
  "KEEPER_VOL_BPS",
  "KEEPER_VOL_COOLDOWN",
]);
const CHAIN_ID = { "op-sepolia": 11155420, sepolia: 11155111, "op-mainnet": 10, mainnet: 1 };
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const HEAD_MAX_AGE_SEC = 300n;

// The grammar of run.sh's read_fields: blank, comment, or NAME=value with NAME allowed, at most once;
// value bare (no quote, $, backtick, backslash, space or shell metacharacter) or wholly in double quotes.
function readFields(file, allowed) {
  const name = basename(file);
  const out = {};
  // the type first, so a FIFO or a directory is refused instead of blocking or throwing late
  if (!statSync(file).isFile()) throw new Error(`${name} is not a regular file`);
  const bytes = readFileSync(file);
  // printable ASCII and newlines only, as run.sh requires, so both read the same bytes
  if (bytes.some(b => b !== 0x0a && (b < 0x20 || b > 0x7e)))
    throw new Error(`${name} holds a byte outside printable ASCII`);
  bytes
    .toString("latin1")
    .split("\n")
    .forEach((line, i) => {
      if (line === "" || line.startsWith("#")) return;
      const m = line.match(/^([A-Z_][A-Z0-9_]*)=(.*)$/);
      if (!m) throw new Error(`${name} line ${i + 1} is not NAME=value`);
      const [, key, raw] = m;
      if (!allowed.has(key))
        throw new Error(`${name} line ${i + 1}: ${key} is not allowed in this file`);
      const quoted = raw.match(/^"([^"$`\\]*)"$/);
      if (!quoted && !/^[^"'$`\\;&|<>()\s]*$/.test(raw))
        throw new Error(`${name} line ${i + 1}: ${key} has an unsupported value`);
      if (key in out) throw new Error(`${name} line ${i + 1}: ${key} is set twice`);
      out[key] = quoted ? quoted[1] : raw;
    });
  return out;
}

// Everything that can throw, including reading the config and loading viem, is inside try, so a
// broken setup reports UNDETERMINED (exit 2) instead of crashing with exit 1, which reads as STALE.
try {
  const dir = realpathSync(dirname(fileURLToPath(import.meta.url)));
  const entry = readFields(`${dir}/entry.env`, ENTRY_FIELDS);
  const e = entry.KEEPER_ENTRY ?? "";
  if (!/^[a-z0-9][a-z0-9-]*$/.test(e) || basename(dir) !== `aastar-price-keeper-${e}`)
    throw new Error(`entry.env: KEEPER_ENTRY ${JSON.stringify(e)} does not name this directory`);
  const chainId = Object.hasOwn(CHAIN_ID, entry.KEEPER_NETWORK ?? "")
    ? CHAIN_ID[entry.KEEPER_NETWORK]
    : 0;
  if (!chainId)
    throw new Error("entry.env: KEEPER_NETWORK must be op-sepolia, sepolia, op-mainnet or mainnet");
  if (!ADDRESS.test(entry.KEEPER_SUPERPAYMASTER ?? ""))
    throw new Error("entry.env: KEEPER_SUPERPAYMASTER missing or not an address");
  if (entry.KEEPER_PAYMASTER && !ADDRESS.test(entry.KEEPER_PAYMASTER))
    throw new Error("entry.env: KEEPER_PAYMASTER is not an address");
  if (!/^[0-9]+(\.[0-9]+)?$/.test(entry.KEEPER_HARD_MAX_FEE_GWEI ?? ""))
    throw new Error("entry.env: KEEPER_HARD_MAX_FEE_GWEI missing");
  if (!/^~\/Dev\/aastar\/aastar-sdk[A-Za-z0-9._-]*$/.test(entry.KEEPER_SDK_DIR ?? ""))
    throw new Error("entry.env: KEEPER_SDK_DIR must be ~/Dev/aastar/aastar-sdk<suffix>");
  if (!/^[0-9]+$/.test(entry.KEEPER_MIN_BALANCE_WEI ?? ""))
    throw new Error("entry.env: KEEPER_MIN_BALANCE_WEI missing or not an integer");
  for (const k of [
    "KEEPER_POLL_INTERVAL",
    "KEEPER_SAFETY_MARGIN",
    "KEEPER_HEALTH_INTERVAL",
    "KEEPER_CHAINLINK_STALE_SEC",
    "KEEPER_VOL_BPS",
    "KEEPER_VOL_COOLDOWN",
  ])
    if (entry[k] && !/^[0-9]+$/.test(entry[k]))
      throw new Error(`entry.env: ${k} must be an integer`);
  // The credential files run.sh needs: their type and shape are checked, no value is used or
  // printed. The type comes first, so a FIFO or a link a mainnet entry may not have is never opened.
  if (chainId === 10 || chainId === 1) {
    if (lstatSync(`${dir}/key.env`).isSymbolicLink())
      throw new Error(
        "key.env is a link; a mainnet entry needs its own key (run.sh refuses to start)"
      );
  }
  const key = readFields(`${dir}/key.env`, new Set(["KEEPER_PRIVATE_KEY"])).KEEPER_PRIVATE_KEY;
  if (!/^0x[0-9a-fA-F]{64}$/.test(key ?? ""))
    throw new Error(
      "key.env: KEEPER_PRIVATE_KEY must be 0x and 64 hex digits (run.sh refuses to start)"
    );
  if (existsSync(`${dir}/telegram.env`))
    readFields(`${dir}/telegram.env`, new Set(["TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"]));
  const sdk = `${homedir()}/${entry.KEEPER_SDK_DIR.slice(2)}`;
  for (const f of [`.env.${entry.KEEPER_NETWORK}`, ".env.optimism", ".env.op-mainnet"])
    if (existsSync(`${sdk}/${f}`)) throw new Error(`${sdk}/${f} exists; run.sh refuses to start`);

  const require = createRequire(`${sdk}/packages/core/package.json`);
  const { createPublicClient, http, parseAbi, formatEther } = require("viem");
  const { privateKeyToAccount } = require("viem/accounts");

  const rpc = readFields(`${dir}/rpc.env`, new Set(["RPC_URL"])).RPC_URL;
  if (!rpc) throw new Error("RPC_URL missing from rpc.env");
  // exactly one line, as run.sh reads it: the address and at most one trailing newline
  if (!statSync(`${dir}/address`).isFile()) throw new Error("address is not a regular file");
  const keeper = readFileSync(`${dir}/address`, "utf8").replace(/\n$/, "");
  if (!ADDRESS.test(keeper))
    throw new Error("address file must hold exactly one address on one line");
  // The account this check watches must be the one that signs, as run.sh requires before it starts
  // the keeper. Only addresses are compared and printed, never the key.
  const signer = privateKeyToAccount(key).address;
  if (signer.toLowerCase() !== keeper.toLowerCase())
    throw new Error(
      `key.env signs as ${signer}, but the address file names ${keeper} (run.sh refuses to start)`
    );
  // Only the contracts this entry updates: an entry without a PaymasterV4 checks no V4.
  const targets = { SuperPaymaster: entry.KEEPER_SUPERPAYMASTER };
  if (entry.KEEPER_PAYMASTER) targets.PaymasterV4 = entry.KEEPER_PAYMASTER;
  const abi = parseAbi([
    "function cachedPrice() view returns (int256, uint256)",
    "function priceStalenessThreshold() view returns (uint256)",
  ]);
  const MIN_BALANCE_WEI = BigInt(entry.KEEPER_MIN_BALANCE_WEI);

  const client = createPublicClient({ transport: http(rpc) });
  const got = await client.getChainId();
  if (got !== chainId)
    throw new Error(`rpc.env RPC_URL is chain ${got}, entry ${e} is chain ${chainId}`);
  // Every read at one block, so the cache time and the block time cannot straddle two heights.
  const { number: blockNumber, timestamp } = await client.getBlock();
  // A stalled or lagging RPC serves an old head in which a cache can still look fresh: the head must
  // be recent by the wall clock (OP and Ethereum produce a block every 2-12 s).
  const headAge = BigInt(Math.floor(Date.now() / 1000)) - timestamp;
  if (headAge > HEAD_MAX_AGE_SEC || headAge < -60n)
    throw new Error(
      `RPC head block ${blockNumber} is ${headAge}s old by the wall clock (limit ${HEAD_MAX_AGE_SEC}s)`
    );
  let ok = true;
  for (const [name, address] of Object.entries(targets)) {
    const [, updatedAt] = await client.readContract({
      address,
      abi,
      functionName: "cachedPrice",
      blockNumber,
    });
    const limit = await client.readContract({
      address,
      abi,
      functionName: "priceStalenessThreshold",
      blockNumber,
    });
    const age = timestamp - updatedAt;
    if (age < 0n) throw new Error(`${name} cache time is after its block time (age ${age}s)`);
    const fresh = age <= limit;
    ok &&= fresh;
    console.log(`${fresh ? "FRESH" : "STALE"} ${name} ${address} age=${age}s limit=${limit}s`);
  }
  const balance = await client.getBalance({ address: keeper, blockNumber });
  const funded = balance >= MIN_BALANCE_WEI;
  ok &&= funded;
  console.log(
    `${funded ? "FUNDED" : "LOW_GAS"} keeper ${keeper} balance=${formatEther(balance)} ETH`
  );
  process.exit(ok ? 0 : 1);
} catch (error) {
  console.log(`UNDETERMINED ${error.shortMessage ?? error.message}`);
  process.exit(2);
}
