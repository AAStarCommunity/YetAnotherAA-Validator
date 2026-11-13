// The static half of "the detector holds no key, keystore, signing or broadcast code" (DSR), used
// by check-pause-detector.mjs. It parses each module (acorn), follows every static import and
// re-export from detector.mjs, and reports anything that could hold a key, sign, broadcast, run
// another program, or reach code the scan does not see. Syntax-aware (Codex R1 P1-1): comments and
// string contents are tokens of their own, not text to strip with regexes.
//
// The runtime half is readOnlyChain's method allowlist; this scan also pins WHERE the network can
// be reached at all: exactly one fetch for JSON-RPC (inside rpcTransport, behind the allowlist) and
// fetches to the Telegram Bot API only.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import * as acorn from "acorn";
import * as walk from "acorn-walk";

// names (identifiers and property names) that hold or use a key, sign, broadcast, or run code
export const FORBIDDEN_NAMES = new Set([
  "Wallet",
  "HDNodeWallet",
  "BaseWallet",
  "SigningKey",
  "AbstractSigner",
  "VoidSigner",
  "JsonRpcSigner",
  "NonceManager",
  "getSigner",
  "signTransaction",
  "signMessage",
  "signTypedData",
  "sendTransaction",
  "sendRawTransaction",
  "broadcastTransaction",
  "fromEncryptedJson",
  "fromEncryptedJsonSync",
  "encryptKeystoreJson",
  "decryptKeystoreJson",
  "Mnemonic",
  "fromPhrase",
  "JsonRpcProvider",
  "FetchRequest",
  "Contract",
  "privateKey",
  "keystore",
  "mnemonic",
  "spawn",
  "spawnSync",
  "exec",
  "execSync",
  "execFile",
  "execFileSync",
  "fork",
  // ways to reach code or globals the scan cannot see
  "eval",
  "Function",
  "globalThis",
  "global",
  "self",
  "window",
  "Reflect",
  "Proxy",
  "WebAssembly",
  "require",
  "createRequire",
  "module",
  "binding",
  "_linkedBinding",
  "dlopen",
]);
// text in string literals and template parts
export const FORBIDDEN_TEXT =
  /(sendRawTransaction|sendTransaction|eth_sign|personal_sign|signTransaction|signTypedData|privatekey|private_key|keystore|mnemonic|child_process|worker_threads|node:vm|node:module|mktx)/i;
// the only members of ethers the detector may use: pure ABI, hashing and formatting utilities
export const ETHERS_OK = new Set([
  "Interface",
  "getAddress",
  "isAddress",
  "dataSlice",
  "toQuantity",
  "toBeHex",
  "keccak256",
  "zeroPadValue",
  "ZeroAddress",
]);
// node modules and, for each, the named imports allowed (null: any)
export const NODE_OK = new Map([
  ["node:fs", null],
  ["node:os", null],
  ["node:path", null],
  ["node:url", null],
  ["node:net", new Set(["createServer"])], // the instance lock only
]);
const GUARDED_OBJECTS = new Set(["process", "ethers", "Object", "console"]);
const TELEGRAM = "https://api.telegram.org/bot";

/** Problems of one module's source; `onImport(spec)` is called for every relative import. Pure. */
export function scanSource(path, text, onImport = () => {}) {
  const p = [];
  const at = n => `${path}:${n.loc?.start?.line ?? "?"}`;
  let ast;
  try {
    ast = acorn.parse(text, { ecmaVersion: "latest", sourceType: "module", locations: true });
  } catch (e) {
    return [`${path}: does not parse (${e.message})`];
  }
  const source = (node, spec, specifiers) => {
    if (spec.startsWith(".")) {
      onImport(spec);
      return;
    }
    if (spec === "ethers") {
      for (const s of specifiers ?? [])
        if (
          s.type !== "ImportSpecifier" ||
          s.imported.name !== "ethers" ||
          s.local.name !== "ethers"
        )
          p.push(`${at(node)}: ethers may only be imported as { ethers }`);
      if (node.type !== "ImportDeclaration") p.push(`${at(node)}: re-export from ethers`);
      return;
    }
    if (!NODE_OK.has(spec)) {
      p.push(`${at(node)}: imports ${spec}`);
      return;
    }
    const ok = NODE_OK.get(spec);
    if (ok)
      for (const s of specifiers ?? [])
        if (s.type !== "ImportSpecifier" || !ok.has(s.imported.name))
          p.push(`${at(node)}: imports ${s.imported?.name ?? "*"} from ${spec}`);
    if (ok && node.type !== "ImportDeclaration") p.push(`${at(node)}: re-export from ${spec}`);
  };
  let rpcFetches = 0;
  walk.fullAncestor(ast, (node, _state, ancestors) => {
    const parent = ancestors[ancestors.length - 2];
    switch (node.type) {
      case "ImportDeclaration":
        source(node, node.source.value, node.specifiers);
        break;
      case "ExportAllDeclaration":
        source(node, node.source.value, null);
        break;
      case "ExportNamedDeclaration":
        if (node.source) source(node, node.source.value, null);
        break;
      case "ImportExpression":
        p.push(`${at(node)}: a dynamic import`);
        break;
      case "Identifier":
        if (FORBIDDEN_NAMES.has(node.name)) p.push(`${at(node)}: forbidden name ${node.name}`);
        if (node.name === "ethers") {
          const okUse =
            (parent?.type === "MemberExpression" &&
              parent.object === node &&
              !parent.computed &&
              ETHERS_OK.has(parent.property.name)) ||
            parent?.type === "ImportSpecifier";
          if (!okUse) p.push(`${at(node)}: ethers used other than as ethers.<allowed utility>`);
        }
        if (node.name === "fetch") {
          if (!(parent?.type === "CallExpression" && parent.callee === node))
            p.push(`${at(node)}: fetch referenced other than as a direct call`);
          else {
            const a0 = parent.arguments[0];
            const telegram =
              a0?.type === "TemplateLiteral" && a0.quasis[0]?.value?.cooked?.startsWith(TELEGRAM);
            const fn = [...ancestors].reverse().find(x => x.type === "FunctionDeclaration");
            const rpc =
              fn?.id?.name === "rpcTransport" && a0?.type === "Identifier" && a0.name === "url";
            if (rpc) rpcFetches++;
            if (!telegram && !rpc)
              p.push(
                `${at(node)}: fetch to something other than the Telegram Bot API or rpcTransport`
              );
          }
        }
        break;
      case "PrivateIdentifier":
        if (FORBIDDEN_NAMES.has(node.name)) p.push(`${at(node)}: forbidden name ${node.name}`);
        break;
      case "MemberExpression":
        if (!node.computed && FORBIDDEN_NAMES.has(node.property.name))
          p.push(`${at(node)}: forbidden member ${node.property.name}`);
        if (!node.computed && node.property.name === "fetch")
          p.push(`${at(node)}: fetch reached as a member`);
        if (
          node.computed &&
          node.object.type === "Identifier" &&
          GUARDED_OBJECTS.has(node.object.name)
        )
          p.push(`${at(node)}: computed member of ${node.object.name}`);
        break;
      case "Property":
        if (!node.computed && node.key.type === "Identifier" && FORBIDDEN_NAMES.has(node.key.name))
          p.push(`${at(node)}: forbidden key ${node.key.name}`);
        break;
      case "Literal":
        if (typeof node.value === "string" && FORBIDDEN_TEXT.test(node.value))
          p.push(`${at(node)}: forbidden text in a string`);
        break;
      case "TemplateElement":
        if (FORBIDDEN_TEXT.test(node.value.cooked ?? node.value.raw))
          p.push(`${at(node)}: forbidden text in a template`);
        break;
      default:
    }
  });
  if (rpcFetches > 1) p.push(`${path}: more than one JSON-RPC fetch`);
  return p;
}

/** Problems of `path` and every module it reaches by static import or re-export. */
export function scanTree(path, read = f => readFileSync(f, "utf8"), seen = new Set()) {
  if (seen.has(path)) return [];
  seen.add(path);
  let text;
  try {
    text = read(path);
  } catch {
    return [`${path}: cannot be read`];
  }
  if (typeof text !== "string") return [`${path}: cannot be read`];
  const next = [];
  const p = scanSource(path, text, spec => next.push(resolve(dirname(path), spec)));
  for (const n of next) p.push(...scanTree(n, read, seen));
  return p;
}
