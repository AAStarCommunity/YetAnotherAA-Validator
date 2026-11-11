// The published form of a watcher record: deterministic JSON bytes (keys sorted at every level,
// bigints as decimal strings, 2-space indent, trailing newline), so the same record always gives the
// same bytes, the same CID and the same recordHash. Local-only fields are stripped.
import { ethers } from "ethers";
import { cidV1Raw } from "./cid.mjs";

export const RECORD_SCHEMA = "dvt.guardian-watcher.record.v1";
const LOCAL_ONLY = new Set(["seenAt", "id"]); // when this host saw it, and the store's file id

function canon(v) {
  if (typeof v === "bigint") return v.toString();
  if (Array.isArray(v)) return v.map(canon);
  if (v && typeof v === "object") {
    const out = {};
    for (const k of Object.keys(v).sort()) {
      if (v[k] === undefined) continue;
      out[k] = canon(v[k]);
    }
    return out;
  }
  return v;
}

/** { bytes, cid, recordHash, json } for a record. Throws if the file exceeds the CID cap. */
export function recordFile(record, { recheck } = {}) {
  const body = {};
  for (const [k, v] of Object.entries(record)) if (!LOCAL_ONLY.has(k)) body[k] = v;
  const doc = canon({ schema: RECORD_SCHEMA, record: body, ...(recheck ? { recheck } : {}) });
  const json = JSON.stringify(doc, null, 2) + "\n";
  const bytes = new TextEncoder().encode(json);
  return { bytes, json, cid: cidV1Raw(bytes), recordHash: ethers.keccak256(bytes) };
}

/** Path of a record in the GitHub mirror branch: a function of the record and its CID only. */
export function mirrorPath(record, cid) {
  // the path is built from chain data; make its shape an invariant (#409 review N2)
  if (!/^[a-z2-7]+$/.test(String(cid))) throw new Error("mirrorPath: CID is not base32");
  if (
    record.route !== "bls" &&
    (!/^0x[0-9a-fA-F]{64}$/.test(String(record.txHash)) ||
      !Number.isSafeInteger(record.logIndex) ||
      record.logIndex < 0)
  )
    throw new Error(
      "mirrorPath: owner-route record needs a 32-byte txHash and an integer logIndex"
    );
  const id =
    record.route === "bls"
      ? `bls-${record.kind}-${BigInt(record.key).toString(16).padStart(64, "0")}`
      : `owner-${String(record.txHash).toLowerCase()}-${record.logIndex}`;
  return `records/${record.route}/${id}.${cid}.json`;
}
