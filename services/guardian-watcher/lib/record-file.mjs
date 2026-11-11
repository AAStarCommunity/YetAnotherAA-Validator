// The published form of a watcher record: deterministic JSON bytes (keys sorted at every level,
// bigints as decimal strings, 2-space indent, trailing newline), so the same record always gives the
// same bytes, the same CID and the same recordHash. Local-only fields are stripped.
import { ethers } from "ethers";
import { cidV1Raw } from "./cid.mjs";
import { Store } from "./store.mjs";

export const RECORD_SCHEMA = "dvt.guardian-watcher.record.v1";
// Fields that record when or how often THIS host saw a record, not what it says, plus the store's
// file id. They stay local: the published record is exactly the content the second provider
// confirmed (D-RPC2; #422 review), which ignores the same fields (lib/confirm.mjs uses this set).
export const LOCAL_ONLY = new Set([
  "id",
  "seenAt",
  "firstSeen",
  "exhaustedAfter",
  "provenAt",
  "lastReasons",
]);

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

/** Path of a record in the GitHub mirror branch: a function of the record and its CID only. The id is
 * the store's own (Store.recordId), so a public, unattributed or quarantine record is never named
 * like an owner-route one. */
export function mirrorPath(record, cid) {
  // the path is built from chain data; make its shape an invariant (#409 review N2): the CID here,
  // the id below (the store's own record id, path-safe)
  if (!/^[a-z2-7]+$/.test(String(cid))) throw new Error("mirrorPath: CID is not base32");
  // an owner-route record is named by its tx and log position: both well-formed (#409 review N2);
  // unattributed and quarantine records keep their own ids (W2c)
  if (
    record.route === "owner" &&
    (!/^0x[0-9a-fA-F]{64}$/.test(String(record.txHash)) ||
      !Number.isSafeInteger(record.logIndex) ||
      record.logIndex < 0)
  )
    throw new Error(
      "mirrorPath: owner-route record needs a 32-byte txHash and an integer logIndex"
    );
  const id = Store.recordId(record);
  if (!/^[A-Za-z0-9._-]+$/.test(id)) throw new Error("record id not path-safe");
  return `records/${record.route}/${id}.${cid}.json`;
}
