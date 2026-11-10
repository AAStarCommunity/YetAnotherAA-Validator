// Disclosure publication (M0 §5.3, DSR W2 ruling) for one flagged record. Idempotent: every step
// records its outcome in `state`, and a re-run skips what is done, so a crash or a failed provider
// is retried on the next tick without repeating finished work.
//
// Order: IPFS pins (each verified: provider CID == local CID, and the bytes fetched back by CID
// from that provider's public gateway are identical) -> GitHub mirror commit -> published (at least
// one verified pin AND the mirror commit) -> Telegram -> DisclosureRegistry.disclose (BLS records
// only; owner/guardian-route records have no on-chain signer evidence and get no registry entry).
//
// Sinks are injected (tests use mocks):
//   pinners:  [{ name, upload(bytes) -> { cid }, fetchPublic(cid) -> Uint8Array }]
//   mirror:   { commit(path, bytes, message) -> { commit, url } }
//   telegram: { send(text) -> void }
//   registry: { findEntry(kind, key) -> { entryId, txHash } | null,
//               disclose(args) -> { txHash, entryId? } }
import { ethers } from "ethers";
import { Kind } from "../../../scripts/disclosure/recheck-lib.mjs";
import { recordFile, mirrorPath } from "./record-file.mjs";

const bytesEqual = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
const errMsg = e => e?.shortMessage ?? e?.message ?? String(e);

/** The disclose() arguments for a BLS record (registry ABI: Signed + record context). */
export function discloseArgs(rec, file) {
  const kind = Kind[rec.kind];
  if (kind === undefined) throw new Error(`record kind ${rec.kind} has no registry kind`);
  const commit =
    rec.ruleset?.verified && rec.ruleset?.commit
      ? `0x${rec.ruleset.commit}`
      : ethers.ZeroHash.slice(0, 42);
  return {
    signed: {
      kind,
      proposalId: BigInt(rec.proposalId),
      messageInputs: rec.messageInputs,
      signerMask: BigInt(rec.signerMask),
      signers: rec.signers,
      anchor: rec.anchor,
    },
    subjectToken: rec.subjectToken ?? ethers.ZeroAddress,
    txHash: rec.txHash,
    blockNumber: BigInt(rec.blockNumber),
    rulesetCommit: commit,
    recordURI: `ipfs://${file.cid}`,
    recordHash: file.recordHash,
  };
}

export function telegramText(rec, file, mirror) {
  const what =
    rec.route === "bls"
      ? `BLS ${rec.kind} key ${rec.key} (signers ${rec.signers?.length ?? "?"})`
      : `${rec.label}: ${rec.event}`;
  return [
    `DISCLOSURE ${what}`,
    `tx ${rec.txHash} block ${rec.blockNumber}`,
    ...(rec.verdict?.reasons ?? []).map(r => `- ${r}`),
    `record ipfs://${file.cid}`,
    mirror?.url ? `mirror ${mirror.url}` : null,
  ]
    .filter(Boolean)
    .join("\n");
}

/**
 * Advance the publication of `rec` as far as the sinks allow. Returns { state, alerts }.
 * `state` is the previous state (or {}) and is returned updated; the caller persists it.
 */
export async function publishRecord(rec, sinks, prev = {}) {
  const file = recordFile(rec);
  const state = { ...prev, pins: { ...(prev.pins ?? {}) } };
  const alerts = [];
  if (state.cid && state.cid !== file.cid) {
    // Records are immutable once stored; a different CID means the bytes changed underneath us.
    alerts.push(
      `record bytes changed after first publication (${state.cid} -> ${file.cid}); not republishing`
    );
    return { state, alerts };
  }
  state.cid = file.cid;
  state.recordHash = file.recordHash;
  state.bytes = file.bytes.length;

  for (const p of sinks.pinners ?? []) {
    if (state.pins[p.name]?.ok) continue;
    const at = new Date().toISOString();
    try {
      const up = await p.upload(file.bytes);
      if (up?.cid !== file.cid) {
        state.pins[p.name] = {
          ok: false,
          at,
          error: `provider CID ${up?.cid} != local ${file.cid}`,
        };
        alerts.push(`${p.name}: CID mismatch (${up?.cid} vs ${file.cid})`);
        continue;
      }
      // Public readability by CID, byte for byte: a private or altered copy is not a publication.
      const back = await p.fetchPublic(file.cid);
      if (
        !back ||
        !bytesEqual(back instanceof Uint8Array ? back : ethers.getBytes(back), file.bytes)
      ) {
        state.pins[p.name] = {
          ok: false,
          at,
          error: "public gateway did not serve the exact bytes",
        };
        alerts.push(`${p.name}: public fetch by CID did not return the record bytes`);
        continue;
      }
      state.pins[p.name] = { ok: true, at, cid: file.cid };
    } catch (e) {
      state.pins[p.name] = { ok: false, at, error: errMsg(e) };
      alerts.push(`${p.name}: ${errMsg(e)}`);
    }
  }

  if (!state.mirror?.commit && sinks.mirror) {
    try {
      const path = mirrorPath(rec, file.cid);
      const m = await sinks.mirror.commit(path, file.bytes, `disclosure ${path}`);
      state.mirror = { commit: m.commit, url: m.url, path };
    } catch (e) {
      alerts.push(`mirror: ${errMsg(e)}`);
    }
  }

  const okPins = Object.values(state.pins).filter(x => x.ok).length;
  state.published = okPins >= 1 && !!state.mirror?.commit;
  if (state.published && okPins < (sinks.pinners?.length ?? 0)) {
    alerts.push(`published with ${okPins}/${sinks.pinners.length} pins; the others are retried`);
  }
  if (!state.published) return { state, alerts };

  if (!state.telegram?.at && sinks.telegram) {
    try {
      await sinks.telegram.send(telegramText(rec, file, state.mirror));
      state.telegram = { at: new Date().toISOString() };
    } catch (e) {
      alerts.push(`telegram: ${errMsg(e)}`);
    }
  }

  if (rec.route === "bls" && sinks.registry && !state.registry?.txHash) {
    try {
      // Never disclose the same action twice: a crash after broadcast must not cause a second entry.
      const existing = await sinks.registry.findEntry(Kind[rec.kind], BigInt(rec.key));
      if (existing) {
        state.registry = { ...existing, recovered: true };
      } else {
        const r = await sinks.registry.disclose(discloseArgs(rec, file));
        state.registry = { txHash: r.txHash, entryId: r.entryId ?? null };
      }
    } catch (e) {
      alerts.push(`registry: ${errMsg(e)}`);
    }
  }
  return { state, alerts };
}
