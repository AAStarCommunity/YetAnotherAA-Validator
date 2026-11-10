// Disclosure publication (M0 §5.3, DSR W2 ruling) for one flagged record. Resumable: after every
// stage the caller's `persist(state)` is awaited, so a crash repeats at most the stage in flight,
// and each stage is safe to repeat (below).
//
// Order: IPFS pins -> GitHub mirror commit -> published -> Telegram -> DisclosureRegistry.disclose
// (BLS records only; owner/guardian-route records have no on-chain signer evidence and no entry).
// - A pin is CURRENT only if the provider's CID equals the local CID and the bytes fetched back by
//   CID from its public gateway are identical. `reverify` re-checks current pins (weekly
//   reconcile); a pin that no longer serves is demoted and re-uploaded. Re-uploading the same
//   bytes is harmless (content addressing).
// - published = at least one CURRENT pin of a configured provider AND the mirror commit.
// - The mirror sink must be idempotent: committing a path that already holds identical bytes
//   returns the existing commit.
// - Telegram is at-least-once: the attempt is journalled before sending; after a crash between
//   the two, the message is re-sent marked as a possible duplicate.
// - Registry: exactly-once by a journal. The tx is SIGNED and persisted (raw, hash, nonce) before
//   it is broadcast; a restart rebroadcasts the same raw tx, never a new one. It is complete only
//   when its receipt succeeded and carries the Disclosed event. A reverted tx is alerted and not
//   retried blindly; a tx whose nonce was consumed by another tx is cleared and, after a fresh
//   findEntry(kind, key), re-signed.
//
// Sinks are injected (tests use mocks):
//   pinners:  [{ name, upload(bytes) -> { cid }, fetchPublic(cid) -> Uint8Array | null }]
//   mirror:   { commit(path, bytes, message) -> { commit, url } }   (idempotent, see above)
//   telegram: { send(text) -> void }
//   registry: { findEntry(kind, key) -> { entryId, txHash } | null,
//               sign(args) -> { raw, hash, nonce }, broadcast(raw) -> void,
//               receipt(hash) -> { status, entryId } | null, nonce() -> number }
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
 * opts.persist(state) is awaited after every stage; opts.reverify re-checks pins already current.
 */
export async function publishRecord(rec, sinks, prev = {}, opts = {}) {
  const persist = opts.persist ?? (async () => {});
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

  const configured = new Set((sinks.pinners ?? []).map(p => p.name));
  for (const p of sinks.pinners ?? []) {
    const cur = state.pins[p.name];
    const at = new Date().toISOString();
    if (cur?.current && !opts.reverify) continue;
    try {
      if (cur?.current) {
        // Reverify: still served, byte for byte? If not, demote and upload again below.
        const back = await p.fetchPublic(file.cid);
        if (
          back &&
          bytesEqual(back instanceof Uint8Array ? back : ethers.getBytes(back), file.bytes)
        ) {
          state.pins[p.name] = { ...cur, checkedAt: at };
          continue;
        }
        alerts.push(
          `${p.name}: a previously verified pin no longer serves the record; re-uploading`
        );
        state.pins[p.name] = { ...cur, current: false, lostAt: at };
      }
      const up = await p.upload(file.bytes);
      if (up?.cid !== file.cid) {
        state.pins[p.name] = {
          ...state.pins[p.name],
          current: false,
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
          ...state.pins[p.name],
          current: false,
          at,
          error: "public gateway did not serve the exact bytes",
        };
        alerts.push(`${p.name}: public fetch by CID did not return the record bytes`);
        continue;
      }
      state.pins[p.name] = { current: true, everOk: true, at, checkedAt: at, cid: file.cid };
    } catch (e) {
      state.pins[p.name] = { ...state.pins[p.name], current: false, at, error: errMsg(e) };
      alerts.push(`${p.name}: ${errMsg(e)}`);
    }
  }
  await persist(state);

  if (!state.mirror?.commit && sinks.mirror) {
    try {
      const path = mirrorPath(rec, file.cid);
      const m = await sinks.mirror.commit(path, file.bytes, `disclosure ${path}`);
      state.mirror = { commit: m.commit, url: m.url, path };
      await persist(state);
    } catch (e) {
      alerts.push(`mirror: ${errMsg(e)}`);
    }
  }

  const current = Object.entries(state.pins).filter(
    ([n, x]) => configured.has(n) && x.current
  ).length;
  state.published = current >= 1 && !!state.mirror?.commit;
  if (state.published && current < configured.size) {
    alerts.push(
      `published with ${current}/${configured.size} current pins; the others are retried`
    );
  }
  await persist(state);
  if (!state.published) return { state, alerts };

  if (sinks.telegram && !state.telegram?.at) {
    const retry = !!state.telegram?.attemptAt;
    state.telegram = { attemptAt: new Date().toISOString() };
    await persist(state);
    try {
      await sinks.telegram.send(
        (retry ? "(re-sent after an interrupted delivery; may be a duplicate)\n" : "") +
          telegramText(rec, file, state.mirror)
      );
      state.telegram = { ...state.telegram, at: new Date().toISOString() };
      await persist(state);
    } catch (e) {
      alerts.push(`telegram: ${errMsg(e)}`);
    }
  }

  if (rec.route === "bls" && sinks.registry && state.registry?.phase !== "confirmed") {
    try {
      await advanceRegistry(rec, file, sinks.registry, state, persist, alerts);
    } catch (e) {
      alerts.push(`registry: ${errMsg(e)}`);
    }
  }
  return { state, alerts };
}

async function advanceRegistry(rec, file, reg, state, persist, alerts) {
  const r = state.registry;
  if (r?.phase === "reverted") return; // alerted when it happened; needs a human, not a blind retry
  if (r?.phase === "signed" || r?.phase === "sent") {
    // Same raw tx, never a new one: rebroadcasting a known tx is harmless.
    try {
      await reg.broadcast(r.raw);
    } catch {
      /* "already known" / "nonce too low" are expected here; the receipt decides */
    }
    if (r.phase === "signed") {
      state.registry = { ...r, phase: "sent" };
      await persist(state);
    }
    const rc = await reg.receipt(r.hash);
    if (rc && Number(rc.status) === 1 && rc.entryId != null) {
      state.registry = { ...state.registry, phase: "confirmed", entryId: rc.entryId };
      await persist(state);
      return;
    }
    if (rc && Number(rc.status) !== 1) {
      state.registry = { ...state.registry, phase: "reverted" };
      await persist(state);
      alerts.push(`registry: disclose tx ${r.hash} reverted`);
      return;
    }
    if (rc && rc.entryId == null) {
      alerts.push(`registry: tx ${r.hash} succeeded without a Disclosed event`);
      return;
    }
    // No receipt yet. If our nonce is already used, this tx was replaced or dropped: start over.
    if ((await reg.nonce()) > r.nonce) {
      alerts.push(`registry: tx ${r.hash} (nonce ${r.nonce}) was dropped or replaced; re-signing`);
      state.registry = null;
      await persist(state);
    } else {
      return; // pending; next tick
    }
  }
  // Nothing in flight: an entry may already exist (an earlier publication completed elsewhere).
  const existing = await reg.findEntry(Kind[rec.kind], BigInt(rec.key));
  if (existing) {
    state.registry = {
      phase: "confirmed",
      entryId: existing.entryId,
      txHash: existing.txHash,
      recovered: true,
    };
    await persist(state);
    return;
  }
  const signed = await reg.sign(discloseArgs(rec, file));
  state.registry = { phase: "signed", raw: signed.raw, hash: signed.hash, nonce: signed.nonce };
  await persist(state); // journal BEFORE broadcast
  await reg.broadcast(signed.raw);
  state.registry = { ...state.registry, phase: "sent" };
  await persist(state);
  const rc = await reg.receipt(signed.hash);
  if (rc && Number(rc.status) === 1 && rc.entryId != null) {
    state.registry = { ...state.registry, phase: "confirmed", entryId: rc.entryId };
    await persist(state);
  }
}
