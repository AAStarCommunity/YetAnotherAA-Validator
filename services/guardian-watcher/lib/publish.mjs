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
//   retried blindly; a tx whose nonce was consumed by another tx is cleared and re-signed. The
//   registry itself refuses a second entry for the same action (AlreadyDisclosed), so a misjudged
//   drop or a second process costs at most a reverted tx. An existing entry counts as ours only if
//   its stored binding equals keccak256(abi.encode(kind, key, subjectToken)) of this record;
//   otherwise it is a CONFLICT, parked and re-alerted like a revert.
//
// Sinks are injected (tests use mocks):
//   pinners:  [{ name, upload(bytes) -> { cid }, fetchPublic(cid) -> Uint8Array | null }]
//   mirror:   { commit(path, bytes, message) -> { commit, url } }   (idempotent, see above)
//   telegram: { send(text) -> void }
//   registry: { finalized() -> block number,
//               entryOf(kind, key, { blockTag }) -> entryId (0 = none),
//               entry(entryId, { blockTag }) -> { binding, recordURI, recordHash, amendments[] },
//               sign(args, { nonce?, replace?, prevRaw? }) -> { raw, hash, nonce }, broadcast(raw) -> void,
//               receipt(hash) -> { status, entryId, blockNumber, blockHash } | null,
//               canonical(blockNumber, blockHash) -> bool,
//               nonce() -> the writer's nonce at the FINALIZED block }
import { ethers } from "ethers";
import { SafeError, safeCode, safeText } from "./safe-error.mjs";
import { Kind } from "../../../scripts/disclosure/recheck-lib.mjs";
import { recordFile, mirrorPath } from "./record-file.mjs";

/** A failure to persist state: publication must stop, the returned state is NOT durable. */
export class PersistError extends SafeError {
  constructor(cause) {
    super(`persist failed: ${safeCode(cause)}`); // the cause is not kept: its text is untrusted
    this.name = "PersistError";
  }
}

const bytesEqual = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
// Never e.shortMessage / e.message of a foreign error (Codex W2b R3): see lib/safe-error.mjs.
const errMsg = e => safeText("unexpected", e);

/** The disclose() arguments for a BLS record (registry ABI: Signed + record context). */
export function discloseArgs(rec, file) {
  const kind = Kind[rec.kind];
  if (kind === undefined) throw new SafeError(`record kind ${rec.kind} has no registry kind`);
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
  // The journal is the crash-safety guarantee; without a durable persist there is none, so it is
  // required. Only an explicitly unsafe test mode may skip it.
  if (typeof opts.persist !== "function" && opts.unsafeNoJournal !== true) {
    throw new SafeError(
      "publishRecord needs opts.persist (durable state); unsafeNoJournal is for tests only"
    );
  }
  const rawPersist = opts.persist ?? (async () => {});
  const persist = async st => {
    try {
      await rawPersist(st);
    } catch (e) {
      throw new PersistError(e); // never mistaken for a sink failure: the caller must stop
    }
  };
  const file = recordFile(rec);
  const state = { ...prev, pins: { ...(prev.pins ?? {}) } };
  const alerts = [];
  // Stage failures (a sink that errored or refused), as distinct from pending work: the pass is
  // not "ok" while any stage failed (Codex W2c R3).
  const failures = [];
  // Unresolved registry incidents are re-alerted on EVERY run, before anything can return early.
  const inc = prev.registry;
  if ((inc?.phase === "conflict" || inc?.phase === "reverted") && !inc.ack) {
    alerts.push(
      inc.phase === "conflict"
        ? `registry: entry ${inc.entryId} for this action has ${inc.conflict ?? "a conflict"}; INCIDENT, unresolved until acknowledged`
        : `registry: disclose tx reverted (${inc.reason ?? "no reason recorded"}); unresolved until acknowledged`
    );
  }
  if (state.bytesChanged) {
    // A recorded bytes change stands until resolved by hand (the marker is removed), even if the
    // bytes have changed back: alerted on every pass, and nothing else runs (Codex W2c R2).
    alerts.push(
      `record bytes changed after first publication (${state.bytesChanged.from} -> ${state.bytesChanged.to}); not republishing; INCIDENT until resolved by hand`
    );
    return { state, alerts, failures };
  }
  if (state.cid && state.cid !== file.cid) {
    // Records are immutable once stored; a different CID means the bytes changed underneath us.
    // A durable, standing incident (Codex W2c R1 M4): it keeps the record out of "done" and is
    // alerted on every pass until resolved by hand; it is never republished automatically.
    alerts.push(
      `record bytes changed after first publication (${state.cid} -> ${file.cid}); not republishing; INCIDENT`
    );
    if (state.bytesChanged?.to !== file.cid) {
      state.bytesChanged = { from: state.cid, to: file.cid, at: new Date().toISOString() };
      await persist(state);
    }
    return { state, alerts, failures };
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
          error: `provider CID differs from local ${file.cid}`,
        };
        alerts.push(`${p.name}: CID mismatch (local ${file.cid})`);
        failures.push(`pin:${p.name}`);
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
        failures.push(`pin:${p.name}`);
        continue;
      }
      state.pins[p.name] = { current: true, everOk: true, at, checkedAt: at, cid: file.cid };
    } catch (e) {
      if (e instanceof PersistError) throw e;
      state.pins[p.name] = { ...state.pins[p.name], current: false, at, error: errMsg(e) };
      alerts.push(`${p.name}: ${errMsg(e)}`);
      failures.push(`pin:${p.name}`);
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
      if (e instanceof PersistError) throw e;
      alerts.push(`mirror: ${errMsg(e)}`);
      failures.push("mirror");
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
  if (!state.published) return { state, alerts, failures };

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
      if (e instanceof PersistError) throw e;
      alerts.push(`telegram: ${errMsg(e)}`);
      failures.push("telegram");
    }
  }

  if (rec.route === "bls" && sinks.registry && state.registry?.phase !== "confirmed") {
    try {
      await advanceRegistry(rec, file, sinks.registry, state, persist, alerts, opts);
    } catch (e) {
      if (e instanceof PersistError) throw e;
      alerts.push(`registry: ${errMsg(e)}`);
      failures.push("registry");
    }
  }
  return { state, alerts, failures };
}

export const DEFAULT_MAX_PENDING_MS = 30 * 60_000;

/**
 * On-chain content is untrusted text, and its shape proves nothing (a base32-shaped string can
 * still carry a secret; Codex W2b R4). A URI is kept in plain text only when it EQUALS the URI we
 * expect; otherwise only the digest of the original string is kept, which still tells two
 * different conflicting values apart.
 */
export function storable(c, expectedURI) {
  const same = c.recordURI != null && c.recordURI === expectedURI;
  const digest =
    c.recordURIKeccak ??
    (c.recordURI == null ? null : ethers.keccak256(ethers.toUtf8Bytes(String(c.recordURI))));
  return {
    recordURI: same ? c.recordURI : null,
    recordURIKeccak: digest,
    recordHash: /^0x[0-9a-f]{64}$/.test(c.recordHash) ? c.recordHash : null,
  };
}

/** Effective record content of an existing entry: the latest amendment wins, in order. */
function effectiveContent(entry) {
  const last = (entry.amendments ?? []).at(-1);
  return {
    recordURI: last?.recordURI ?? entry.recordURI,
    recordURIKeccak: last ? last.recordURIKeccak : entry.recordURIKeccak,
    recordHash: String(last?.recordHash ?? entry.recordHash).toLowerCase(),
  };
}

/**
 * Registry stage. Every read that decides completion is taken at the FINALIZED block, so a reorg
 * cannot leave a "confirmed" that is no longer on chain. Phases:
 *   signed -> sent -> landed (receipt ok, not yet final) -> confirmed (final, content verified)
 *   reverted | conflict (parked, re-alerted by publishRecord until acknowledged)
 */
async function advanceRegistry(rec, file, reg, state, persist, alerts, opts) {
  const r = state.registry;
  if (r?.phase === "conflict" || r?.phase === "reverted") return; // alerted by publishRecord
  const maxPendingMs = opts.maxPendingMs ?? DEFAULT_MAX_PENDING_MS;

  if (r?.phase === "signed" || r?.phase === "sent" || r?.phase === "landed") {
    // Rebroadcast the latest raw of the journal (never a newly signed one for the same nonce
    // unless replacing a stuck tx below); a known tx is harmless.
    try {
      await reg.broadcast(r.raw);
    } catch (e) {
      state.registry = { ...r, lastBroadcastError: errMsg(e) };
    }
    // A resumed in-flight journal (including one written before sentAt existed) gets its sentAt
    // once, so the stuck-tx timeout can elapse.
    state.registry = {
      ...state.registry,
      phase: r.phase === "signed" ? "sent" : r.phase,
      sentAt: r.sentAt ?? new Date().toISOString(),
    };
    await persist(state);
    // Any of the journalled hashes (original and replacements) may be the one that landed. A
    // receipt counts only if its block is canonical: an orphaned receipt is ignored, the other
    // hashes are checked, and pending/dropped recovery resumes.
    let rc = null;
    for (const h of state.registry.hashes ?? [state.registry.hash]) {
      const c = await reg.receipt(h);
      if (!c) continue;
      if (!(await reg.canonical(c.blockNumber, c.blockHash))) {
        alerts.push(`registry: receipt of ${h} is on an orphaned block; ignored`);
        continue;
      }
      rc = c;
      break;
    }
    if (rc && Number(rc.status) === 1 && rc.entryId != null) {
      return settleLanded(rec, file, reg, state, persist, alerts, rc);
    }
    if (rc && Number(rc.status) !== 1) {
      // A failure is final only once its block is finalized; until then it may still reorg away,
      // or the competing entry (AlreadyDisclosed) may not be final yet.
      if (Number(rc.blockNumber) > (await reg.finalized())) return;
      // Finality established; only now is canonicality decisive. Re-check it: the receipt's branch
      // may have been reorged out before the replacement branch finalized.
      if (!(await reg.canonical(rc.blockNumber, rc.blockHash))) {
        alerts.push(
          `registry: failed receipt's block was reorged out before finality; not parking`
        );
        return;
      }
      // Reverted - possibly AlreadyDisclosed because another tx of ours landed first.
      if (await adoptExisting(rec, file, reg, state, persist, alerts)) return;
      state.registry = {
        ...state.registry,
        phase: "reverted",
        reason: rc.reason ?? "status 0",
        revertedAt: new Date().toISOString(),
      };
      await persist(state);
      alerts.push(
        `registry: disclose tx reverted (${state.registry.reason}); unresolved until acknowledged`
      );
      return;
    }
    if (rc && rc.entryId == null) {
      alerts.push(`registry: a disclose tx succeeded without a Disclosed event`);
      return;
    }
    // No receipt. Nonce consumed at the FINALIZED block without any of our hashes landing: the
    // journalled txs are dead. On-chain uniqueness makes a re-sign safe.
    if ((await reg.nonce()) > state.registry.nonce) {
      alerts.push(
        `registry: disclose tx (nonce ${state.registry.nonce}) was dropped or replaced; re-signing`
      );
      state.registry = null;
      await persist(state);
    } else {
      const age = Date.now() - Date.parse(state.registry.sentAt ?? new Date().toISOString());
      if (age < maxPendingMs) return; // pending; next tick
      // Stuck (evicted or underpriced) with its nonce unused: replace it at the SAME nonce with a
      // higher fee, journalled before broadcast like the original.
      alerts.push(
        `registry: disclose tx pending ${Math.round(age / 60000)} min; replacing at nonce ${state.registry.nonce}`
      );
      // The sink takes its fee floor from the tx being replaced (its journalled raw bytes, the
      // source of truth), so each replacement clears the node's >= 10% rule (W2b R1 H4).
      const rep = await reg.sign(discloseArgs(rec, file), {
        nonce: state.registry.nonce,
        replace: true,
        prevRaw: state.registry.raw,
      });
      const hashes = [...(state.registry.hashes ?? [state.registry.hash]), rep.hash];
      state.registry = {
        ...state.registry,
        raw: rep.raw,
        hash: rep.hash,
        hashes,
        sentAt: new Date().toISOString(),
        replacements: (state.registry.replacements ?? 0) + 1,
      };
      await persist(state); // journal BEFORE broadcast
      await reg.broadcast(rep.raw);
      return;
    }
  }
  // Nothing in flight: an entry may already exist (an earlier publication completed elsewhere).
  if (await adoptExisting(rec, file, reg, state, persist, alerts)) return;
  const signed = await reg.sign(discloseArgs(rec, file));
  state.registry = {
    phase: "signed",
    raw: signed.raw,
    hash: signed.hash,
    hashes: [signed.hash],
    nonce: signed.nonce,
  };
  await persist(state); // journal BEFORE broadcast
  await reg.broadcast(signed.raw);
  state.registry = { ...state.registry, phase: "sent", sentAt: new Date().toISOString() };
  await persist(state);
}

/** A successful receipt: confirmed only once final and the entry at the finalized block is ours. */
async function settleLanded(rec, file, reg, state, persist, alerts, rc) {
  const fin = await reg.finalized();
  if (rc.blockNumber == null || Number(rc.blockNumber) > fin) {
    state.registry = {
      ...state.registry,
      phase: "landed",
      entryId: String(rc.entryId),
      landedBlock: rc.blockNumber,
    };
    await persist(state);
    return;
  }
  if (await adoptExisting(rec, file, reg, state, persist, alerts)) return;
  // Final receipt but no entry at the finalized block: inconsistent RPC; stay landed, alert.
  state.registry = { ...state.registry, phase: "landed", entryId: String(rc.entryId) };
  await persist(state);
  alerts.push(`registry: receipt final but entry ${rc.entryId} not visible at the finalized block`);
}

/** The binding the registry stores for this record's entry (DisclosureRegistry._append). */
export function expectedBinding(rec) {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint8", "uint256", "address"],
      [Kind[rec.kind], BigInt(rec.key), rec.subjectToken ?? ethers.ZeroAddress]
    )
  );
}

/**
 * If the registry already holds this action's entry AT THE FINALIZED BLOCK, adopt it only if both
 * its binding and its effective record content (URI and hash, after amendments) are this record's.
 * Anything else is an incident: a different binding, or the right binding with other content (for
 * example written by a compromised writer key). Both are parked and re-alerted.
 */
async function adoptExisting(rec, file, reg, state, persist, alerts) {
  const fin = await reg.finalized();
  const id = BigInt(await reg.entryOf(Kind[rec.kind], BigInt(rec.key), { blockTag: fin }));
  if (id === 0n) return false;
  const e = await reg.entry(id, { blockTag: fin });
  const bindingOk = String(e.binding).toLowerCase() === expectedBinding(rec).toLowerCase();
  const eff = effectiveContent(e);
  const contentOk =
    eff.recordHash === file.recordHash.toLowerCase() && eff.recordURI === `ipfs://${file.cid}`;
  if (bindingOk && contentOk) {
    state.registry = {
      ...(state.registry ?? {}),
      phase: "confirmed",
      entryId: id.toString(),
      recovered: !state.registry?.hash,
      finalizedAt: fin,
    };
    await persist(state);
    return true;
  }
  const why = !bindingOk ? "a different binding" : "the right binding but different record content";
  state.registry = {
    ...(state.registry ?? {}),
    phase: "conflict",
    entryId: id.toString(),
    conflict: why,
    storedBinding: e.binding,
    storedContent: storable(eff, `ipfs://${file.cid}`),
  };
  await persist(state);
  alerts.push(
    `registry: entry ${id} for this action has ${why}; INCIDENT, unresolved until acknowledged`
  );
  return true;
}
