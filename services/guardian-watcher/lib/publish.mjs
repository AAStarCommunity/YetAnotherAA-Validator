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
//   registry: { entryOf(kind, key) -> entryId (0 = none), binding(entryId) -> bytes32,
//               sign(args) -> { raw, hash, nonce }, broadcast(raw) -> void,
//               receipt(hash) -> { status, entryId } | null, nonce() -> number }
import { ethers } from "ethers";
import { Kind } from "../../../scripts/disclosure/recheck-lib.mjs";
import { recordFile, mirrorPath } from "./record-file.mjs";

/** A failure to persist state: publication must stop, the returned state is NOT durable. */
export class PersistError extends Error {
  constructor(cause) {
    super(`persist failed: ${cause?.message ?? cause}`);
    this.name = "PersistError";
    this.cause = cause;
  }
}

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
  // The journal is the crash-safety guarantee; without a durable persist there is none, so it is
  // required. Only an explicitly unsafe test mode may skip it.
  if (typeof opts.persist !== "function" && opts.unsafeNoJournal !== true) {
    throw new Error(
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
      if (e instanceof PersistError) throw e;
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
      if (e instanceof PersistError) throw e;
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
      if (e instanceof PersistError) throw e;
      alerts.push(`telegram: ${errMsg(e)}`);
    }
  }

  if (rec.route === "bls" && sinks.registry && state.registry?.phase !== "confirmed") {
    try {
      await advanceRegistry(rec, file, sinks.registry, state, persist, alerts);
    } catch (e) {
      if (e instanceof PersistError) throw e;
      alerts.push(`registry: ${errMsg(e)}`);
    }
  }
  return { state, alerts };
}

async function advanceRegistry(rec, file, reg, state, persist, alerts) {
  const r = state.registry;
  if (r?.phase === "conflict") {
    if (!r.ack)
      alerts.push(
        `registry: entry ${r.entryId} for this action has a different binding; unresolved until acknowledged`
      );
    return;
  }
  if (r?.phase === "reverted") {
    // Parked, not retried blindly (an out-of-gas or a bad input needs a human). Re-alerted every
    // time until an operator acknowledges it (state.registry.ack), so it cannot go silent.
    if (!r.ack)
      alerts.push(
        `registry: disclose tx ${r.hash} reverted (${r.reason ?? "no reason recorded"}); unresolved until acknowledged`
      );
    return;
  }
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
      // Reverted - possibly AlreadyDisclosed because another tx of ours landed first.
      if (await adoptExisting(rec, reg, state, persist, alerts)) return;
      state.registry = {
        ...state.registry,
        phase: "reverted",
        reason: rc.reason ?? "status 0",
        revertedAt: new Date().toISOString(),
      };
      await persist(state);
      alerts.push(
        `registry: disclose tx ${r.hash} reverted (${state.registry.reason}); unresolved until acknowledged`
      );
      return;
    }
    if (rc && rc.entryId == null) {
      alerts.push(`registry: tx ${r.hash} succeeded without a Disclosed event`);
      return;
    }
    // No receipt yet. If our nonce is already used, this tx was replaced or dropped: start over.
    // nonce() must be the writer's nonce at a FINALIZED block: a mined nonce, past reorgs, and with
    // the receipt indexes caught up. A pending or latest view would misread a broadcast or a
    // not-yet-indexed receipt as a drop.
    if ((await reg.nonce()) > r.nonce) {
      alerts.push(`registry: tx ${r.hash} (nonce ${r.nonce}) was dropped or replaced; re-signing`);
      state.registry = null;
      await persist(state);
    } else {
      return; // pending; next tick
    }
  }
  // Nothing in flight: an entry may already exist (an earlier publication completed elsewhere).
  if (await adoptExisting(rec, reg, state, persist, alerts)) return;
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

/** The binding the registry stores for this record's entry (DisclosureRegistry._append). */
export function expectedBinding(rec) {
  return ethers.keccak256(
    ethers.AbiCoder.defaultAbiCoder().encode(
      ["uint8", "uint256", "address"],
      [Kind[rec.kind], BigInt(rec.key), rec.subjectToken ?? ethers.ZeroAddress]
    )
  );
}

/** If the registry already holds this action's entry, adopt it (same binding) or flag a conflict. */
async function adoptExisting(rec, reg, state, persist, alerts) {
  const id = BigInt(await reg.entryOf(Kind[rec.kind], BigInt(rec.key)));
  if (id === 0n) return false;
  const stored = String(await reg.binding(id)).toLowerCase();
  if (stored === expectedBinding(rec).toLowerCase()) {
    state.registry = { phase: "confirmed", entryId: id.toString(), recovered: true };
    await persist(state);
    return true;
  }
  state.registry = { phase: "conflict", entryId: id.toString(), storedBinding: stored };
  await persist(state);
  alerts.push(
    `registry: entry ${id} for this action has a different binding; unresolved until acknowledged`
  );
  return true;
}
