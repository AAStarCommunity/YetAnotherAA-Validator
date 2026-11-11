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
import { MIRROR_BLOB_URL } from "../sinks/git-mirror.mjs";

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

/** Of the journalled raw txs, the one with the highest maxFeePerGas (#411 N2): a known tx whose raw
 * is missing is floored on the most expensive raw we have, since the unfloored re-sign branch
 * means the latest raw is not necessarily the most expensive one. */
export function highestFeeRaw(raws) {
  let best = null;
  let bestFee = -1n;
  for (const r of raws) {
    if (!r) continue;
    try {
      const fee = ethers.Transaction.from(r).maxFeePerGas ?? 0n;
      if (fee > bestFee) [best, bestFee] = [r, fee];
    } catch {
      // not a parseable tx (a test stub): ignored unless nothing else exists
      if (best === null) best = r;
    }
  }
  return best;
}

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
    // a journalled URL is sent only in the exact shape gitMirror builds (Codex W2c R23 #1)
    mirror?.url && MIRROR_BLOB_URL.test(String(mirror.url))
      ? `mirror ${mirror.url}`
      : /^[0-9a-f]{4,40}$/.test(String(mirror?.commit ?? ""))
        ? `mirror commit ${mirror.commit}`
        : null,
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
    // a pin whose last re-verification could not reach the gateway is re-verified on every pass
    // until a check succeeds (Codex W2c R20 #3)
    if (cur?.current && !opts.reverify && !cur.checkError) continue;
    try {
      if (cur?.current) {
        // Reverify: still served, byte for byte? If not, demote and upload again below. A transport
        // error is no evidence either way (#409 review N1): the pin keeps its state, alerted.
        let back;
        try {
          back = await p.fetchPublic(file.cid);
        } catch (e) {
          if (e instanceof PersistError) throw e;
          state.pins[p.name] = { ...cur, checkError: errMsg(e), checkErrorAt: at };
          alerts.push(`${p.name}: re-verification could not reach the gateway; pin state kept`);
          continue;
        }
        if (
          back &&
          bytesEqual(back instanceof Uint8Array ? back : ethers.getBytes(back), file.bytes)
        ) {
          const { checkError: _e, checkErrorAt: _a, ...kept } = cur;
          (void _e, _a);
          state.pins[p.name] = { ...kept, checkedAt: at };
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

  // W2d: the registry stage belongs to the registry it was written for. A stage written for another
  // address or chain is archived and the record is disclosed again on the configured one; its
  // signed transactions are never broadcast again (they target the old registry).
  const where = sinks.registry ? registryWhere(sinks.registry) : null;
  if (
    rec.route === "bls" &&
    where &&
    state.registry &&
    !sameRegistry(registryAt(state.registry), where)
  ) {
    const from = registryAt(state.registry);
    state.registryHistory = [
      ...(state.registryHistory ?? []),
      { ...state.registry, supersededAt: new Date().toISOString() },
    ];
    state.registry = null;
    state.registryMigrated = { from, to: where, at: new Date().toISOString() };
    await persist(state);
    alerts.push(
      "registry: the configured registry changed; this record is disclosed again on it (the old registry's transactions are not broadcast)"
    );
  }
  if (rec.route === "bls" && sinks.registry && state.registry?.phase !== "confirmed") {
    // every journal write of this stage records the registry it is for
    const persistAt = st => {
      if (st.registry && !st.registry.at) st.registry = { ...st.registry, at: where };
      return persist(st);
    };
    try {
      const ar = await advanceRegistry(rec, file, sinks.registry, state, persistAt, alerts, opts);
      if (ar === "broadcast-failed") failures.push("registry");
    } catch (e) {
      if (e instanceof PersistError) throw e;
      alerts.push(`registry: ${errMsg(e)}`);
      failures.push("registry");
    }
  }
  return { state, alerts, failures };
}

export const DEFAULT_MAX_PENDING_MS = 30 * 60_000;

/** The registry a sink writes to (W2d): { address (lowercase), chainId (decimal string) }. */
export function registryWhere(reg) {
  return { address: String(reg.address).toLowerCase(), chainId: String(reg.chainId) };
}
/**
 * The registry a journalled stage was written for: its `at`, or for a stage journalled before
 * W2d, the address and chain of its signed transaction. Null when neither exists; such a stage
 * (journalled before W2d without a transaction) is taken as the registry configured at upgrade:
 * no deployment ran before W2d (Phase D needs it), so there is no other registry it could be for.
 */
export function registryAt(r) {
  if (r?.at?.address) return r.at;
  if (r?.raw) {
    try {
      const tx = ethers.Transaction.from(r.raw);
      if (tx.to) return { address: tx.to.toLowerCase(), chainId: String(tx.chainId) };
    } catch {
      // not a parseable transaction: no evidence either way
    }
  }
  return null;
}
export const sameRegistry = (at, where) =>
  !at || (at.address === where.address && at.chainId === where.chainId);

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
    let broadcastFailed = false;
    try {
      await reg.broadcast(r.raw);
      // a broadcast that now goes through clears the earlier error, so a stall (e.g. insufficient
      // funds, since topped up) does not stay counted as degraded forever
      if (r.lastBroadcastError !== undefined) {
        const { lastBroadcastError: _cleared, ...rest } = r;
        void _cleared;
        state.registry = rest;
      }
    } catch (e) {
      broadcastFailed = true;
      state.registry = { ...r, lastBroadcastError: errMsg(e) };
      // a writer without the funds cannot land anything: said plainly, every pass (#411 review F1)
      if (safeCode(e) === "INSUFFICIENT_FUNDS")
        alerts.push(
          `registry: the writer has insufficient funds for the disclose tx (nonce ${r.nonce}); fund the writer`
        );
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
      // an RPC answer that cannot be ours: marked, so the watcher is degraded until the phase moves
      // on (Codex W2c R21 #1)
      if (!state.registry.noEventAt) {
        state.registry = { ...state.registry, noEventAt: new Date().toISOString() };
        await persist(state);
      }
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
      if (age < maxPendingMs) {
        // Pending. If this pass's rebroadcast failed and nothing has landed, the tx may not be
        // in any mempool: a stage failure, not a normal wait (Codex W2c R4).
        if (broadcastFailed) {
          alerts.push("registry: rebroadcast failed and no receipt yet; retried next pass");
          return "broadcast-failed";
        }
        return; // pending; next tick
      }
      // Stuck (evicted or underpriced) with its nonce unused: replace it at the SAME nonce with a
      // higher fee, journalled before broadcast like the original.
      alerts.push(
        `registry: disclose tx pending ${Math.round(age / 60000)} min; replacing at nonce ${state.registry.nonce}`
      );
      // The fee floor comes from the newest journalled tx a node KNOWS (#411 review F1): only an
      // accepted tx must be outbid (>= 10% rule, W2b R1 H4). If no node ever accepted one (e.g.
      // every broadcast failed for lack of funds), the replacement is priced at the current
      // estimate, so the fee never climbs on rejections alone.
      const hashes0 = state.registry.hashes ?? [state.registry.hash];
      // a journal written before raws existed holds only the LATEST raw: it belongs to the last
      // hash, the earlier ones have none (W2b Codex R7)
      const raws0 =
        state.registry.raws?.length === hashes0.length
          ? state.registry.raws
          : hashes0.map((_, i) => (i === hashes0.length - 1 ? state.registry.raw : null));
      let floorRaw = null;
      for (let i = hashes0.length - 1; i >= 0 && floorRaw === null; i--)
        if (await reg.knows(hashes0[i]))
          // a known tx without its raw bytes: floor on the latest journalled raw, whose fees are
          // never below an earlier one's (each replacement only rises from its floor)
          floorRaw = raws0[i] ?? highestFeeRaw(raws0);
      let rep;
      try {
        rep = await reg.sign(
          discloseArgs(rec, file),
          floorRaw
            ? { nonce: state.registry.nonce, replace: true, prevRaw: floorRaw }
            : { nonce: state.registry.nonce }
        );
      } catch (e) {
        if (e?.code !== "FEE_CAP") throw e;
        // the configured ceiling stops escalation; never silently: alerted on every pass
        state.registry = { ...state.registry, feeCapped: new Date().toISOString() };
        await persist(state);
        alerts.push(
          `registry: replacing the disclose tx (nonce ${state.registry.nonce}) needs a fee above the configured maxFeePerGas; disclosure stalled until the cap is raised or the fee falls`
        );
        return;
      }
      // the replacement supersedes the old tx's fee cap and broadcast error (#413 review F3); a
      // failure of the new broadcast is journalled again by broadcastJournalled
      const { feeCapped, lastBroadcastError, ...rest } = state.registry;
      void lastBroadcastError;
      state.registry = {
        ...rest,
        raw: rep.raw,
        hash: rep.hash,
        // an identical re-sign (flat estimate, nothing accepted) is not journalled again (#411 N1)
        hashes: hashes0.includes(rep.hash) ? hashes0 : [...hashes0, rep.hash],
        raws: hashes0.includes(rep.hash) ? raws0 : [...raws0, rep.raw],
        sentAt: new Date().toISOString(),
        replacements: (state.registry.replacements ?? 0) + 1,
      };
      await persist(state); // journal BEFORE broadcast
      await broadcastJournalled(reg, rep.raw, state, persist, alerts);
      return;
    }
  }
  // Nothing in flight: an entry may already exist (an earlier publication completed elsewhere).
  if (await adoptExisting(rec, file, reg, state, persist, alerts)) return;
  let signed;
  try {
    signed = await reg.sign(discloseArgs(rec, file));
  } catch (e) {
    if (e?.code !== "FEE_CAP") throw e;
    // the stall is journalled like a replacement's (Codex W2c R11): it counts as degraded until a
    // signature succeeds, which replaces this state
    state.registry = { phase: "unsigned", feeCapped: new Date().toISOString() };
    await persist(state);
    alerts.push(
      "registry: the disclose tx needs a fee above the configured maxFeePerGas; not signed, retried next pass"
    );
    return;
  }
  state.registry = {
    phase: "signed",
    raw: signed.raw,
    hash: signed.hash,
    hashes: [signed.hash],
    raws: [signed.raw],
    nonce: signed.nonce,
  };
  await persist(state); // journal BEFORE broadcast
  await broadcastJournalled(reg, signed.raw, state, persist, alerts);
  state.registry = { ...state.registry, phase: "sent", sentAt: new Date().toISOString() };
  await persist(state);
}

/**
 * A first or replacement broadcast (Codex W2c R12 #2): a failure is journalled like a rebroadcast's
 * (lastBroadcastError, so an unfunded writer counts as a stall from the first attempt) and alerted
 * when it is insufficient funds, then rethrown so the pass still records the failure.
 */
async function broadcastJournalled(reg, raw, state, persist, alerts) {
  try {
    await reg.broadcast(raw);
  } catch (e) {
    state.registry = { ...state.registry, lastBroadcastError: errMsg(e) };
    if (safeCode(e) === "INSUFFICIENT_FUNDS")
      alerts.push(
        `registry: the writer has insufficient funds for the disclose tx (nonce ${state.registry.nonce}); fund the writer`
      );
    await persist(state); // a persist failure (PersistError) stops the pass, as everywhere else
    throw e;
  }
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
  // Final receipt but no entry at the finalized block: inconsistent RPC; stay landed, alert, and
  // mark it so the watcher is degraded until a later check confirms the entry (Codex W2c R20 #2)
  state.registry = {
    ...state.registry,
    phase: "landed",
    entryId: String(rc.entryId),
    inconsistentAt: new Date().toISOString(),
  };
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
