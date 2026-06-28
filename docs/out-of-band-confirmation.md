# Out-of-Band Confirmation API (DVT) — pending_confirmation + polling

Status: implemented & live. Opt-in (`CONFIRM_ENABLED`, default off). Closes #124
(the SDK-facing status + polling API for
[aastar-sdk#176](https://github.com/AAStarCommunity/aastar-sdk/issues/176) Phase
4).

For a **high-value** UserOperation the DVT node does **not** co-sign until the
real account user approves over an **independent channel**
(Telegram/email/Nostr, or a WebAuthn passkey). A stolen owner key alone can pass
the Stage-1 owner-auth gate but **cannot** produce the out-of-band approval —
this is what lets the DVT tier survive owner-key compromise. The signature is
withheld until approval, single-use, with a TTL.

This doc is the wire contract the SDK integrates against. **No external
dependency** for the status/polling/token path — it is local node state. (The
optional _passkey_ approval method delegates RP verification to KMS; see §4.)

---

## 1. Trigger & lifecycle

| What                                                 | Controlled by           | Default         |
| ---------------------------------------------------- | ----------------------- | --------------- |
| Feature on/off                                       | `CONFIRM_ENABLED`       | off             |
| Threshold (native value of `execute(to,value,data)`) | `CONFIRM_THRESHOLD_WEI` | 0 (every op)    |
| TTL before a pending confirmation expires            | `CONFIRM_TTL_MS`        | 600000 (10 min) |

Only ops whose decoded native `value` ≥ threshold are gated. Below threshold (or
with `CONFIRM_ENABLED=false`) signing is unchanged.

---

## 2. Sign → `pending_confirmation`

`POST /signature/sign` with the usual `{ userOp, ownerAuth }`. When the op is
high-value and not yet approved, instead of a signature you get:

```jsonc
{
  "status": "pending_confirmation",
  "userOpHash": "0x…", // the pollable id (= EntryPoint.getUserOpHash)
  "expiresAt": 1750000000000, // epoch ms; confirmation must happen before this
  "message": "high-value operation pending out-of-band confirmation; approve via your channel",
}
```

The node sends a one-time approval token ONLY over the user's independent
channel (never in this response). The owner-auth 403 gate still runs **first** —
an unauthenticated caller never reaches this path.

After the user approves (§3), **re-submit the same `POST /signature/sign`**: the
gate now resolves to `confirmed` (single-use) and returns the normal
`{ nodeId, signature, publicKey }`.

---

## 3. Poll status

`GET /signature/confirmation/:userOpHash` →

```jsonc
{ "userOpHash": "0x…", "status": "pending", "expiresAt": 1750000000000 }
```

| `status`    | meaning                                                           | SDK action                                              |
| ----------- | ----------------------------------------------------------------- | ------------------------------------------------------- |
| `pending`   | awaiting out-of-band approval                                     | keep polling until `expiresAt`                          |
| `approved`  | approved — not yet consumed                                       | re-submit `POST /signature/sign` to get the signature   |
| `expired`   | TTL elapsed without approval (the implicit **reject** — see note) | re-submit sign to re-arm a fresh confirmation, or abort |
| `not_found` | never created, or already consumed by a successful sign           | treat as done/unknown                                   |

> **On "rejected":** an explicit reject is intentionally **not** modeled —
> letting the confirmation expire IS how a user declines. So `#124`'s `rejected`
> maps to `expired` here. The polling API is read-only and does not consume the
> pending entry.

---

## 4. Approve (out-of-band)

`POST /signature/confirm` →
`{ status: "confirmed" | "rejected", confirmed: boolean }`. Two independent
methods:

```jsonc
// (a) token — delivered over the user's channel (Telegram/email). KMS-free.
{ "userOpHash": "0x…", "token": "0x…" }

// (b) passkey (WebAuthn) — path-2 (#124/#193). Raw navigator.credentials.get() JSON.
{ "userOpHash": "0x…", "passkey": { /* AuthenticationResponseJSON */ } }
```

- **token**: matched against the single-use token the node sent out-of-band. No
  external dependency.
- **passkey**: the node checks the assertion is bound to this `userOpHash`
  (`clientDataJSON.challenge == base64url(userOpHash)`), then delegates
  cryptographic RP verification to **KMS**
  (`POST {KMS_BASE_URL}/verify-confirm-assertion`, per-node `x-api-key`).
  Fail-closed if KMS is unreachable. This is the **only** part of the flow with
  an external dependency, and it is optional — a deployment that uses the token
  channel needs no KMS.

Both paths set the pending entry to `approved`; re-submitting the sign then
releases the signature.

---

## 5. SDK integration sketch (aastar-sdk#176 Phase 4)

```
1. resolveTransfer() → if dvt.needsOutOfBandConfirm (value ≥ threshold), pre-warn the user.
2. POST /signature/sign → if { status: "pending_confirmation", userOpHash, expiresAt }:
     show "approve on your channel" UI, then poll GET /signature/confirmation/{userOpHash}.
3. status:"approved" → re-POST /signature/sign → got the signature.
   status:"expired"  → offer retry (re-arms) or cancel.
```

Fail-closed contract: if a high-value op needs confirmation but no channel can
deliver the token, `POST /signature/sign` returns **403** (`undeliverable`) —
the node refuses to sign an op it cannot get the user to approve.
