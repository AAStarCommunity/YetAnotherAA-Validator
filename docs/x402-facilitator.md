# x402 Facilitator Module (DVT) — Endpoint & Settlement Spec

Status: implemented, opt-in (`X402_FACILITATOR_ENABLED`, default off). Tracks
issue
[#130](https://github.com/AAStarCommunity/YetAnotherAA-Validator/issues/130).

The DVT node operates the **x402 payment facilitator** as an optional module,
the same shape as `relay` (#98): an opt-in HTTP service that holds a **dedicated
operator key** and submits an on-chain settlement on the payer's behalf. The
role was previously homeless — the SDK (`@aastar/x402`) is client-only and the
in-repo SuperPaymaster reference node (`packages/x402-facilitator-node`) is
`@deprecated`. A client now just repoints its facilitator `url` at
`https://<dvt-node>/x402`.

This module is **orthogonal to the BLS signing core**: no `PackedUserOperation`,
no `AAStarValidator`, no BLS aggregation — it never touches the
security-critical 403 owner-auth gate. The payer authorizes with their own
EIP-712 signature; the node submits with its operator EOA.

---

## 1. Endpoints (x402 v2, SDK `FacilitatorClient`-compatible)

Base path `/x402`. Wire-compatible with
`aastar-sdk/packages/x402/src/facilitator.ts` — the SDK client posts to
`${url}/verify`, `${url}/settle`, `GET ${url}/supported`.

| Method | Path              | Purpose                                            | Latency |
| ------ | ----------------- | -------------------------------------------------- | ------- |
| POST   | `/x402/verify`    | Off-chain signature/expiry/nonce-replay check      | ~100 ms |
| POST   | `/x402/settle`    | Submit the on-chain `X402Facilitator` settlement   | ~2 s    |
| GET    | `/x402/supported` | Discovery: settleable kinds, assets, fee, contract | —       |

### Request body (`/verify` and `/settle`)

The standard x402 v2 envelope:

```jsonc
{
  "x402Version": 2,
  "paymentPayload": {
    "x402Version": 2,
    "payload": {
      "signature": "0x…", // payer EIP-712 signature
      "authorization": {
        // EIP-3009 authorization fields
        "from": "0x…", // payer
        "to": "0x…", // final recipient (== paymentRequirements.payTo)
        "value": "1000000", // == paymentRequirements.amount
        "validAfter": "0",
        "validBefore": "1750000000",
        "nonce": "0x…32 bytes", // direct path nonce; eip-3009 salt fallback
      },
    },
  },
  "paymentRequirements": {
    "scheme": "exact", // x402 PRICING scheme (only "exact" accepted)
    "network": "eip155:11155111",
    "asset": "0x…", // xPNTs (direct) or EIP-3009 token (USDC)
    "amount": "1000000",
    "payTo": "0x…", // final recipient
    "maxTimeoutSeconds": 3600,
    "extra": {
      /* see §2 */
    },
  },
}
```

### Response shapes

Both endpoints return **HTTP 200 with a discriminated body for ALL application
outcomes** (the SDK client throws on non-2xx and only reads JSON on 2xx, so a
rejection must still be 200). HTTP 503 is reserved for "module disabled on this
node". The optional HMAC guard (§4) may pre-empt `/settle` with 402/400/403.

```jsonc
// /verify → VerifyResponse
{ "isValid": true, "payer": "0x…" }
{ "isValid": false, "invalidReason": "Nonce already used" }

// /settle → SettleResponse
{ "success": true, "transaction": "0x…txhash", "network": "eip155:11155111", "payer": "0x…" }
{ "success": false, "errorReason": "settlement reverted (tx 0x…)" }

// /supported → FacilitatorSupported
{
  "kinds": [{
    "x402Version": 2,
    "scheme": "exact",
    "network": "eip155:11155111",
    "extra": {
      "settlementSchemes": ["direct", "eip-3009"],
      "assets": ["0x696a73…", "0xe6579a…"],   // lower-cased xPNTs (direct)
      "feeBPS": 200,
      "facilitatorContract": "0xfe1DB01e…",
      "operator": "0x…"
    }
  }],
  "extensions": []
}
```

---

## 2. `paymentRequirements.extra` schema (this module owns it)

The x402 v2 standard `paymentRequirements` carries no SuperPaymaster settlement
detail. Per #130 (deliverable: "agree the `/supported.extra` schema"), this
module reads the following OPTIONAL fields from `extra`:

| Field        | Type                       | Default                                                       | Meaning                                 |
| ------------ | -------------------------- | ------------------------------------------------------------- | --------------------------------------- |
| `settlement` | `"direct"` \| `"eip-3009"` | auto: `asset ∈ X402_SUPPORTED_ASSETS` ? `direct` : `eip-3009` | which on-chain call                     |
| `maxFee`     | decimal string             | `amount`                                                      | payer-approved fee cap (M-1)            |
| `salt`       | `0x`+64 hex                | `authorization.nonce`                                         | EIP-3009 nonce preimage                 |
| `name`       | string                     | `"USDC"`                                                      | EIP-712 token domain name (eip-3009)    |
| `version`    | string                     | `"2"`                                                         | EIP-712 token domain version (eip-3009) |

`permit2` is rejected by the **shared scheme guard**
(`rejectUnsupportedScheme`), which both `/verify` and `/settle` funnel through
so they can never diverge.

### Nonce derivation (must match the contract byte-for-byte)

- **direct**: on-chain nonce = the raw `authorization.nonce`.
- **eip-3009**: on-chain nonce = `keccak256(abi.encode(payTo, maxFee, salt))`
  (`X402Facilitator.settleX402Payment` derives it; the payer's EIP-3009
  signature and the replay slot are BOTH keyed on this derived value).
- **replay key**: `keccak256(abi.encode(asset, from, effectiveNonce))`
  (`x402NonceKey`). `/verify` checks both this triple key and the legacy
  raw-nonce slot against `x402SettlementNonces`.

---

## 3. On-chain settlement (authoritative ABI)

Settles on the standalone **`X402Facilitator`** contract (v5.4 god-split, NOT
SuperPaymaster). The ABI is taken from the contract source, NOT the stale
`@aastar/core` ABI:

```solidity
// direct (xPNTs): payer signs an X402PaymentAuthorization (EOA or ERC-1271)
settleX402PaymentDirect(from, to, asset, amount, maxFee, validBefore, nonce, signature)

// eip-3009 (USDC): payer signs a ReceiveWithAuthorization; nonce = keccak256(to, maxFee, salt)
settleX402Payment(from, to, asset, amount, maxFee, validAfter, validBefore, salt, signature)
```

EIP-712 domains:

- **direct**:
  `name="X402Facilitator", version="1", verifyingContract = facilitator`.
- **eip-3009**: the token's own domain (`name`/`version` from `extra`, default
  USDC `"USDC"`/`"2"`), `verifyingContract = asset`, recipient `to` = the
  facilitator contract (`receiveWithAuthorization` forces `msg.sender == to`).

`/verify` recovers EOA signatures off-chain and falls back to an on-chain
**ERC-1271** `isValidSignature` check for AirAccount passkey / smart accounts,
matching the contract's `SignatureCheckerLib`.

### ⚠️ SDK-side gap (aastar-sdk#39 — needed for end-to-end)

The current SDK `X402Client.createPayment` produces a payload that the deployed
contract **cannot yet settle**: it signs a `TransferWithAuthorization` (the
contract requires `ReceiveWithAuthorization`), omits `maxFee`/`salt`, and the
`direct` path lacks the `X402PaymentAuthorization` signature. For this module to
settle real payments, the SDK must, per the schema above:

1. For `eip-3009`: sign **ReceiveWithAuthorization** over the derived nonce
   `keccak256(payTo, maxFee, salt)`, recipient = the facilitator contract; put
   `maxFee` + `salt` in `extra`.
2. For `direct`: sign the **X402PaymentAuthorization** (X402Facilitator domain)
   and put `maxFee` in `extra`; set `extra.settlement = "direct"`.
3. Set `extra.settlement` (or rely on asset-based auto-detection) and keep
   `paymentRequirements.scheme = "exact"`.

The SDK also owns `DEFAULT_X402_FACILITATORS` (mirrors `DEFAULT_DVT_NODES`),
pointing at `https://dvt{1,2,3}.aastar.io/x402` once these nodes are deployed.

---

## 4. Optional auth headers (`/x402/settle`) — `createAuthHeaders` scheme

Opt-in via `X402_AUTH_ENABLED=true` + `X402_AUTH_SECRET`. Recommended for PUBLIC
nodes to blunt replay/bot spam on the gas-spending settle path. **Not a security
gate** — the on-chain authorization is authoritative.

The scheme is **stateless HMAC**, shaped to map 1:1 onto the SDK's
`FacilitatorConfig.createAuthHeaders()` (which must return headers with no prior
round-trip). Two headers on `POST /x402/settle`:

```
X-X402-Timestamp: <unix epoch ms>
X-X402-Auth:      hex HMAC-SHA256(X402_AUTH_SECRET, `${timestamp}.${rawBody}`)
```

The node accepts iff `|now − timestamp| ≤ X402_AUTH_TTL_MS` (default 300 000)
and the HMAC matches (constant-time) over the **raw** request bytes (`main.ts`
sets `rawBody: true`). On failure: 401 (missing/stale), 403 (HMAC mismatch).
`/verify` and `/supported` stay open. When disabled (default) the guard is a
no-op.

SDK side — `createAuthHeaders()` returns, for the body it will POST:

```ts
const ts = Date.now();
const auth = hmacSha256Hex(secret, `${ts}.${JSON.stringify(body)}`);
return { settle: { "X-X402-Timestamp": String(ts), "X-X402-Auth": auth } };
```

> Replaces the earlier challenge-response HMAC (which needed a server-issued
> `X-Challenge` and so couldn't fit `createAuthHeaders`). Settle replay is
> already neutralised on-chain — the X402Facilitator nonce is single-use — so a
> TTL-bounded stateless HMAC is sufficient. A golden header vector lives in
> `conformance/x402/fixtures.json` (`authHeader`).

---

## 5. Configuration

```bash
# x402 Facilitator module (AAStar Sepolia defaults; aPNTs + PNTs settle `direct`)
X402_FACILITATOR_ENABLED=true
X402_FACILITATOR_CONTRACT=0xfe1DB01e1d6622e722B92ed5993af61325DB92aF
X402_SUPPORTED_ASSETS=0x696A73701b104c6cCBbAadDD2216788ea08EaB89,0xE6579A90dc498a710008de12119812D0FB7aA224
X402_OPERATOR_PK=0x…            # DEDICATED key — NOT ETH_PRIVATE_KEY / RELAY_OPERATOR_PK
X402_FEE_BPS=200
X402_CHAIN_ID=11155111
X402_RPC_URL=https://…          # falls back to ETH_RPC_URL
# Optional stateless-HMAC auth on /x402/settle (see §4)
X402_AUTH_ENABLED=true
X402_AUTH_SECRET=<32-byte random>
X402_AUTH_TTL_MS=300000
```

| Default asset | Token | Sepolia address                              | Scheme   |
| ------------- | ----- | -------------------------------------------- | -------- |
| AAStar        | aPNTs | `0x696A73701b104c6cCBbAadDD2216788ea08EaB89` | `direct` |
| Mycelium      | PNTs  | `0xE6579A90dc498a710008de12119812D0FB7aA224` | `direct` |

---

## 6. Operator provisioning runbook

The `X402_OPERATOR_PK` EOA must be provisioned by the AAStar deployer before it
can settle. It must also be funded with ETH for gas.

> ⚠️ Verified against the deployed contract source — the function name and role
> string below differ from the draft in issue #130. The contract checks
> `REGISTRY.hasRole(keccak256("PAYMASTER_SUPER"), msg.sender)` (NOT
> `"ROLE_PAYMASTER_SUPER"`) and the direct gate is `addApprovedFacilitator` on
> the xPNTs token (NOT `addAutoApprovedSpender` — that is a separate
> transferFrom firewall). Using the issue's strings produces the wrong role hash
> / wrong mapping and every settle reverts with `Unauthorized()`.

```bash
# 1. Set this operator's facilitator fee on X402Facilitator (onlyOwner = AAStar deployer)
cast send $X402_FACILITATOR "setOperatorFacilitatorFee(address,uint256)" \
  $OPERATOR_ADDRESS 200 --private-key $DEPLOYER_KEY --rpc-url $RPC_URL

# 2. Approve the operator as a facilitator on each supported xPNTs token.
#    Caller MUST be the token's communityOwner (a multisig), and OPERATOR != communityOwner.
cast send $APNTS_TOKEN "addApprovedFacilitator(address)" $OPERATOR_ADDRESS \
  --private-key $COMMUNITY_OWNER_KEY --rpc-url $RPC_URL
cast send $PNTS_TOKEN  "addApprovedFacilitator(address)" $OPERATOR_ADDRESS \
  --private-key $COMMUNITY_OWNER_KEY --rpc-url $RPC_URL

# 3. Grant the PAYMASTER_SUPER role in the Registry (onlyOwner). The role hash is
#    keccak256("PAYMASTER_SUPER") — note: NO "ROLE_" prefix in the hashed string.
cast send $REGISTRY "grantRole(bytes32,address)" \
  $(cast keccak "PAYMASTER_SUPER") $OPERATOR_ADDRESS \
  --private-key $DEPLOYER_KEY --rpc-url $RPC_URL
```

The `direct` path requires the operator be in
`IxPNTsToken(asset).approvedFacilitators(operator)` for each supported token —
established by step 2's `addApprovedFacilitator` (callable only by the token's
`communityOwner`; revocable instantly via `removeApprovedFacilitator` for
incident response). This is distinct from `autoApprovedSpenders` (the
transferFrom allowance firewall).

---

## 7. Conformance fixtures & live round-trip

`conformance/x402/fixtures.json` holds the **golden wire vectors** — the exact
`/x402/{verify,settle}` request bodies a conformant SDK emits (one `direct`, one
`eip-3009`, signed by a fixed key), plus the values the DVT derives (effective
nonce, ordered settle args, payer) and the `authHeader` vector. It is the
cross-repo contract: `x402-conformance.spec.ts` drives the DVT off-chain against
it, and the SDK can load the same JSON to assert its `createPayment` produces
byte-identical envelopes. Regenerate with:

```bash
node scripts/x402/gen-conformance-fixtures.mjs > conformance/x402/fixtures.json
```

Once a node exposes `/x402` (testnet operator provisioned per §6), a live
round-trip:

```bash
BODY=$(jq -c '.vectors[1].body' conformance/x402/fixtures.json)   # eip-3009 vector
curl -s -X POST https://<node>/x402/verify -H 'content-type: application/json' -d "$BODY"
# → { "isValid": true, "payer": "0x…" }   (verify is off-chain; open by default)
curl -s -X POST https://<node>/x402/settle -H 'content-type: application/json' -d "$BODY"
# → { "success": true, "transaction": "0x…", "network": "eip155:11155111", "payer": "0x…" }
```

(With `X402_AUTH_ENABLED`, add the §4 `X-X402-Timestamp` / `X-X402-Auth`
headers. The fixture vectors use placeholder addresses, so a real round-trip
needs an envelope signed for the deployed token/facilitator and a funded,
provisioned operator.)

---

## 8. Source provenance

- HTTP contract: `aastar-sdk/packages/x402/src/{facilitator,types}.ts`.
- verify/settle logic ported (viem → ethers v6) from the battle-tested reference
  node `SuperPaymaster/packages/x402-facilitator-node/src/` (4/4 E2E on Sepolia
  v5.4.1-rc.1).
- Authoritative ABI/domains from
  `SuperPaymaster/contracts/src/paymasters/superpaymaster/v3/X402Facilitator.sol`.
