# Deploy your own DVT node (testnet, always-on via Cloudflare)

Clone the repo, configure, and stand up your **own** 3-node DVT signer with a
stable public HTTPS endpoint — no servers to expose by hand, no static IP. The
nodes run as Docker containers; a **Cloudflare named tunnel** gives each a
stable hostname.

> This is the reproducible path behind the AAStar testnet DVT. The same compose
> file is what the reference deployment runs.

## Prerequisites

- **Docker** + **Docker Compose v2**, on a host that stays on (your VPS /
  always-on box).
- A **Cloudflare account** with a **domain (zone)** you control.
- A **Sepolia RPC URL** (Alchemy/Infura/…).
- For on-chain registration: see step 3 (the validator's `registerPublicKey` is
  `onlyOwner`).

## 1. Generate 3 independent node keys

Each node needs its **own secret** BLS12-381 key (do **not** reuse the public
`BLS_TEST` fixtures — those are for local dev only and anyone can sign with
them).

```bash
for i in 1 2 3; do
  mkdir -p deploy/node$i
  node --input-type=module -e '
    import { bls12_381 as bls } from "@noble/curves/bls12-381.js";
    import { randomBytes } from "crypto"; import { writeFileSync } from "fs";
    const sigs = bls.longSignatures;
    let sk; do { sk = randomBytes(32); try { sigs.getPublicKey(sk); break; } catch {} } while (true);
    const id = "0x" + randomBytes(32).toString("hex");
    writeFileSync(process.argv[1], JSON.stringify({
      nodeId: id, nodeName: "dvt-"+process.argv[2],
      privateKey: "0x"+Buffer.from(sk).toString("hex"),
      publicKey: sigs.getPublicKey(sk).toHex(),
      createdAt: new Date().toISOString(), description: "production DVT node"
    }, null, 2));
    console.log("dvt-"+process.argv[2]+": nodeId="+id);
  ' "deploy/node$i/node_state.json" "node$i"
done
```

`deploy/node{1,2,3}/node_state.json` are git-ignored (they hold private keys).

## 2. Configure

```bash
cp deploy/.env.testnet.example deploy/.env.testnet
# fill in: ETH_RPC_URL, VALIDATOR_CONTRACT_ADDRESS (verify with `npm run check-deps`),
#          CLOUDFLARE_TUNNEL_TOKEN, NODE{1,2,3}_PUBLIC_URL
```

## 3. Register each node's BLS public key on the validator

The on-chain verifier `AAStarBLSAlgorithm.registerPublicKey(nodeId, publicKey)`
takes a **128-byte EIP-2537 G1** key and is **`onlyOwner`** in v0.20.0 — so a
third-party operator **cannot self-register**; the validator owner must register
your nodeId + pubkey (or use the SuperPaymaster staking-based registration path,
where applicable).

**(a) AAStar testnet (owner-registered, fastest):** open an issue / ping the
validator owner with each node's `nodeId` + `publicKey` (from step 1) to get
registered on `0xAF525A…`. Verify `isRegistered(nodeId) == true` and
`getRegisteredNodeCount()` includes your nodes.

**(b) Permissionless via staking (run your OWN community DVT, no owner
approval):**

1. **Buy the governance token** at
   [launch.mushroom.cv](https://launch.mushroom.cv).
2. **Stake** by interacting with the registry contract directly on Etherscan
   (connect wallet → `stake(...)` → register your node), which authorizes your
   node without the validator owner.
3. **Stand up your community DVT** — your own nodes + your own domain
   (`dvt.xxx.com`, `dvt.xxx.net`, ≥3 for a real N-of-M).
4. **Or use COS72** (open-source; self-host or run locally) and follow its
   guided flow to do **buy → stake → deploy → activate** end-to-end.

> Path (a) is the owner-coordinated bootstrap for the AAStar reference nodes;
> path (b) is the permissionless route any community uses to run an independent
> DVT. Until the staking path is fully wired on the current
> `AAStarBLSAlgorithm`, (a) is the interim for testnet — (b) is the target for
> true multi-party.

## 4. Cloudflare named tunnel

1. Cloudflare dashboard → **Zero Trust → Networks → Tunnels → Create a tunnel →
   Cloudflared**.
2. Copy the **token** → `CLOUDFLARE_TUNNEL_TOKEN` in `deploy/.env.testnet`.
3. Add **3 Public Hostnames** on the tunnel, each → an HTTP service on the
   docker network:
   - `dvt-node-1.yourdomain.com` → `http://dvt-node-1:3001`
   - `dvt-node-2.yourdomain.com` → `http://dvt-node-2:3002`
   - `dvt-node-3.yourdomain.com` → `http://dvt-node-3:3003`

## 5. Launch

```bash
docker compose -f docker-compose.testnet.yml --env-file deploy/.env.testnet up -d --build
docker compose -f docker-compose.testnet.yml ps     # all healthy
```

## 6. Verify (public)

```bash
# health + fail-closed (expect a nodeId, then 403)
curl -s https://dvt-node-1.yourdomain.com/node/info | jq .nodeId
curl -s -o /dev/null -w "%{http_code}\n" -X POST https://dvt-node-1.yourdomain.com/signature/sign \
  -H 'content-type: application/json' -d '{"userOp":{}}'   # → 403

# full on-chain E2E (3-node co-sign → AAStarBLSAlgorithm.validate === 0)
#   point scripts/e2e/realnode-e2e.mjs at your public URLs + nodeIds, or run it locally.
```

## 7. Hand off to the coordinator / SDK

Provide: the 3 public hostnames, the 3 `nodeId`s, and the userOpHash convention
(EntryPoint v0.7 `getUserOpHash` + EIP-191 `ownerAuth`). See
[`docs/HOW_TO_INTEGRATION.md`](../docs/HOW_TO_INTEGRATION.md).

---

## Notes

- **Independence is the point** (TESTNET_RELEASE_PLAN §5): real multi-party
  means 3 keys, 3 operators, 3 hosts — not 3 processes with shared keys. For a
  true N-of-M, different operators each run this compose with their own key +
  their own Cloudflare tunnel.
- `POLICY_ENABLED=true` + `POLICY_REGISTRY_ADDRESS` turns on the independent
  policy gate (see [`docs/DVT_VALUE.md`](../docs/DVT_VALUE.md)).
- Keys never enter the image — `node_state.json` is a read-only mount.
