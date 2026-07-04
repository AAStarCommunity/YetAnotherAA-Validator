# Run an independent community DVT node

The DVT is decentralized by **independent operators**: AAStar runs one node
(`dvt.aastar.io`); communities run their own. A real N-of-M needs **≥3
independent operators** (different keys, hosts, domains, jurisdictions — that's
what makes the second factor trustworthy and resists collusion). This guide is
for a community operator standing up their **own** node.

> You do **not** get an `aastar.io` subdomain — and shouldn't want one. If every
> node lived under `aastar.io`, AAStar would control all the DNS and the network
> wouldn't be decentralized. Use **your own domain**. AAStar provides the
> software + this guide, not hosting.

## What you provide

- Your **own** BLS12-381 key (never shared, never AAStar's).
- Your **own** host (an i.MX93 board, a small VPS, or a Mac mini).
- Your **own** public HTTPS endpoint (your domain; a free Cloudflare Tunnel
  gives it a stable hostname — same mechanism AAStar uses for dvt1/2/3).

## The 5 steps

### 1. Generate your node key

```bash
git clone https://github.com/AAStarCommunity/YetAnotherAA-Validator && cd YetAnotherAA-Validator
npm install
mkdir -p deploy/node1
node --input-type=module -e '
  import { bls12_381 as bls } from "@noble/curves/bls12-381.js";
  import { randomBytes } from "crypto"; import { writeFileSync } from "fs";
  const sigs = bls.longSignatures;
  let sk; do { sk = randomBytes(32); try { sigs.getPublicKey(sk); break; } catch {} } while (true);
  const id = "0x" + randomBytes(32).toString("hex");
  writeFileSync("deploy/node1/node_state.json", JSON.stringify({
    nodeId: id, nodeName: "dvt-community",
    privateKey: "0x"+Buffer.from(sk).toString("hex"),
    publicKey: sigs.getPublicKey(sk).toHex(),
    createdAt: new Date().toISOString(), description: "community DVT node"
  }, null, 2));
  console.log("nodeId=" + id + "\npublicKey=" + sigs.getPublicKey(sk).toHex());
'
```

Encrypt it at rest (recommended for a physical board — see
[`../docs/KEYSTORE.md`](../docs/KEYSTORE.md)):
`NODE_KEY_PASSPHRASE=… node scripts/encrypt-node-key.mjs deploy/node1/node_state.json`.

### 2. Register your public key on-chain

The validator must know your `nodeId` + `publicKey` or your signatures won't
verify. `registerPublicKey` is **`onlyOwner`** on the current validator, so
there are two paths:

- **(a) Owner-coordinated (interim, works today):** send your `nodeId` +
  `publicKey` (from step 1) to AAStar (open an issue on this repo). The
  validator owner registers you. Verify: `isRegistered(nodeId) == true`.
- **(b) Permissionless via staking (target, when wired):** buy the governance
  token at [launch.mushroom.cv](https://launch.mushroom.cv), stake, and
  self-register through the SuperPaymaster staking path — no owner approval.
  Until this is fully wired on the current validator, use (a).

> This on-chain step is the one part you can't fully self-serve yet — the rest
> below is all automatable. See "Self-onboarding tool" at the bottom.

### 3. Configure

```bash
cp deploy/.env.testnet.example deploy/.env.testnet   # or .env.mainnet for production
# Required: ETH_RPC_URL, VALIDATOR_CONTRACT_ADDRESS
# Your public identity (so peers/clients can reach you):
#   PUBLIC_URL=https://dvt.your-community.org
#   GOSSIP_PUBLIC_URL=wss://dvt.your-community.org/ws
# Join the network (see step 5):
#   GOSSIP_BOOTSTRAP_PEERS=wss://dvt.aastar.io/ws
```

### 4. Deploy (pick your host)

| Host                        | How                                                                               |
| --------------------------- | --------------------------------------------------------------------------------- |
| **i.MX93 board** (embedded) | [`imx93/README.md`](imx93/README.md) — self-contained bundle + systemd, no Docker |
| **VPS / server**            | `docker-compose.mainnet.yml` — Docker with self-heal                              |
| **Mac / Linux box**         | `deploy/dvt-testnet.sh` (testnet) as a template                                   |

Expose your node publicly via a **Cloudflare Tunnel on your own domain** (see
[`README.md`](README.md) §4 — same steps, your hostnames).

### 5. Join the network — P2P discovery (already built)

Discovery is automatic via the built-in **gossip** layer (SWIM-style). You do
NOT build anything; you just point at a seed:

- Set `GOSSIP_BOOTSTRAP_PEERS=wss://dvt.aastar.io/ws` (any existing node's
  gossip endpoint works as a seed).
- On start, your node connects to the seed, joins, and gossips its `PeerInfo`
  (`nodeId`, `publicKey`, **`apiEndpoint`** = your `PUBLIC_URL`,
  `gossipEndpoint`) across the network. Every node — including yours — converges
  on the full roster.

**How nodeId ↔ URL is shared (your question):** it's the gossip roster. Fetch it
from **any** node:

```bash
curl -s https://dvt.aastar.io/gossip/peers | jq '.peers[] | {nodeId, apiEndpoint, status}'
# → the full {nodeId, publicKey, apiEndpoint} list. A coordinator/SDK reads this to know
#   who to ask for signatures and at which URL. "Deploy, then everyone knows each other's
#   URL" — that's exactly this, no manual list needed once you're on the gossip mesh.
```

## Verify the path end-to-end

```bash
# your node is up + on the mesh:
curl -s https://dvt.your-community.org/health | jq '{version, status}'
curl -s https://dvt.your-community.org/node/info | jq .nodeId
curl -s https://dvt.your-community.org/gossip/peers | jq '.peers | length'   # sees peers

# owner-auth gate is fail-closed (expect 403):
curl -s -o /dev/null -w "%{http_code}\n" -X POST https://dvt.your-community.org/signature/sign \
  -H 'content-type: application/json' -d '{"userOp":{}}'

# full on-chain co-sign E2E (your node + others → AAStarValidator.validate === 0):
#   scripts/e2e/realnode-e2e.mjs — point it at the gossip roster URLs + nodeIds.
```

## Self-onboarding tool (planned)

An onboarding helper (`deploy/onboarding/`) is planned to automate steps **1, 3,
4, 5** and run the E2E in step "Verify" as a single guided flow. Step **2
(on-chain registration)** stays owner-coordinated until the permissionless
staking path is wired — the tool will generate your `nodeId`+`publicKey` and a
ready-to-send registration request. Track it in the N-of-M design issue (#157).
