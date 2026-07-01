# Deploy your own DVT node (testnet, always-on via Cloudflare)

Clone the repo, configure, and stand up your **own** 3-node DVT signer with a
stable public HTTPS endpoint — no servers to expose by hand, no static IP. The
nodes run as Docker containers; a **Cloudflare named tunnel** gives each a
stable hostname.

> This is the reproducible path behind the AAStar testnet DVT. The same compose
> file is what the reference deployment runs.
>
> **Deploying to mainnet?** This page is the **testnet** runbook. For production
> (mainnet) — test↔prod differences, prerequisites, the prod runbook, full
> regression, and upstream/downstream notification — see
> [`docs/PRODUCTION_DEPLOYMENT.md`](../docs/PRODUCTION_DEPLOYMENT.md).

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

**Option A — Docker (recommended for always-on hosts, e.g. Mac mini):**

```bash
docker compose -f docker-compose.testnet.yml --env-file deploy/.env.testnet up -d --build
docker compose -f docker-compose.testnet.yml ps     # all healthy
```

**Option B — local-process manager script (no Docker):** runs the 3 nodes on
4001/2/3 + the cloudflared named tunnel as plain processes. Full lifecycle:

```bash
./deploy/dvt-testnet.sh start       # build (if needed) + boot 3 nodes + cloudflared
./deploy/dvt-testnet.sh status      # local nodes + cloudflared + public dvt*.aastar.io
./deploy/dvt-testnet.sh info        # nodeId + public URL + pubkey per node
./deploy/dvt-testnet.sh logs 1      # tail node 1 (use `logs cf` for the tunnel)
./deploy/dvt-testnet.sh restart     # stop then start
./deploy/dvt-testnet.sh stop        # stop the 3 nodes + OUR cloudflared (pid-tracked,
                                    # never pkill — other tunnels on the host are safe)
```

Reads `deploy/.env.testnet` + `deploy/.cf-run-token` +
`deploy/node{1,2,3}/node_state.json`; runtime logs/pids in `deploy/.run/`
(git-ignored).

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

## 8. Optional: gasless purchase relay (#98)

The node can also run the **launch token-sale relay** so the gasless
GToken/aPNTs purchase flow stops depending on a single centralized Cloudflare
Worker. When enabled it exposes `POST /v3/relay` (wire-compatible with the old
Worker) and submits buys (EIP-3009 + BuyIntent → BuyHelper) paying gas from a
dedicated hot wallet. Each node is an **independent relayer** — the SDK points
`relayerUrl` at any node and fails over.

This is orthogonal to BLS co-signing (buyer + operator are plain EOAs; no
UserOperation, no validator, no aggregation), so it never affects the 403
owner-auth signing path.

Turn it on with a **separate, funded key per node**. `dvt-testnet.sh` loads the
shared `deploy/.env.testnet` first, then overlays a per-node
`deploy/node$i/.env` (git-ignored) — put each node's own relay key there:

```bash
# shared, once — in deploy/.env.testnet:
RELAY_ENABLED=true

# per node — in deploy/node1/.env, deploy/node2/.env, deploy/node3/.env:
RELAY_OPERATOR_PK=0x<this node's dedicated, funded hot-wallet key>   # NOT the validator-owner key

# generate a fresh key + print its address to fund (repeat per node):
node -e 'const w=require("ethers").Wallet.createRandom(); console.log("RELAY_OPERATOR_PK="+w.privateKey, "\naddress (fund with Sepolia ETH):", w.address)'

./deploy/dvt-testnet.sh restart
curl -s https://dvt1.aastar.io/relay/health | jq .     # {status:"ok", operator:0x…}
```

Public relay endpoints: `https://dvt{1,2,3}.aastar.io/v3/relay`.

⚠️ `RELAY_OPERATOR_PK` is a **public-facing gas-paying key** — keep it
dedicated, fund each node's address with Sepolia ETH, and never reuse the
validator-owner key. Addresses default to the Sepolia Path-A sale stack;
override `RELAY_*` for a different deployment. See
[`.env.testnet.example`](./.env.testnet.example) for all knobs.

---

## 9. 运维手册（macOS 本地部署）

### 服务一览

共 2 个进程，6 个逻辑服务：

| 服务 | 端口 | 说明 |
|------|------|------|
| DVT node 1 | 4001 | BLS 联合签名节点 |
| DVT node 2 | 4002 | BLS 联合签名节点 |
| DVT node 3 | 4003 | BLS 联合签名节点 |
| cloudflared | — | 将三节点暴露为 dvt1/2/3.aastar.io |
| relay（内置） | 同节点端口 | Gasless 代币购买中继，`POST /v3/relay` |
| keeper（内置） | 同节点端口 | 节点签名策略 / 心跳 |
| x402-facilitator（内置） | 同节点端口 | x402 支付撮合 |
| **price-keeper** | — | 独立进程，每 3 分钟刷新 SuperPaymaster 价格预言机 |

> relay / keeper / x402-facilitator 是 DVT 节点的内置模块，随节点启停，不需要单独管理。
> price-keeper 是独立进程，由 LaunchAgent 托管。

---

### 查看所有服务状态

```bash
cd ~/Dev/aastar/YetAnotherAA-Validator
./deploy/dvt-testnet.sh status
```

输出示例：
```
local nodes:
  node1 :4001  ✅ UP
  node2 :4002  ✅ UP
  node3 :4003  ✅ UP
cloudflared:  ✅ running
relay (#98, optional):
  node1 relay: ✅ enabled  ...
keeper (#58, optional):
  node1 keeper: ✅ enabled  ...
x402-facilitator (optional):
  node1 facilitator: ✅ enabled  ...
price-keeper (standalone):
  price-keeper: ✅ running
public:
  https://dvt1.aastar.io  ✅  ...
```

---

### 启动

```bash
cd ~/Dev/aastar/YetAnotherAA-Validator

# 启动 DVT 三节点 + cloudflared（含 relay / keeper / facilitator）
./deploy/dvt-testnet.sh start

# 启动 price-keeper（通常由 LaunchAgent 自动启动，手动启动用这个）
cd ~/Dev/aastar/aastar-sdk
./run-keeper.sh sepolia
```

### 停止

```bash
cd ~/Dev/aastar/YetAnotherAA-Validator

# 停止 DVT 三节点 + cloudflared
./deploy/dvt-testnet.sh stop

# 停止 price-keeper
pkill -f "keeper.ts.*sepolia"
```

### 重启

```bash
cd ~/Dev/aastar/YetAnotherAA-Validator

# 重启 DVT 三节点 + cloudflared
./deploy/dvt-testnet.sh restart

# 重启 price-keeper（通过 LaunchAgent）
launchctl kickstart -k gui/$(id -u)/io.aastar.price-keeper
```

---

### 查看日志

```bash
cd ~/Dev/aastar/YetAnotherAA-Validator

# DVT 节点日志（1 / 2 / 3 任选）
./deploy/dvt-testnet.sh logs 1
./deploy/dvt-testnet.sh logs 2
./deploy/dvt-testnet.sh logs 3

# cloudflared 隧道日志
./deploy/dvt-testnet.sh logs cf

# price-keeper 日志
tail -f ~/Dev/aastar/aastar-sdk/keeper.log
```

---

### 开机自启（macOS LaunchAgent）

两个 plist 已配置在 `~/Library/LaunchAgents/`，Mac 登录后自动启动，无需手动操作：

| plist 文件 | 管理的服务 | 崩溃自动重启 |
|-----------|----------|------------|
| `io.aastar.dvt-testnet.plist` | DVT 三节点 + cloudflared | 否（脚本后台化后退出属正常） |
| `io.aastar.price-keeper.plist` | price-keeper | 是 |

手动加载 / 卸载（通常不需要）：

```bash
# 加载（开机自启生效）
launchctl load ~/Library/LaunchAgents/io.aastar.dvt-testnet.plist
launchctl load ~/Library/LaunchAgents/io.aastar.price-keeper.plist

# 卸载（取消自启）
launchctl unload ~/Library/LaunchAgents/io.aastar.dvt-testnet.plist
launchctl unload ~/Library/LaunchAgents/io.aastar.price-keeper.plist
```

检查 LaunchAgent 运行状态：

```bash
launchctl list io.aastar.dvt-testnet
launchctl list io.aastar.price-keeper
# PID 有值 = 正在运行；LastExitStatus = 0 = 上次正常退出
```

---

### ⚠️ price-keeper 为什么不能停

price-keeper 每 3 分钟调用一次 `SuperPaymaster.updatePrice()`。
一旦停止 → aPNTs 价格过期 → `getRealtimeTokenCost` revert → 用户看到
`InsufficientBalance`（哪怕账户有 1000 万 aPNTs 也没用）。

签名账户：anni EOA `0xEcAACb915f7D92e9916f449F7ad42BD0408733c9`（持有 `PRICE_UPDATER_ROLE`）。

---

## Notes

- **Independence is the point** (TESTNET_RELEASE_PLAN §5): real multi-party
  means 3 keys, 3 operators, 3 hosts — not 3 processes with shared keys. For a
  true N-of-M, different operators each run this compose with their own key +
  their own Cloudflare tunnel.
- `POLICY_ENABLED=true` + `POLICY_REGISTRY_ADDRESS` turns on the independent
  policy gate (see [`docs/DVT_VALUE.md`](../docs/DVT_VALUE.md)).
- Keys never enter the image — `node_state.json` is a read-only mount.
