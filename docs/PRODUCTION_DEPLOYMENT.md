# DVT 生产环境部署 Runbook

> 目标:**照这份文档一步步走，就能把一套生产（mainnet）DVT 跑起来并验证通过。**
> 适用对象:AAStar 官方参考节点运维，以及任何要在主网自建 DVT 的社区运营方。
>
> 关联:[`deploy/README.md`](../deploy/README.md)（测试网 runbook）·
> [`deploy/DEPLOYMENT_OPTIONS.md`](../deploy/DEPLOYMENT_OPTIONS.md)（托管方案对比）·
> 本仓库 issue #100（主网规划）· #98（relay）· #58（keeper）· PR #105（nonce 硬化）

---

## 0. 一句话:测试环境 ≠ 生产环境的本质

DVT 节点本身是**链无关**的：换一套 `.env`（链、合约地址、密钥、RPC）就从测试网变主网（见
multi-chain 决议——多实例、各自 `.env`，不在进程内切链）。所以"部署生产"不是改代码，是:
**换一套主网配置 + 把"测试网能凑合"的每一项都换成"生产必须可靠"的版本**（密钥托管、RPC、Gas、HA、监控、策略门）。

---

## 1. 测试 vs 生产 —— 全景对照表

| 维度 | 测试环境（当前，Sepolia） | 生产环境（mainnet） |
|---|---|---|
| **链** | Sepolia `chainId 11155111` | 目标主网（Ethereum / Optimism `chainId 1` / `10`）—— 先定链 |
| **合约地址** | validator `0xAF525A…`、SuperPaymaster `0x030025…`、PaymasterV4 `0x957852…`、BuyHelper `0xF78f…` | **全部换主网部署地址**（EntryPoint v0.7 `0x0000000071727De…` 跨链同址，是唯一不变的） |
| **BLS 签名密钥** | 本地生成、明文存 gitignored `node_state.json` | **HSM / KMS 托管**（`SIGNER_BACKEND`，arch #67）或至少加密磁盘 + 受限主机 |
| **Relay / Keeper 热钱包** | 水龙头 ETH，0.2–0.5 ETH，随手生成 | **真金 ETH**，预算化、限额、监控余额、定期轮换 |
| **Gas** | 免费、不在乎 | **真钱**——估值 +15% 自动 bump（已在 PR #105）；relay 还要补**提交前 eth_call 预检**（见 §6）避免给注定 revert 的 tx 烧真 gas |
| **RPC** | 凑合（本次就因 RPC mempool 不广播导致 nonce 卡 10 小时） | **专用付费 RPC（Alchemy/Infura 付费档或自建全节点）+ 故障转移**，这是硬要求 |
| **主机 / HA** | 一台 Mac，3 进程 + cloudflared | **≥2 台**互备（单机=单点）；不同操作方/不同机房更佳 |
| **自愈** | `dvt-testnet.sh` 手动 | **Docker `restart: unless-stopped` / systemd `Restart=always`** + 开机自启 |
| **公网入口** | cloudflared quick/named tunnel | 稳定域名 + named tunnel **或**反代 + TLS + 负载均衡 |
| **策略门** | `POLICY_ENABLED=false` | **`POLICY_ENABLED=true`** + 主网 `POLICY_REGISTRY_ADDRESS`（独立第二因子，强烈建议开） |
| **限流** | 可选 | `RATE_LIMIT_ENABLED=true`（挡 pre-auth RPC 放大） |
| **Keeper 冗余** | 3 节点都开（输家偶尔冗余 revert，免费） | 冗余 revert 烧**真 gas** → 建议**单 keeper + 热备**或确定性分配（见 §6） |
| **监控告警** | 看日志 | **必须**：健康探针 + 余额看护 + nonce 健康 + 价格新鲜度 + 失败告警（接 #52 通知） |
| **变更/漂移** | 手动 | `npm run check-deps` 定期对主网 baseline 跑，合约漂移即告警 |

---

## 2. 前置诉求（开工前必须就位）

按依赖顺序，缺一不可:

1. **主网合约已部署并验证**（不是 DVT 的事，但 DVT 依赖它）:
   - `AAStarValidator` / `AAStarBLSAlgorithm`（BLS 校验）—— 拿到主网地址。
   - `SuperPaymaster` + 社区 `PaymasterV4`（keeper 要保活的报价合约）—— 主网地址 + 确认 `cachedPrice()`/`updatePrice()` 接口一致（用 `check-deps`）。
   - `BuyHelper`（relay 提交目标，带 `onlyRelayer`）—— 主网地址，且 **constructor/白名单要纳入我们主网 relay operator 地址**（和 launch 协调，见 §5）。
2. **目标链确定** + 该链的 **Chainlink ETH/USD feed 地址**（keeper 用）。
3. **专用 RPC**：付费 Alchemy/Infura（或自建全节点）+ 一个备用 RPC（故障转移）。**不要用免费共享端点**。
4. **always-on 主机 ≥2 台**：Mac mini / 云 VM，Docker 可跑，24h 在线。
5. **域名 + Cloudflare 账号**（named tunnel）或反代 + 证书方案。
6. **国库/资金流程**：给 relay、keeper 热钱包持续供应主网 ETH 的预算与流程。
7. **密钥托管决策**：BLS 签名键走 HSM/KMS（`SIGNER_BACKEND`）还是受限主机加密磁盘——生产前定。
8. **监控栈**：uptime 探针 + 告警通道（Telegram/#52 通知模块 contacts）。

---

## 3. 部署步骤（生产 runbook）

> 假设走推荐路径:**Docker + Cloudflare named tunnel**（`DEPLOYMENT_OPTIONS.md` 方案一），≥2 台主机各跑一套。每台 = 1 个 DVT 节点身份。

### 3.1 生成生产密钥（每个节点 3 把，隔离）

每个节点要 **3 个独立 EOA + 1 个 BLS 身份**:

```
BLS 签名身份   → node_state.json（生产建议 HSM/KMS；私钥永不进 git，永不复用测试夹具）
RELAY_OPERATOR_PK → relay 代付热钱包（对外、烧 gas、最该轮换）
KEEPER_PRIVATE_KEY → keeper updatePrice 热钱包（和 relay 分开，避免 nonce 互踩——PR #105 已强制分离）
ETH_PRIVATE_KEY   → 注册/admin（只在 registerPublicKey 时用，之后可下线/冷存）
```

生成（打印地址去充值，私钥落 gitignored 文件，**不打印**）:
```bash
node -e 'const w=require("ethers").Wallet.createRandom();console.log(w.privateKey,"\naddr:",w.address)'
```
> ⚠️ 主网密钥用硬件/隔离环境生成更稳；relay/keeper 是热钱包，**限额**（只放够用的 ETH）。

### 3.2 在主网 validator 注册节点公钥

`registerPublicKey` 当前是 `onlyOwner`（协调步骤）或走无许可质押注册（见 `deploy/README.md` §3b）。
注册后核对链上 `isRegistered(nodeId) === true`。

### 3.3 让主网 BuyHelper 把 relay operator 加白名单

和 launch 协调（同测试网 dvt#5 的流程）:把每台节点的 `RELAY_OPERATOR_PK` 地址写进主网
`BuyHelper` 白名单（`isRelayer(addr)===true`）。**强烈建议主网 BuyHelper 用可增删的白名单集合**，
而非单个 immutable（否则换 key 要重部署合约）。

### 3.4 配置 `.env.mainnet`

拷 [`deploy/.env.mainnet.example`](../deploy/.env.mainnet.example) → `deploy/.env.mainnet`（gitignored），填:
- `ETH_RPC_URL` = 专用主网 RPC（+ 备用）
- `VALIDATOR_CONTRACT_ADDRESS`、`ENTRY_POINT_ADDRESS`（v0.7 同址）
- `POLICY_ENABLED=true` + `POLICY_REGISTRY_ADDRESS`（主网）
- `RATE_LIMIT_ENABLED=true`
- relay:`RELAY_ENABLED=true` + 主网 `RELAY_BUY_HELPER` / `RELAY_USDC` / `RELAY_GTOKEN` / `RELAY_APNTS` + 复核 caps
- keeper:`KEEPER_ENABLED`、`KEEPER_PAYMASTER_ADDRESS`（主网 SuperPaymaster + PaymasterV4，逗号分隔）、`KEEPER_CHAINLINK_FEED`（主网 feed）
- 每节点私钥放各自 `deploy/node$i/.env`（per-node overlay）

### 3.5 充值热钱包（主网 ETH）

给每台的 `RELAY_OPERATOR_PK` / `KEEPER_PRIVATE_KEY` 地址打**少量、够用**的主网 ETH，记录初始余额，接入余额监控（§7）。

### 3.6 起服务（Docker，自愈）

把 `docker-compose.testnet.yml` 复制为 `docker-compose.mainnet.yml`，env_file 指 `.env.mainnet`，确认:
- `restart: unless-stopped`、`healthcheck`（探 `/health`）、`127.0.0.1` 端口绑定、key 文件 `:ro` 挂载
```bash
docker compose -f docker-compose.mainnet.yml up -d --build
```
配 named tunnel（`deploy/cf-tunnel-setup.mjs` 同款）把节点暴露成稳定域名（如 `dvt.aastar.io` / `dvt1.aastar.io`）。

### 3.7 冒烟验证（见 §4 全量回归之前的快检）

```bash
curl -s https://<域名>/health | jq .            # status ok + capabilities
curl -s https://<域名>/relay/health | jq .       # operator 在白名单内
curl -s -o /dev/null -w "%{http_code}\n" -X POST https://<域名>/signature/sign \
  -H 'content-type: application/json' -d '{"userOp":{}}'   # → 403 fail-closed
```

---

## 4. 部署后全量回归测试

按层跑全，**全绿才算上线**:

| 层 | 怎么跑 | 通过标准 |
|---|---|---|
| 单元/集成 | `npm run test:ci` | 全部通过（含 owner-auth、policy、keeper、relay、gas） |
| 合约一致性 | `cd contracts && forge test` | 通过；`npm run check-deps` 对**主网** baseline 无漂移 |
| 多节点链上 E2E | `scripts/e2e/realnode-e2e.mjs` 指向主网节点 URL + nodeId | N 节点共签 → 主网 `AAStarBLSAlgorithm.validate() === 0`；ECDSA(0x02) 被拒 |
| owner-auth 门 | 空体/伪造 ownerAuth | 一律 **403**（永不 400） |
| 策略门 | 构造越界 op（超 perTxMax / 非 allowlist 收款人） | 被拒（独立第二因子生效） |
| Relay E2E | 主网发一笔**小额**真实 gasless 购买（SDK `buyGasless`） | 链上 tx success；`/relay/health` operator 正常 |
| Keeper | 等价格接近 stale，观察 | 主网 paymaster `cachedPrice.updatedAt` 被刷新；**无 nonce 积压**（PR #105 已修，重点盯） |
| 限流 | 超频打 `/signature/sign` | 触发 429 |
| 自愈 | `docker kill` 一个容器 | 自动重启、健康恢复 |
| 监控 | 触发一次 keeper/relay 失败 | 告警到位 |
| 软压测/soak | 持续观察 24–72h | 余额平稳、nonce 健康、价格常新、无堆积 |

> 验证脚本可参考 `deploy/verify-prod-e2e.mjs`（已含 RPC 重试），改指主网。

---

## 5. 周知上下游（生产配置发布）

部署完**必须**同步出去，否则端到端不通:

| 对象 | 内容 |
|---|---|
| **SDK（aastar-sdk）** | 在 `sdk-dvt-config` 的 `environments.mainnet` 填:主网 DVT URL + nodeId + 合约地址；SDK 把 `active` 切 `mainnet` 即生效（零代码切换）。请其跑**主网连通性自测**（同测试网 #153） |
| **launch（MushroomDAO/launch）** | 主网 `BuyHelper` 白名单纳入我们主网 relay operator 地址；BuyHelper 地址回传给我们填 `RELAY_BUY_HELPER` |
| **KMS / AirAccount** | 若 BLS 键托管走 KMS；ownerAuth 签名方案一致性 |
| **协调器 / Bundler** | 主网节点 URL + nodeId + userOpHash 约定（EntryPoint v0.7 `getUserOpHash` + EIP-191 ownerAuth） |
| **内部运维** | 监控面板、on-call、余额告警阈值、incident playbook |

---

## 6. 生产专属加固（测试网欠的债，主网必须补）

1. **Relay 提交前 eth_call 预检**（#98 已知限制）:主网前给 relay 加 `staticCall(executeBuy)`，
   会 revert（过期/滑点/库存）就**不提交**，避免给注定失败的 tx 烧真 gas + 挡 griefing。
2. **Keeper 冗余的真 gas 成本**:测试网 3 keeper 输家冗余 revert 免费；主网应**单 keeper + 热备**，
   或 paymaster→节点**确定性分配**（用现成 gossip 层），彻底消除冗余提交（PR #105 的预检已大幅减少，但主网值得做满）。
3. **RPC 可靠性**:本次事故根因就是 RPC mempool 不广播 → tx 卡 10h 过期 revert。主网**专用 RPC + 备用 + 监控**（出块延迟、pending 是否被丢）。
4. **热钱包限额 + 轮换**:relay/keeper 只放够用 ETH；定期轮换；白名单用可增删集合以支持轮换。
5. **策略门 + 确认门**:`POLICY_ENABLED=true`；高额 op 可开 `CONFIRM_ENABLED`（带外确认）。

---

## 7. 持续运维（上线后）

- **健康探针**:`/health`、`/relay/health`、`/node/info`（Docker healthcheck + 外部 uptime）。
- **余额看护**:盯 relay/keeper 两个热钱包，低于阈值告警充值。
- **nonce 健康**:监控 operator `pending - latest`，>0 持续 = 卡住（本次的教训）→ 用高 gas 自转覆盖解卡，并查 RPC。
- **价格新鲜度**:监控两个 paymaster `cachedPrice` age vs threshold，长期 stale = keeper 异常。
- **漂移**:定期 `npm run check-deps`（主网 baseline）。
- **密钥轮换**:relay/keeper 周期轮换；轮换前确保 BuyHelper 白名单可增删。
- **Incident playbook**:RPC 故障 → 切备用 RPC + 重启；nonce 卡 → 解卡脚本；合约重部署 → 同步 `RELAY_BUY_HELPER` + 通知 SDK（参考 dvt#5 三方对齐时序）。

---

## 8. 待决策 / 开放问题

- **生产链**:Ethereum mainnet 还是 Optimism mainnet（或多链各一套）？决定后定全部地址。
- **BLS 键托管**:HSM/KMS 还是受限主机？影响 `SIGNER_BACKEND` 与合规。
- **节点数 / 操作方**:几台、谁运营（真去中心化需多操作方多机）。
- **托管路径**:自管 Docker（方案一）还是 PaaS（方案二）——见 `DEPLOYMENT_OPTIONS.md`。
- **资金来源**:relay gas 由谁补贴/结算（销售收入 / 国库 / 未来 aPoints 计价的 Phase 2）。
