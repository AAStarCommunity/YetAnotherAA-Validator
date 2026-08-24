# DVT 运营手册（AAStarValidator / AAStarCommitteeValidator）

> BLS 门限签名验证器 —— 为 ERC-4337 账户的 tier-2/3 授权提供去中心化联签 + 质押问责。Sepolia：legacy
> `0x539B9681…` · committee `0x1A8Db639…`。账户 router `getAlgorithm(0x01)`
> 挂其一。

## 核心价值

账户把 tier-2/3 的 BLS 验证委托给链上 validator。DVT 提供的不是"多签"，是**去中心化门限**：

- **no single node forges a quorum**
  —— 严格递增 nodeId（防单节点重复凑数）+ 质押绑定 + pubkey 唯一性。
- **签名绑定
  `userOpHash`**（EntryPoint 已绑 sender/chainId/nonce）→ 防跨账户 oracle；`accountId`
  绝不进签名。
- **质押问责** —— `registerWithProof` 绑 ROLE_DVT 质押，可 slash。

## 两种模式（同一验证器，owner 手动开关，非自动）

|        | Legacy（whole-set）                 | Committee（per-proposal）                                                              |
| ------ | ----------------------------------- | -------------------------------------------------------------------------------------- |
| 开关   | `epochLength=0`（默认）             | `setEpochLength(N≥64)`（约束 `==0 \|\| >=64`，N=1..63 revert）                         |
| 签名集 | 提交的 nodeId（账户 tier 定最小数） | per-proposal 抽样委员会                                                                |
| quorum | 账户 tier 要求                      | `requiredQuorum()=⌈2·m_e/3⌉`                                                           |
| 抽样   | 无                                  | `H(CMT_SELECT, seed, accountId, nodeId) < T`                                           |
| 前置   | 节点注册                            | 节点注册 + 账户 `enroll()`（airaccount 侧封装 `enrollInCommitteeValidator()`）+ keeper |

**降级规则**：legacy↔committee 手动切；committee 模式**内**委员会大小随 N 自动伸缩（下表）。committee 不需要 17/30 个节点才能用 ——
N=3 即可（退化 whole-set）。

## 安全阈值表（链上 `expectedCommittee`/`requiredQuorum` 实测）

| N 活跃节点 | 委员会 m_e  | quorum | 安全模型                                 |
| ---------- | ----------- | ------ | ---------------------------------------- |
| 3          | 3           | 2      | whole-set 2-of-3（机制验证，非抽样安全） |
| 8 / 17     | =N          | 6 / 12 | whole-set                                |
| 30         | 30          | 20     | whole-set 边界                           |
| 31–150     | 30（floor） | 20     | **抽样开始**（m_e<N）                    |
| 200        | 40          | 27     | 抽样 ⌈N/5⌉                               |
| ≥430       | 86（cap）   | 58     | 抽样上限                                 |

**安全系数**：forgery `P ≤ 1e-6 @ β≤10%`（敌手持 ≤10% 全网质押）；liveness
`P(失败) ≤ 1e-3`；oversample `1.25×`。**floor 30 是抽样安全下限** ——
N<30 走 whole-set BFT 2/3，没有抽样界。cap 86 控 calldata/gas。

## 部署依赖（顺序）

1. validator 合约部署（committee 版 = `#237` AAStarCommitteeValidator）
2. 账户 router `registerAlgorithm(0x01, validator)`（set-once +
   finalized，不可改指）
3. 节点注册到该 validator：`registerWithProof`（生产，质押 30 ETH + PoP）或
   `batchRegisterPublicKeys`（bootstrap，owner，仅测试/受信）
4. committee 模式还需：账户 self-enroll 调验证器 `enroll()`（本仓
   `AAStarCommitteeValidator.sol:323`，selector
   `0xe65f2a7e`，msg.sender=账户；airaccount 侧封装为
   `enrollInCommitteeValidator()`）→
   **迁移联锁：enroll 必须在 setEpochLength 之前**（否则未 enroll 账户 self-brick）

## 运营

- **翻转（两步，不可逆治理）**：`setEpochLength(N)` +
  `snapshotEpoch()`，然后**等跨过一个 epoch 边界**（~N 块）`requiredQuorum()`
  才从哨兵 `type(uint256).max` 变真值 → 读回确认非哨兵再宣布可用。回 legacy =
  `setEpochLength(0)`。
- **keeper**（`deploy/committee-keeper.mjs --watch`）：committee
  ON 时**必须常驻**，每 epoch 在首块后 256 块窗口内 `snapshotEpoch()`
  pin。漏 pin → 该 epoch + 下个 fail-close，自愈。permissionless，建议 ≥2 冗余。
- **proofgen**（`deploy/committee-proofgen.mjs`）：aggregator 对冻结树
  `setRoot[e-1]` 重建 per-signer Merkle 证明。
- ⚠️
  **别把同一把 pubkey 注册成两个 nodeId**（owner 误配缺口，能让 1 个签名者凑假 quorum）——注册前查 pubkey 未占用。

## 验证过程（`validate(userOpHash, payload)`）

1. `messagePoint = hashToG2(userOpHash)`（RFC-9380，DST=`BLS_SIG_..._POP_`，链上/节点/KMS 三方逐字节一致）
2. 逐 signer：nodeId 严格递增 + `isRegistered` +（committee：Merkle proof ∈
   `setRoot[e-1]` + sortition 命中）
3. Σpubkey 聚合 + EIP-2537 pairing 验 Σsig（k=2 每对 102,900 gas）
4. `k ≥ requiredQuorum`
5. 全过 → `return 0`（accept）；任一不过 → `return 1`（**fail-closed**）

## 节点侧（signer 服务）核心

- `POST /signature/sign` **fail-closed**：必须带完整 PackedUserOp + owner
  ECDSA 授权（节点自派生 userOpHash 再验 `isValidOwnerAuth`），任何失败一律
  **403**。防未授权调用方，不防 owner 私钥泄露（那靠链上 guard 限额）。
- 密钥：`node_state.json`（BLS 私钥，git-ignored）或 KMS-TEE 托管（`RUST_SIGNER_URL`）。
- **改状态的 admin 端点默认关闭**（`POST /node/register`、`POST /dashboard/nodes`、
  `POST /dashboard/import-node`、`DELETE /dashboard/current-node`、`POST /gossip/data`）。节点监听
  `0.0.0.0` 且经隧道公网可达，这些端点此前完全无鉴权（CC-49 round-4
  HIGH-1）。注册请走 CLI `node scripts/register-node.mjs`；确需 HTTP 时按
  [node-admin 端点说明](./NODE_ADMIN_ENDPOINTS.md) 配 `NODE_ADMIN_ENABLED` +
  `NODE_ADMIN_TOKEN`（默认仅 loopback，带限流，token 不得复用 RepCredit 实验密钥）。
