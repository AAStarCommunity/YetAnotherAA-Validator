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

- **committee-off 窗口（部署 → enroll → 翻
  `setEpochLength`）**：账户侧**链上强制** tier-2/3 fail-closed ——
  `airaccount-contract` #208（merged `72d2311`, v0.32.0）的 `_blsAlgMode()`
  三态：`committeeActive()` 返回 `false`（本验证器已挂载但未武装）⇒
  tier-2/3 直接拒；返回 `true` ⇒ 正常 committee；**revert** （真 legacy
  `0x539B`，没有该函数）⇒
  whole-set 直通，长期共存不受影响。⚠️ 所以 cutover 期间 tier-2/3 是**不可用**，不是**不受保护**
  —— 这是刻意的 fail-closed 姿态。**不再需要**「cutover 期间不挂 tier-2/3 账户」这条运维纪律，它已被链上边界取代。
- **前置：`setBlsAggregator(...)`（质押模式必须）**。CC-112
  D2 起，快照会读每个 operator 的 ROLE_DVT 退出通知，地址必须等于 SP
  `Registry.blsAggregator()`
  发布的那个（合约会强制比对）。没设或与 Registry 不一致 → 每次快照
  `aggregator stale: re-run setBlsAggregator`
  fail-closed。纯 bootstrap 集合不需要。
- **翻转（两步，不可逆治理）**：`setEpochLength(N)` +
  `snapshotEpoch(activeNodeIds)`，然后**等跨过一个 epoch 边界**（~N 块）
  `requiredQuorum()` 才从哨兵 `type(uint256).max`
  变真值 → 读回确认非哨兵再宣布可用。回 legacy = `setEpochLength(0)`。
- **keeper**（`deploy/committee-keeper.mjs --watch`）：committee
  ON 时**必须常驻**，每 epoch 在首块后 256 块窗口内
  `snapshotEpoch(activeNodeIds)` pin。漏 pin
  → 该 epoch + 下个 fail-close，自愈。permissionless，建议 ≥2 冗余。keeper 从
  `SlotAssigned`/`SlotCleared` 事件重建活跃集并与 `activeCount()`
  对账，不用链上 O(n²) 的 `activeNodeIdsSorted()` helper（那个只供本地调用）。
- **快照被拒时怎么办**：`snapshotEpoch`
  要求集合中每个成员都合格，拒绝时按原因分流：
  - `ineligible node in set` → 用 `isEligibleForSnapshot(nodeId)` 找出是谁，然后
    - 掉质押 / 失去 ROLE_DVT → **`syncNode(nodeId)`**
    - 有在途 ROLE_DVT 退出通知 → **`syncExitNotice(nodeId)`**。⚠️ 这种情况
      `syncNode` 会报 `Node still active`：SP 在整个 2 天通知期内**保留**
      role 和 stake，所以 stake 判据看它仍然健康。没有这条路径，一次**正常退出**就能让快照卡死两天。两个都是 permissionless。
  - `aggregator stale: re-run setBlsAggregator` → SP 轮换了 aggregator，见下。
- **⚠️ 快照 gas 的运营上限（实测，非保证）**：`snapshotEpoch`
  对活跃集大小线性，且链上**没有** N 上限（`TREE_DEPTH=14` ⇒
  16,384 个槽位）。bootstrap 路径实测（**下界**，不含外部调用）：N=10 → 153,738
  gas；50 → 202,109；100 → 263,163；200 → 387,231，约 **1,229
  gas/节点**。质押路径每节点多两次外部 view 调用，斜率明显更陡（估 8–15k/节点，**未实测**）。按该斜率，**几千个节点**就会把 pin 推过 30M 区块上限 —— 而
  **pin 不上等于该 epoch 全网 fail-close**。刻意不加硬上限：委员会曲线是按池规模到 20,000 设计的，硬限会与本验证器要实现的取值自相矛盾。根本解法是**分批快照**（未来工作）。在那之前请**监控活跃集规模**，并在接近前用
  `syncNode`/`syncExitNotice` 清理失格节点。
- **⚠️ `epochLength`
  上界**：`2 · epochLength · 24s < GUARDIAN_EXIT_DELAY(2 days)` ⇒ **L ≤
  3599**（12 秒出块 ≈ 12 小时/epoch）。这是 **liveness** 约束不是安全约束：
  `validate` 同时需要 `_epochUsable(e)` 与
  `_epochUsable(e-1)`，若一个 epoch 的墙钟时长逼近 2 天，`setRoot[e-1]` 在 `e`
  里就已过期 →
  committee 模式**永久 fail-close**。24 秒是出块时间的**上界**假设（允许持续 missed
  slot）；高估是保守方向，猜错的代价是过度保守（fail-closed 可见），不是静默放松。
- **⚠️ 链停摆超过 2 天**：所有已 pin 的快照按时钟过期，committee 模式 fail-close 直到 keeper 重新 pin。这是刻意的 —— 过期意味着「冻结时质押 ⟹ 仍可罚没」不再成立。
- **⚠️ aggregator 轮换的迁移顺序（会短暂停摆，属预期）**：SP 先
  `Registry.setBLSAggregator(successor)`。此后本验证器的快照立即 fail-closed（宁可停也不能拿旧 ledger 判断——旧的对新 aggregator 上申报的通知一律返回「无通知」，那是静默 fail-open）。owner 随后
  `setBlsAggregator(successor)`，这会 **bump
  `configVersion`**，使**所有已 pin 的快照失效**。后果：当前 epoch 必然停摆；若轮换发生在 pin 窗口之外，下一个 epoch 也停。因此**轮换应安排在维护窗口**，并在轮换后立刻让 keeper 重新 pin。已冻结但尚未过期的快照不会被「偷偷继续用」——这是刻意的 fail-closed。
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
