# DVT End-to-End: Validated Architecture → Production Service

> 状态: **生产化设计（绑定 #110 链上坐实的 C4 E2E）** · 协调 hub: #42 · 关联:
> #40 本文吸收 airaccount-contract C4
> E2E（Sepolia 链上真实验证、Codex 核过）的架构、流程、经验与教训，规划 DVT 作为**真正上线 service**
> 所需的数据、真实服务与待补支持。最后更新: 2026-06-16

---

## 0. 为什么这份文档

DVT 不是 demo，是要上线的 service。#110 的 C4 E2E 已在 Sepolia
**链上坐实**了组合签名的验证逻辑（至少模拟节点版被验证通过）。本文把那条被验证的底层架构作为锚点，回答三件事：
**①
DVT 该怎么 follow 这条被验证的架构 ② 各基础设施能力怎么串起来 ③ 真实跑通需要哪些数据、真实服务、和目前还缺的支持。**

---

## 1. #110 C4 E2E 坐实了什么（验证锚点）

Sepolia 真实链上验证（测试账户
`0x45Dfe3D5938fDf5a8D30641C3FDA9c9fb1F31ba9`，Factory
`0x1b694Aa5…`，v0.18.0-beta.2），Codex 逐笔核过 receipt/status/gas：

| 档        | 因子                                       | algId | 结果                      | gas   |
| --------- | ------------------------------------------ | ----- | ------------------------- | ----- |
| Tier1     | ECDSA                                      | 0x02  | ✅ PASS                   | —     |
| **Tier2** | **P256 主签 + ≥门限 BLS 聚合（DVT 共签）** | 0x04  | ✅ PASS                   | ~349K |
| **Tier3** | P256 + BLS + Guardian ECDSA                | 0x05  | ✅ PASS                   | ~357K |
| 负向      | 低档因子→高档额度                          | —     | ✅ 正确拒（inner-revert） |

**被坐实的底层不变量（DVT 必须 follow 这条）：**

1. 真实 P256 + 真实 BLS 聚合 over
   `userOpHash`（EntryPoint 派生，非 caller 传入）。
2. **wire = `[nodeIdsLength(32)][nodeIds(N×32)][blsSig(256)]`**；messagePoint
   **不传**，链上 `AAStarBLSAlgorithm` 用 `hashToG2(userOpHash)`（RFC 9380, DST
   `_POP_`）重算，EIP-2537 pairing 验证（#45 绑定，跨 op replay 不可能）。
3. BLS 聚合 = G2 点加；签名 = `sk·hashToCurve(userOpHash)`；编码 = EIP-2537
   256B（x.c0@16 / x.c1@80 / y.c0@144 / y.c1@208）。
4. 分档由额度触发；档位不足额度 → 链上拒。

**经验/教训：**

- 链上**只能验**，不产签名；正确性全靠"链上重算 messagePoint + 丢弃 caller 值"。
- gas ~350K 来自 BLS 预编译（EIP-2537
  pairing）——大额才上 DVT 的分层是必要的成本控制。
- 模拟版的"真实度边界"= BLS 签名来自 noble 本地
  `sk·H(m)`，公钥已链上注册 → 验证 100% 真， **只有签名来源是模拟的**。

---

## 2. DVT 全链路（生产，端到端）

```
 用户/owner          SDK(#63)            DVT 节点群(本仓库,≥门限)        链上
   │  发起 op          │                      │                          │
   ├─ 构造 userOp ────►│                      │                          │
   │                   ├─ userOpHash = EntryPoint.getUserOpHash(userOp)  │
   │                   ├─ 主签: P256/passkey 或 KMS(secp256k1) over hash │
   │  owner ECDSA 签 ─►│  (ownerAuth = owner() 的 EIP-191 sig over hash) │
   │                   ├─ 对每个节点 i:  POST /signature/sign {userOp, ownerAuth}
   │                   │       节点 i: ①Stage1 验 ownerAuth==owner()  ②Stage2 策略门
   │                   │               ③签 sk_i·hashToCurve(userOpHash) ─► signature_i
   │                   │◄───────────── { nodeId_i, signature_i(EIP-2537), publicKey_i }
   │                   ├─ aggregate: aggSig = Σ signature_i  (点加 / /signature/aggregate)
   │                   ├─ wire: [nodeIdsLength][nodeIds][aggSig] + 主签 → 组合签名
   │                   ├─ 提交 handleOps ────────────────────────────────►│
   │                   │                      │     account.validateUserOp:
   │                   │                      │       验主签 + AAStarBLSAlgorithm.validate(
   │                   │                      │         userOpHash, [nodeIds][aggSig])
   │                   │                      │       链上重算 messagePoint + pairing
   │                   │                      │     PolicyRegistry.checkPolicy (验证期, 可选)
   │                   │                      │     ✅ valid → 执行
```

**关键：DVT 节点的独立性三支柱**（命门，见 #70）——独立 BLS
key、独立策略（本地 layer-2 + 链上 layer-1）、独立通道（节点 HTTP 直连，不经 CA）。安全增益全来自此，盲签=橡皮图章。

---

## 3. 各基础设施能力串接

| 能力                                                | 提供方                                     | 接口                                                                              | 在链路中的位置       |
| --------------------------------------------------- | ------------------------------------------ | --------------------------------------------------------------------------------- | -------------------- |
| 节点协议 / BLS 共签                                 | **YetAnotherAA-Validator(本仓库, v1.1.0)** | `POST /signature/sign`、`/signature/aggregate`、`/node/register`                  | 产 `signature_i`     |
| 节点身份/质押/slash + BLS 聚合验证 + PolicyRegistry | **SuperPaymaster #283**                    | `registerBLSPublicKey`、`setConsumerAuthorization`、`checkPolicy`                 | 链上注册/授权/策略源 |
| 账户链上验组合签名                                  | **airaccount-contract #110**               | `AAStarBLSAlgorithm.validate(userOpHash, [nodeIds][blsSig])`、co-sign entry-point | 链上验证             |
| 客户端组装                                          | **aastar-sdk #63**                         | `aggregatorActions`、`encodeDVTProof`、`policyRegistryActions`                    | 串 SDK 组装 + 提交   |
| 主签（大额第一因子）                                | **AirAccount KMS/TEE #70**                 | secp256k1 主签 + #68 passkey 授权绑定（challenge=SHA256(nonce‖userOpHash)）       | 产主签；C1 绑定向量  |
| 激励/slash 经济                                     | **Brood PGL #3**                           | `IDVTIncentive`（贡献 SBT 绑正确执行，非签名次数）                                | 节点经济约束         |
| 节点发现                                            | 本仓库 gossip                              | WebSocket `/ws`                                                                   | 节点群组网           |

---

## 4. 模拟 → 真实 差距分析（要替换什么）

| 环节         | #110 模拟版          | 生产真实版                                            | 差距 / 替换                                                                  |
| ------------ | -------------------- | ----------------------------------------------------- | ---------------------------------------------------------------------------- |
| BLS 签名来源 | noble 本地 `sk·H(m)` | 真节点 `POST /signature/sign`                         | **drop-in**：wire 不变，换签名来源                                           |
| 节点闸门     | 无（直接 sk 签）     | **Stage1 owner-auth + Stage2 策略门**                 | ⚠️ 真节点拒无 `ownerAuth`；账户须有 ECDSA `owner()≠0x0`                      |
| 账户 owner   | 脚本本地 signer      | 真账户 owner                                          | passkey-only（owner==0x0）→ 真节点 Stage1 fail-closed（=#40 Stage2，未实现） |
| 主签         | P256 本地私钥        | KMS/TEE secp256k1 + passkey                           | 接 AirAccount KMS（#70 已交付绑定向量）                                      |
| 门限/多样性  | 2 个本地 key         | M-of-N 跨独立运营方/法域                              | 防串谋；当前缺真多运营方                                                     |
| 策略         | 无                   | PolicyRegistry（per-sender,验证期可读）+ 节点 layer-2 | E2E 须配 registry 放行或关策略                                               |
| 独立通道     | N/A                  | 客户端直连节点（不经 CA）                             | D2，待形式化（#42 节点协议）                                                 |

---

## 5. 真实跑通需要的数据

- **≥门限个 DVT 节点**：各自独立 BLS keypair，已 `registerBLSPublicKey`
  上链（已知 slot）。
- **测试/生产账户**：`owner()` =
  ECDSA 地址（≠0x0）；或 passkey-only 则**阻塞于 #40 Stage2**。
- **owner 私钥/签名能力**：客户端能产 `ownerAuth`（owner EIP-191 over
  userOpHash）。
- **PolicyRegistry 配置**：`setConsumerAuthorization(账户/consumer)`；如启用策略，配 AssetPolicy/ContractScope 使测试 op
  = ALLOW。
- **EntryPoint / Factory / BLSAlgorithm /
  PolicyRegistry 地址**（Sepolia 已知）。
- **资金**：Sepolia ETH 付 gas（DVT tx ~350K）。
- **主签材料**：P256/passkey 或 KMS 密钥 + #68 nonce。

---

## 6. 真实跑通需要的服务

- **≥门限个运行中的 YetAnotherAA-Validator
  v1.1.0 实例**（独立 key/策略/通道；理想 M-of-N 跨运营方）。
- **AirAccount KMS/TEE**：产主签 + passkey 授权绑定。
- **SuperPaymaster**：PolicyRegistry（已部署 Sepolia
  `0x8c2488d4…`，v5.4.0-beta.1-redeploy）+ BLSAggregator + 授权 consumer。
- **aastar-sdk 运行时**：组装 + 提交（待 cut release / npm 发布）。
- **RPC 端点**（Sepolia/mainnet）+ bundler（SuperRelay 或公共）。
- **gossip 网络**：节点发现（≥3 节点）。

---

## 7. 真实上线还缺的支持（hub 提出，供 program 决策）

1. **#40 Stage 2 — P256/passkey-owner 授权**：当前真节点只支持 ECDSA
   `owner()`；passkey-only 账户（大额 Tier2 的主流）真节点会 fail-closed。**这是 passkey 账户上 DVT 的硬阻塞**，需补节点侧 P256-owner 授权路径（读账户 passkey/attestation 验 ownerAuth）。**优先级最高。**
2. **独立确认通道（D2）形式化**：co-signer 独立性第三支柱。当前
   `/signature/sign`
   已是直连 HTTP，但缺"客户端如何直连各节点、不经 CA"的形式化协议 + 节点发现/寻址规范。
3. **节点运营方多样性（M-of-N）**：真实跨运营方/法域/软件栈部署，防同质化一锅端。当前只有参考实现，需招募/部署 ≥3 独立运营方。
4. **节点 BLS 私钥的生产级管理**：节点私钥应进 KMS/HSM，非明文
   `node_state.json`（README 已警示）。
5. **带外确认（#40 Stage2 第二机制）**：大额 op push/email 给真实用户二次确认。
6. **Slashing 上线 + 激励闭环**：Brood `IDVTIncentive` 与 SP
   slash 路径联调（贡献 SBT、slash 盲签/违策略）。
7. **监控/可观测性 + 限流**：节点签名审计、异常检测、按账户限流（防 DoS）。
8. **Mainnet 部署 + 外部审计**：跨仓库组合签名 +
   PolicyRegistry 上主网前的安全审计。

---

## 8. 真·跨仓库 E2E（基于 #110 脚本 drop-in，下一步）

1. **#110**：测试账户配 ECDSA `owner()`（或声明 passkey-only → 走 §7.1
   Stage2 等待）。
2. **本仓库节点**：起 ≥门限 v1.1.0 实例，`POLICY_ENABLED=false`（或配 registry 放行）。
3. **#63 SDK**：取 owner ECDSA 签 → 传 `ownerAuth` 调各节点 `/signature/sign`
   → 聚合 → 套 #110 wire → 提交。
4. **SP**：授权 consumer + 确认节点 BLS 注册。→ 产出"真节点版"Sepolia 证据，与 #110 模拟版 tx 对照 → 标
   **DVT v1 RELEASED** 关闭 #42。

> 模拟版证明了**验证逻辑真**；真节点版证明**签名来源 + 节点闸门（Stage1/2）在真实链路里也成立**。二者合起来 =
> DVT 作为上线 service 的完整证据链。
