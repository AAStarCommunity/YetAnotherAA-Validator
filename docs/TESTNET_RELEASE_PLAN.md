# 测试网发布方案 / Testnet Release Plan

> **状态**：草案，待 review。最后更新：2026-06-20。 **目标版本**：建议
> **v1.5.0**（minor 里程碑 = "首个测试网正式发布 / testnet-ready"）。
> **关联**：[`HOW_TO_INTEGRATION.md`](./HOW_TO_INTEGRATION.md) §2 在线版 ·
> [`DVT_VALUE.md`](./DVT_VALUE.md) ·
> [`design/dvt-e2e-and-production.md`](./design/dvt-e2e-and-production.md) ·
> [`RELEASING.md`](../RELEASING.md) · `scripts/check-deps.mjs` ·
> `scripts/e2e/`。

---

## 0. 目标与"发布完成"的定义

把 DVT 从"本地调试版"推进到
**Sepolia 测试网正式发布**。一个发布只有当**全部**满足才算 **RELEASED**：

1. ✅ **依赖一致性门禁通过** —— `check-deps` 全绿（pinned
   == 上游最新且无源码/ABI/地址漂移）
2. ✅ **测试网多节点部署 + 链上注册完成**
3. ✅ **全链路 E2E 绿** ——
   SDK→协调器→节点群→聚合→Bundler→EntryPoint→链上验→执行，端到端可复现
4. ✅ **Codex 全链路挑战通过**
   —— 合理性/规范/安全/效率对抗审查，findings 已解决或明确 defer
5. ✅ **GitHub Release 打标** —— `vX.Y.0` tag + release notes（含依赖 pin 表 +
   E2E 报告 + Codex 结论）

> 顺序是**门禁链**：任一环不过，不进下一环；第 4 步（Codex 挑战）是发布前的最后一道闸。

---

## 1. 上游 / 下游依赖管理（确定最新 + 一致 + 变动应对）

### 1.1 依赖清单（本节点绑定的上下游，来源 `scripts/check-deps.mjs`）

| 角色     | 仓库                | 绑定物                                          | 当前 pin                         | 校验维度               |
| -------- | ------------------- | ----------------------------------------------- | -------------------------------- | ---------------------- |
| **上游** | SuperPaymaster      | `PolicyRegistry.checkPolicy`（layer-1 策略）    | `v5.4.0-beta.1` · `0x8c2488…`    | 地址 + 源码 diff + ABI |
| **下游** | airaccount-contract | `AAStarBLSAlgorithm.validate`（链上验聚合签名） | `v0.19.0-beta.2` · `0x68c381Ad…` | 地址 + 源码 diff + ABI |
| **上游** | AirAccount (KMS)    | owner secp256k1 `ownerAuth`（Stage-1 验签）     | TA `0.5.0`                       | TA/签名方案版本守卫    |
| 规范     | EntryPoint v0.7     | `getUserOpHash`                                 | `0x0000…71727De2…`               | 固定规范地址           |

### 1.2 "如何确定是最新且与我一致的版本"

`check-deps` **已经**在做（发布前必跑、必须全绿）：

- **是否最新**：对每个 dep 拉上游 `release view` / `tags`，比对 `pinned` vs
  `latest release`，标 `✓ / ⚠️ MOVED / ~ transient`；并扫 `-redeploy` 变体 tag。
- **是否一致**：① 地址层——从上游
  `deployments/config.sepolia.json`（权威）解析 canonical 地址，对比 pin，并
  `getCode` 确认链上有代码；② 源码层——diff 绑定的 `.sol`
  文件（baselineRef↔HEAD），断言被调 ABI 签名仍在；③ KMS——守 TA 版本（=
  ownerAuth 签名方案）。

→ **发布门禁规则**：`check-deps` 退出码非零（任何 drift）=
**禁止发布**，先走 §1.3。

### 1.3 上游变动应对（Drift Playbook）

| 漂移类型                           | 影响                    | 处理                                                                                                 |
| ---------------------------------- | ----------------------- | ---------------------------------------------------------------------------------------------------- |
| **地址漂移**（redeploy，新地址）   | 节点连旧合约 / 验签失败 | 评估 → re-pin 地址（PR review）→ 若 validator 换地址则**节点公钥需 re-register** 到新合约（见 §2.3） |
| **源码/ABI 漂移**（wire/接口变了） | 编解码/验签不兼容       | fetch diff，判断是否动 ABI/wire/DST/数据结构 → 改代码 → 重测 → re-pin baselineRef                    |
| **KMS TA 版本漂移**                | ownerAuth 签名方案变    | 检查 EIP-191/C1 绑定是否变 → 适配 Stage-1 验签                                                       |
| **仅版本号动、源码相同**           | 无                      | re-pin 版本号即可                                                                                    |

> 原则：**drift 未解决 + 未重新验证（单测 + 真节点 E2E
> `validate=0`）前，绝不发布。**（与 `check-deps` skill 的既有约定一致。）

### 1.4 自动发现 + 同步检查（要我落地的脚本）

1. **`check-deps --json`**（增强现有脚本）：结构化输出，供门禁/CI 消费（当前只有人类可读输出）。
2. **`scripts/release-preflight.mjs`**（新）：发布门禁聚合器——跑
   `check-deps` + 校验 `package.json` 版本号 + 校验 testnet
   env 完整性（RPC/validator/entrypoint/policy 地址齐备且与 pin 一致）+
   `npm run build && test`。**任一不过即 fail，阻断发布**。
3. **`.github/workflows/deps-watch.yml`**（新）：**定时**（如每日）跑
   `check-deps`，发现 drift
   **自动开 issue**（标题含 dep + 漂移类型）→ 这就是"自动发现上游变动"。
4. **统一 env 源**：消除 `realnode-e2e.mjs` 用 `V018` 而 pin 是 `V019`
   的不一致（见 §2.2），单一 `.env.sepolia` key 为准。

---

## 2. 链上合约与配置（Sepolia）

### 2.1 权威地址（以 `check-deps` 为准，发布前重新核对）

| 用途                                | 地址                                         | 版本                               |
| ----------------------------------- | -------------------------------------------- | ---------------------------------- |
| BLS 验证器（下游消费聚合签名）      | `0x68c381Ad3A2e3380F22840008027E9Ec2783F43A` | airaccount-contract v0.19.0-beta.2 |
| PolicyRegistry（上游 layer-1 策略） | `0x8c2488d46d5447418558c38AA6441720df656094` | SuperPaymaster v5.4.0-beta.1       |
| EntryPoint v0.7                     | `0x0000000071727De22E5E9d8BAf0edAc6f37da032` | 规范                               |

### 2.2 ⚠️ 必须先消除的不一致

- `realnode-e2e.mjs` / `.e2e/common.env` 历史用
  **V018**（`AIRACCOUNT_V018_BLS_ALGORITHM`），但 canonical 最新是
  **V019**。本轮已把集群 `common.env`
  切到 V019、node3 注册到 V019；**发布前要把 E2E 脚本与所有 env 统一到 V019（canonical）**，否则 validate 会对错合约。

### 2.3 节点链上注册流程

- 每个节点用 `registerPublicKey(bytes32 nodeId, bytes publicKey)` 注册到
  **V019**（`onlyOwner`；publicKey 为 **128-byte EIP-2537 G1**
  编码，非 48-byte 压缩——见本轮 node3 注册经验）。
- 发布需登记的节点集合（建议 ≥3 独立实例）全部
  `isRegistered=true`，`getRegisteredNodeCount` 匹配。

### 2.4 其他疑虑（清单）

- 🔴
  **ECDSA 回退风险**：参考账户 V6/V7/V8（`AAStarAccountBase`）有 owner-ECDSA 独签回退，owner 私钥持有者可绕过 DVT（见
  `DVT_VALUE.md` §4/§7.5）。**testnet
  E2E 必须明确用"强制 BLS 路径"的账户，或在 release notes 标注此限制**。
- 协调器 /
  Bundler：testnet 上由谁运行？（SuperRelay？公共 bundler？需确定，见 §3）
- viem 迁移（#88）：是否在此版本前完成？建议**之后**单独里程碑，不阻塞 testnet 发布。

---

## 3. 发布后的上下游（你的上下游是谁）

```
        ┌─────────────────── 上游（驱动 / 提供输入）───────────────────┐
        │  dApp / aastar-sdk  ──构造 PackedUserOperation──┐            │
        │  账户 owner @ KMS  ──ownerAuth(EIP-191 secp256k1)┤            │
        │  协调器(coordinator) ──分发 {userOp, ownerAuth}──┘            │
        └───────────────────────────┬──────────────────────────────────┘
                                     ▼  POST /signature/{sign,aggregate}
                            ┌──────────────────┐
                            │  DVT 节点群(≥3)   │  只读: EntryPoint.getUserOpHash
                            │ (本仓库 / testnet)│        account.owner()
                            └────────┬─────────┘        PolicyRegistry.checkPolicy(开启时)
                                     ▼  聚合签名(EIP-2537)
        ┌─────────────────── 下游（消费 / 最终验证）──────────────────┐
        │  Bundler ──eth_sendUserOperation──► EntryPoint v0.7           │
        │  EntryPoint ──► account.validateUserOp ──► AAStarBLSAlgorithm │
        │                (EIP-2537 验聚合签名) ──► 执行 ──► 链上确认     │
        └──────────────────────────────────────────────────────────────┘
```

- **上游**：aastar-sdk（构造 userOp）、KMS（owner 私钥出 ownerAuth）、协调器（收集/聚合）。
- **下游**：PolicyRegistry（读策略）、AAStarBLSAlgorithm（链上验聚合）、EntryPoint +
  Bundler（提交执行）。

---

## 4. 全链路 E2E 测试方案

### 4.1 分层（L0→L3，逐层加真实度）

| 层                    | 范围                                                                               | 现状                                 | 验证点                               |
| --------------------- | ---------------------------------------------------------------------------------- | ------------------------------------ | ------------------------------------ |
| **L0** 单节点         | 各服务单测（gate/policy/keeper…）                                                  | ✅ 76 测试                           | fail-closed 403、策略门、keeper 护栏 |
| **L1** 多节点本地     | 3 节点本地共签 + 聚合 + 链下验                                                     | ✅ `selftest.mjs`                    | 共签一致、聚合正确                   |
| **L2** 真节点 + 链上  | 真节点共签 → 聚合 → **链上 `validate=0`**                                          | ✅ `realnode-e2e.mjs`（需统一 V019） | 链上 AAStarBLSAlgorithm 接受聚合签名 |
| **L3** 全链路 testnet | SDK→协调器→节点群→聚合→**Bundler→EntryPoint→account.validateUserOp→执行→链上确认** | 🚧 **新增**                          | 一笔真实 UserOp 端到端上链成功       |

### 4.2 上下游契约测试（每一段都要对拍）

- **上游契约**：KMS 出的 `ownerAuth` 经
  `ethers.verifyMessage(getBytes(userOpHash), sig)==owner`（EIP-191）；SDK 的
  `PackedUserOperation` 字段/编码与节点 `getUserOpHash` 一致。
- **下游契约**：`PolicyRegistry.checkPolicy`
  返回值语义、`AAStarBLSAlgorithm.validate` 返回 0、`EntryPoint.getUserOpHash`
  与节点自算一致。
- 这些正是 `check-deps`
  源码/ABI 守的——E2E 是**运行时**复核，check-deps 是**静态**复核，二者互补。

### 4.3 负路径 / 安全测试（必跑）

- fail-closed：坏 ownerAuth→403、缺字段→400/403、跨账户 hash 替换被拒。
- 策略门（开启时）：超额/陌生收款人/registry REJECT → 拒签。
- **ECDSA 回退**：在参考账户上验证 owner 独签能绕过 DVT（记录为已知限制），并在"强制 BLS 账户"上验证不能绕过。
- stale 合约：连错版本 validator → validate=1（确认 env 一致性防呆）。

### 4.4 自动化 runner（要我落地）

- **`scripts/e2e/testnet-e2e.mjs`**（新）：一键串 L1→L2→L3，输出结构化报告（每段 pass/fail +
  txHash + 耗时），可贴进 release notes。复用现有 `realnode-e2e.mjs`
  的链上验逻辑，向后接 Bundler→EntryPoint。

---

## 5. Codex 全链路挑战（发布前最后一道闸）

E2E 全绿后，对**整条链路**做 Codex 对抗式审查（不是逐 PR，是端到端）：

- **合理性**：架构/数据流是否自洽；上下游契约假设是否成立。
- **规范**：ERC-4337 v0.7 合规、EIP-191/EIP-2537 编码、错误码（403
  fail-closed）一致。
- **安全**：owner-key 泄露面（ECDSA 回退）、跨账户预言机、聚合阈值（k-of-n 强制点）、env 一致性防呆、密钥处理。
- **效率**：链上 gas、链下并发、RPC 调用、keeper 冗余去重。

→ **门禁**：Codex findings 逐条处理，每条
**fix 或明确 defer（带理由）**；未决的 blocking 项不发布。挑战通过 =
release 真正完成的前置。

---

## 6. 发布与 GitHub Release

### 6.1 版本

- 建议 **v1.5.0**（minor）：语义 =
  "首个测试网正式发布"。理由：相对 v1.4.0（本地特性集）这是面向 testnet 的新能力里程碑，非纯补丁。
- （备选：`v1.4.1-testnet`
  预发布 tag——若想强调"测试网预览"。建议正式 minor 更清晰。）

### 6.2 发布流程（门禁链，按 `RELEASING.md` 扩展）

```
1. release-preflight 绿（check-deps 无 drift + 版本一致 + env 校验 + build/test）
2. 部署 ≥3 节点到 testnet + 链上注册（V019）
3. testnet-e2e 全链路绿（L1→L3）+ 负路径/安全用例绿
4. Codex 全链路挑战通过（findings 已闭环）
5. 版本 bump → PR → 独立 review → 合并 master（勿自合）
6. tag vX.Y.0 + gh release create（notes 含：依赖 pin 表 + E2E 报告 + Codex 结论 + 已知限制如 ECDSA 回退）
7. 在 #42（DVT program）登记本仓库 testnet 发布成功
```

### 6.3 Release notes 必含

- 依赖 pin 表（§1.1，发布时刻的版本/地址 + check-deps 绿截图/输出）
- testnet 合约地址（§2.1）+ 已注册节点集合
- E2E 报告（L1→L3，含 txHash）
- Codex 挑战结论
- **已知限制**（ECDSA 回退等）

---

## 7. 要我落地的脚本 / 改动清单（review 通过后实施）

| 项                                 | 类型 | 作用                                                      |
| ---------------------------------- | ---- | --------------------------------------------------------- |
| `check-deps --json`                | 增强 | 结构化输出供门禁/CI                                       |
| `scripts/release-preflight.mjs`    | 新增 | 发布门禁聚合（deps + 版本 + env + build/test）            |
| `scripts/e2e/testnet-e2e.mjs`      | 新增 | L1→L3 全链路 runner + 结构化报告                          |
| `.github/workflows/deps-watch.yml` | 新增 | 定时 check-deps，drift 自动开 issue（自动发现上游变动）   |
| 统一 V019 env                      | 修复 | 消除 V018/V019 不一致（realnode-e2e + common.env + 文档） |
| `RELEASING.md` 扩展                | 文档 | 增加 testnet 发布门禁链（§6.2）                           |

---

## 8. 风险 / 未决（请 review 时拍板）

1. **协调器 / Bundler 谁来跑 testnet**？（SuperRelay / 公共 bundler / 自建）——L3
   E2E 依赖它。
2. **ECDSA 回退**：testnet 用强制 BLS 账户，还是接受回退并在 notes 标注限制？
3. **版本号**：v1.5.0 vs v1.4.1-testnet？
4. **viem 迁移（#88）** 排在 testnet 发布之前还是之后？（建议之后。）
5. **节点托管**：3 个独立实例放哪（同机多端口 vs 多机 vs 多运营方）？testnet 阶段可单机多端口，但要在 notes 说明"非真正去中心化"。
