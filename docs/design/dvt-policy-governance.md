# DVT Policy Governance — 策略来源、生命周期与接口设计（提案）

> 状态: **提案，待 #42 协商定稿** · 关联: #40 (Fix2 Stage2) · 协调 hub:
> #42 涉及仓库: airaccount-contract #110 · SuperPaymaster #283 · aastar-sdk #63
> · 本仓库最后更新: 2026-06-14

## 0. 这份文档回答什么

#40 提出 DVT 节点要做"独立策略判断"，但没回答最关键的运营问题：
**限额/白名单这些规则从哪来？谁能改？增删改停的流程是什么？是用户接口还是服务接口？**
本文档补上这块，并约定与其他合约的一致性边界。

## 1. 核心安全约束（设计前提）

> 若"限额规则"是 owner 私钥可随时修改的，则 owner 钥匙被盗后，攻击者先把限额改成无限大再清空账户 ——
> DVT 第二因子归零。

因此：**策略变更本身必须比一笔普通交易更难被滥用。** 这是全部设计的命门。

## 2. 两层策略模型

最终决策 = **第 1 层 AND 第 2 层**，任一层拒绝即不共签。

### 第 1 层 — 账户策略（用户的）

- **内容**: **不是单一全局 USD 阈值**，而是**每账户可自定义的一组 scoped 规则**
  —— 针对「某合约 + 某资产/选择器 + 某数额」分别限额（见 §10
  scoped 策略模型）。外加 daily
  limit、velocity、哪些 op 需要 DVT（门限触发条件）。**限额直接以 owner 自定义的「合约 + 资产 + 数额」表达（数额即该资产原生单位），不经外部 USD 价格预言机（owner 决策：不复用 PaymasterV4
  oracle）。**
- **归属**: 账户 owner。
- **存储**: **链上 PolicyRegistry 合约**（CA 改不了）。`todaySpent`
  等累计状态**必须 keyed by sender**（见 §9 Decision 2
  — 否则验证期读取违反 ERC-7562）。
- **读取方**: DVT 节点 + 账户合约（`validateUserOp` 路径）读**同一份**。

### 第 2 层 — 节点策略（运营方的）

- **内容**: 全局上限、制裁/黑名单地址、合规规则。
- **归属**: DVT 节点运营方。
- **存储**: **节点本地**（owner 和 CA 都无法触及 —— 这是 DVT 独立性的硬保证）。
- **读取方**: 仅节点自身。即使账户与链上策略全被攻破，节点仍可凭本层拒签。
- **现状**: 本仓库 Stage 2 v1 (`PolicyService`, env 配置) 已实现本层。

## 3. 生命周期（CRUD + suspend/expire）— 第 1 层

不对称保护是精髓：**让自己更安全 = 即时；让自己更危险 = 延迟 + 多方同意。**

| 动作                      | 方向   | 保护强度                                             |
| ------------------------- | ------ | ---------------------------------------------------- |
| 收紧（调低限额/缩白名单） | 更安全 | 即时生效                                             |
| 放松（调高限额/加白名单） | 更暴露 | 时间锁延迟 N 小时（建议 24–48h）+ 可选 guardian 批准 |
| 关闭 DVT（删第二因子）    | 最危险 | 最强：时间锁 + guardian 多签                         |
| 冻结/暂停（panic）        | 更安全 | owner / guardian / 节点 任一方即时触发               |
| 失效（expire）            | 更安全 | 策略可带 TTL，到期自动回落保守默认                   |

合法用户若发现钥匙被盗，可在"放松"的时间锁窗口内通过 guardian 取消该变更。

## 4. 接口（用户接口 + 服务接口都要）

| 接口类型          | 载体                         | 谁用       | 做什么                                              |
| ----------------- | ---------------------------- | ---------- | --------------------------------------------------- |
| 用户接口          | aastar-sdk #63 / 钱包 UI     | 账户 owner | 管理第 1 层策略 → 写 PolicyRegistry（走受保护路径） |
| DVT 服务/运营接口 | SuperPaymaster ROLE_DVT #283 | 节点运营方 | 节点注册/质押/退出 + 管理第 2 层底线                |
| 节点内部接口      | 本仓库 `PolicyService`       | 节点自身   | 读链上第 1 层 + 本地第 2 层，做 AND 判断            |

## 5. 业务流程（高层）

1. 建户：设保守默认策略（如"> $1000 需 DVT 共签"）。
2. 日常小额：owner 单签即可，不触发 DVT。
3. 大额/高风险：账户合约按 PolicyRegistry 判定需要 DVT
   → 收集 ≥门限个节点 BLS 共签。
4. 每个节点独立按 §2 两层判断，仅在两层都通过时共签。
5. 用户调整策略：收紧即时；放松走时间锁（+guardian）。
6. 异常：owner/guardian/节点任一方可即时冻结。
7. 节点作恶（违策略 / 盲签）：按 ROLE_DVT slash（**不绑签名次数**）。

## 6. 跨仓库一致性要求（必须协商）

1. **airaccount-contract
   #110**: 账户合约与 DVT 节点读同一个 PolicyRegistry、同一套字段 schema。
2. **SuperPaymaster #283（最关键）**: 节点读的第 1 层策略源 **必须等于**
   slash 引用的策略源（同一个链上 registry），否则惩罚不公、无人敢当节点。
3. **aastar-sdk #63**: 提供 owner 管理策略的 API + 按最终格式组装签名。
4. **本仓库**: `PolicyService`
   增补"读链上 PolicyRegistry"作为第 1 层来源（当前仅本地第 2 层）。

## 7. 产品决策（owner 已定）

| 项         | 决策                                                                                                       |
| ---------- | ---------------------------------------------------------------------------------------------------------- |
| 时间锁时长 | **放松类变更 2 天延迟**；收紧/冻结即时                                                                     |
| guardian   | **复用 AirAccount 2-of-3 RecoveryService**（不另造）                                                       |
| 额度估值   | **自定义「合约 + 资产 + 数额」，数额即资产原生单位，不走外部 USD 价格预言机（不复用 PaymasterV4 oracle）** |
| DVT 开关   | **现在可选（opt-in）；服务稳定后转为必选（mandatory）**                                                    |

时间锁/guardian 在生命周期里的用途：时间锁给"放松/关 DVT"留 2 天反应窗口（防盗钥匙者秒开闸）；2-of-3
guardian 用于①窗口内紧急取消恶意变更 ②最危险动作（关闭 DVT）的额外门槛 ③私钥丢失找回。

## 8. 与已落地代码的关系

- 本仓库 Stage 2 v1 = 第 2 层（节点本地）。
- 第 1 层（链上 PolicyRegistry + 生命周期 + 用户接口）= 本文档提案，**待 §6/§7 协商定稿后**再实现
  `PolicyService` 的链上读取与 SDK/合约侧。

## 9. 已定稿决策（#42 协商结果）

### Decision 2 — 验证期强制（SuperPaymaster #283 lead，权威定稿）

选 **(a) staked-validation**，不选纯执行期：

- `todaySpent` 等累计状态**必须 keyed by sender**
  —— 否则验证期读取违反 ERC-7562（账户关联状态才可在验证期读）。这是**硬约束**。
- PolicyRegistry 架构：① sender-keyed 累计状态 ② 链上 +
  governance-gated（CA 改不了，= C2）③ **验证期 pre-check + postOp 权威 debit +
  one-shot block**（belt-and-suspenders）。
- 复用 SP 现有 H-1 credit-ceiling 模式（验证期强制上限，已生产）：SP 是 staked
  entity（`addStake`）享 ERC-7562 宽限。
- 不选纯执行期：validate→execute 之间可 drain + 同 block 重复，正是 H-1 要堵的洞。
- **C1 accepted (with caveat)** / **C2 accepted (unconditional)**。
- ⏳ 待 airaccount-contract #110 确认：账户侧能消费"验证期 staked
  PolicyRegistry 读"。

### C1 调用约定（#1 签名绑定，SP 提）

ROLE_DVT 的 BLS verifier 是 **message-agnostic**；绑定 `userOpHash` 取决于
**co-sign entry point 传
`expectedMessageHash = userOpHash`**。现有 callers（slash/reputation）传的是 proposal
hash，故 DVT co-sign 路径必须用独立 entry point 传 `userOpHash`。→ 待 **#110**
在账户侧 validate 路径确认按此调用（这也是闭合 #45 重放洞的机制）。

## 10. Scoped 策略模型（每账户自定义「合约 + 资产 + 数额」）

阈值不是单一全局 USD 数，而是**每账户一组 scoped 规则**，例如：

- 「对合约 X、资产 Y，单笔上限 Z」
- 「对合约 X、选择器 `transfer`，日累计上限 / 速率上限」
- 不同账户可对不同资产/合约设不同额度。

**AirAccount 侧已有可复用原语**（grant-session，已确认存在）：

| 字段                                  | 用途               |
| ------------------------------------- | ------------------ |
| `contract_scope: [u8;20]`             | 限定到某合约       |
| `selector_scope: [u8;4]`              | 限定到某函数选择器 |
| `velocity_limit` / `velocity_window`  | 速率/窗口限额      |
| `call_targets` / `selector_allowlist` | 目标/选择器白名单  |

→
PolicyRegistry 的 schema 应**对齐/复用 grant-session 的 scoping 字段模型**，避免重造。→
⏳ 待 **airaccount-contract #110**
确认：每账户「合约 + 资产 + 数额」自定义限额的**实现进展**，以及 PolicyRegistry 能否直接复用 grant-session 原语。

## 11. 部署地址 + 启用（layer-1）

SuperPaymaster 已将 IPolicyRegistry 部署上链（v5.4，PR SuperPaymaster#285）。

| 网络    | PolicyRegistry 地址                                                               |
| ------- | --------------------------------------------------------------------------------- |
| Sepolia | `0x8c2488d46d5447418558c38AA6441720df656094` (v5.4.0-beta.1-redeploy, 2026-06-16) |

**启用 layer-1**：把上面地址填到节点 env `POLICY_REGISTRY_ADDRESS`（+
`POLICY_ENABLED=true`）即可，无需改码。 `POLICY_ETH_SENTINEL` 默认
`0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE`（与合约一致）。

**端到端实测（已验证）**：对 Sepolia 上述地址调
`checkPolicy(sender,target,ETH哨兵,1000,0x00000000)` → 返回
`decision=0 (ALLOW)`、`remainingDaily=2^256-1`，即未开通账户的 opt-in
default-ALLOW，ABI/接线与部署合约逐字段一致。
