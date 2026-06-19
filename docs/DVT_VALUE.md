# DVT Value — DVT 节点的核心价值与策略门深度分析

> 本文档说明：这个 BLS DVT 签名节点在 ERC-4337 交易生命周期里扮演什么角色、
> **为什么在已有链上验签的前提下仍然需要它**、它与合约如何交互，以及它最核心的资产——**独立策略门（PolicyRegistry
> / Policy
> Gate）**——能设哪些策略、能拦哪些没有 DVT 就拦不住的攻击、又拦不住哪些（局限与风险）、参数如何调整与生效、以及如何保证策略被"独立、不受干扰"地执行。
>
> 代码锚点（便于核对）：
>
> - 编排：`src/modules/signature/signature.service.ts` `signMessage`
> - 身份门：`src/modules/bls/bls.service.ts` `authorizeAndDeriveHash`
> - 策略门：`src/modules/policy/policy.service.ts` `evaluate` / `decodeCalls` /
>   `normalizeForPolicy`
> - 链上读：`src/modules/blockchain/blockchain.service.ts` `checkPolicy` /
>   `getUserOpHash` / `getAccountOwner`
> - 配置：`src/config/configuration.ts`
> - 请求体：`src/dto/sign.dto.ts` `SignMessageDto`

---

## 1. 一句话定位

**链上验签回答"签名对不对"；DVT 回答"这笔交易该不该签"。**

后者靠 PolicyRegistry 做"分额度、分规则"的独立策略门，在签名**之前**
fail-closed 地拒掉越界操作。这是一道**偷了 owner 私钥也跨不过的第二关**，也正是 DVT 区别于"任何节点都能做的 owner 验签"的核心价值。

---

## 📋 人话速览：有 DVT vs 没 DVT（建议先看这张表）

> 一句话：**没有 DVT，私钥就是一切——谁拿到私钥就能把钱全转走；有了 DVT，就算私钥被偷，钱也未必转得出去。**
> 下表用大白话说清 DVT 加了哪些"保险"、什么时候救你、怎么设置才生效。

| 这道"保险"是什么           | 没有 DVT 会怎样                | 有了 DVT 后                                                     | 什么情况下救你                           | 怎么设置才生效                                                 |
| -------------------------- | ------------------------------ | --------------------------------------------------------------- | ---------------------------------------- | -------------------------------------------------------------- |
| **每种币的"单笔上限"**     | 私钥能签，就能一次转走任意金额 | 给每种币设"一笔最多转多少"，超了直接拒签                        | 私钥被盗，想一次性大额转走               | 在账户的链上策略里，给每个币种（如 USDC、ETH）填一个"单笔上限" |
| **每种币的"每日上限"**     | 没有，能转多少转多少           | 每种币"每天最多花多少"，超了拒签                                | 被盗后分很多小笔"蚂蚁搬家"               | 在账户的链上策略里，给每个币种填一个"每日额度"                 |
| **只能转给信任的地址**     | 能转给任何陌生地址             | 只放行转给你事先信任的地址，陌生地址一律拒签                    | 被盗后想把钱转去攻击者的新地址           | 把你信任的收款地址加进"白名单"（节点本地或账户链上策略都能配） |
| **大额要你本人再点头**     | 没有，签了就走                 | 超过设定金额的操作先挂起，等你在手机/邮件等独立渠道点"同意"才签 | 即使签名有效，也要真人本人确认一次       | 打开"带外确认"，设一个触发金额 + 留下你的联系方式              |
| **大额必须多方共同签**     | 一个私钥说了算                 | 超过设定额度的操作，必须多个独立节点都同意才放行                | 单个私钥/单个节点被攻破                  | 在账户的链上策略里设"超过 X 金额就需要多方共签"                |
| **被盗时一键冻结**         | 只能眼睁睁看钱被转走           | 守护方（你的 2/3 恢复服务）可立即冻结账户，之后所有转账都被拒   | 发现被盗的第一时间止血                   | 在账户链上策略里设好"守护方"，出事时由它触发冻结               |
| **放宽规则有"冷静期"**     | 无规则可言                     | 把规则**调严**立刻生效；把规则**放宽**要等 2 天才生效           | 攻击者夺取了管理权，想偷偷放宽限额来盗刷 | 默认就有（由链上时间锁保障），无需你额外操作                   |
| **节点自己核账，不被忽悠** | 后端/调用方说是多少就是多少    | 节点自己上链核对金额、收款人、账户主人，不信调用方的描述        | 有人伪造请求/篡改金额想骗签              | 默认就有，无需设置                                             |
| **日常小额照常用**         | ——                             | 在以上限额、白名单之内的正常操作，照常秒签，不打扰              | 普通日常转账                             | 把日常额度/常用地址设进策略即可                                |

> ⚠️
> **重大前提（务必先读）**：上表中"私钥被盗也救得了你"的那几行，**只有当账户合约强制走 DVT/BLS 路径、且不允许 owner 单签时才成立**。经核对，**本仓库的参考账户 V6/V7/V8（`AAStarAccountBase`）有一个无条件的 owner-ECDSA 回退**——一条普通 owner 签名即可通过，完全绕过 DVT。也就是说：**在这些参考账户上，DVT 防的是"未授权调用方"和"DVT 路径上的策略合规"，但并不能防 owner 私钥泄露**（持私钥者总能用 ECDSA 独签）。要让上表的"防私钥泄露" 真正成立，需要一个**去掉 ECDSA 回退、强制 BLS 路径的账户变体**（不在本仓库）。详见下方第 5 条追溯与 §4 修正。

**设置分两个地方（都用大白话理解）：**

- **节点这边的"总闸"**（运营节点的人来设）：总开关、原生 ETH 的单笔上限、地址白名单。改了要重启节点。**账户主人无法用一个签名绕过它**。
- **账户这边的"链上策略"**（每个账户各自设，写在链上）：每种币的单笔/每日上限、超额触发多方共签、白名单、守护方、冻结。改严立即生效，放宽要等 2 天。

> 想看每条对应的技术参数（合约字段、env 配置项），见下文第 7 节的深度分析。

### 这张表怎么来的：逐条代码追溯（我读了哪些 / 没读哪些）

下面给出每条"保险"的**判断依据（核心代码 file:line）**、**核心路径**、以及它**实现在节点本仓库还是上游合约**。`路径`
一律从 `SignatureService.signMessage` 起。

1. **每种币的"单笔上限"** — 上游合约 (Layer1)
   - 依据：`PolicyRegistry.sol` `checkPolicy` 的
     `if (amount > ap.perTxHardCap) return REJECT`（ASSET 维度）。
   - 节点侧：`policy.service.ts` `normalizeForPolicy` 把每个 call 解成
     `(asset, amount)`，`evaluate` 调
     `blockchainService.checkPolicy(sender, contract, asset, amount, selector)`（`blockchain.service.ts`
     `checkPolicy`）。
   - 路径：`signMessage → policyService.evaluate → normalizeForPolicy → blockchain.checkPolicy → 链上 ap.perTxHardCap`。

2. **每种币的"每日上限"** — 上游合约 (Layer1)
   - 依据：`PolicyRegistry.sol` `checkPolicy` 的 `dailyLimit + windowSeconds`
     窗口判断（`projected > ap.dailyLimit → REJECT`，返回
     `remainingDaily`）；写侧
     `recordSpend`（`onlyAuthorizedConsumer`）推进计数。
   - 路径：同上；额度计数由授权 consumer（DVT/paymaster）回写。

3. **只能转给信任的地址** — 双层
   - 节点 Layer2：`policy.service.ts` `evaluate` 里对 `recipientAllowlist` 检查
     **被调合约 + 解出的真实收款人两者**；配置
     `POLICY_RECIPIENT_ALLOWLIST`（`configuration.ts`）。
   - 合约 Layer1：`PolicyRegistry.sol` `checkPolicy` 的
     `ContractScope.allowed` + `_selectorAllowed[sender][target][selector]`。

4. **大额要你本人再点头** — 节点本仓库
   - 依据：`confirmation.service.ts` `gate()`；触发条件
     `nativeValue(userOp) >= thresholdWei`；配置
     `CONFIRM_ENABLED/THRESHOLD_WEI/TTL_MS`。
   - 路径：`signMessage → confirmationService.gate → not_required / pending / undeliverable / confirmed`。
   - ⚠️ **诚实标注**：`nativeValue` **只解 `execute()` 的原生 ETH value**（非
     `execute` / 代币转账 → 返回 0
     → 不触发此门）。即**这道确认门只按原生 ETH 金额触发**；代币大额由策略门的 per-token 限额（第 1/2 条）来管，不走这道确认。

5. **大额必须多方共同签** — ⚠️ **已核到底，结论需大幅修正（见下）**
   - 标记依据：`PolicyRegistry.sol` `checkPolicy` 的 `dvtTriggerAmount` /
     `ContractScope.requireDVTAlways` 会返回 `REQUIRE_DVT`
     —— 但这只是给**链下 DVT 层**的信号，**不被任何链上合约消费**。
   - 链上验签：`contracts/src/AAStarValidator.sol` `validateAggregateSignature`
     / `verifyAggregateSignature` 只要求
     `nodeIds.length > 0` + 所有 nodeId 已注册 +
     pairing 通过（`AAStarValidator.sol:100,121,194-196`）。**没有任何 k-of-n 最小签名数阈值**——单个已注册节点（nodeIds 长度=1）即可通过。
   - 账户侧：`AAStarAccountBase._validateSignatureBase` /
     `_parseAndValidateAAStarSignature`（`AAStarAccountBase.sol:67,108`，V6/V7/V8 都走这套）。BLS 路径要求
     **owner ECDSA 验 userOpHash + owner ECDSA 验 messagePoint +
     BLS 聚合验 messagePoint**（三重校验）。账户对 nodeIds 仅限
     `1..100`（`:164`），同样**无最小节点数**。
   - 🔴 **重大发现（推翻原结论）**：`_validateSignatureBase`
     有一个**无条件的 ECDSA 回退**（`AAStarAccountBase.sol:82-88`）——当签名不是合法 BLS 格式（解析 revert）时，`catch`
     分支直接退回 **纯 owner ECDSA 校验**：`hash.recover(signature) == signer`
     即放行。一条普通 65 字节 owner ECDSA 签名会让 `_parseAAStarSignature` 在
     `require(nodeIdsLength<=100)` 处 revert → 命中回退 →
     **仅凭 owner 私钥即通过，完全不需要任何 DVT/BLS**。
   - **因此**：在本仓库的
     **V6/V7/V8 参考账户**上，owner-ECDSA 独签是**一等公民、永远有效**，DVT
     BLS 只是**可选的替代路径**。**持有 owner 私钥者可以绕过 DVT 做任何事**
     —— 这些账户上
     **DVT 并不能防 owner 私钥泄露**（见下方 §4 的修正与表格上方的 ⚠️ 前提）。

6. **被盗时一键冻结** — 上游合约 (Layer1)
   - 依据：`PolicyRegistry.sol` `checkPolicy` 首条
     `if (_frozen[sender]) return REJECT`（最高优先级）；`freezeSender`（`onlyGuardianOrTimelock`，即时）。

7. **放宽规则有"冷静期"** — 上游合约治理
   - 依据：放宽类 `setAssetPolicy / setContractScope / unfreezeSender` 是
     `onlyTimelock`（OZ TimelockController，`minDelay = 2 days`）；收紧/冻结类
     `tightenAssetPolicy / tightenContractScope / freezeSender` 是
     `onlyGuardianOrTimelock`（即时）；`timelock` 地址 `immutable`。

8. **节点自己核账，不被忽悠** — 节点本仓库
   - 依据：`bls.service.ts` `authorizeAndDeriveHash` 内：`getUserOpHash`
     自算哈希、`getAccountOwner`
     自读 owner、`ethers.verifyMessage(getBytes(userOpHash), ownerAuth)`
     自验；`policy.service.ts` `decodeCalls / normalizeForPolicy`
     自解金额与收款人。
   - 路径：`signMessage → authorizeAndDeriveHash`（一切结论由节点从链上 /
     calldata 重算）。

9. **日常小额照常用** — 双层
   - 节点：`policy.service.ts` `evaluate` 在 `!enabled` 时直接
     `{allowed: true}`。
   - 合约：`PolicyRegistry.sol` `checkPolicy` 的
     **opt-in 默认 ALLOW**——未配置的维度不约束，`remainingDaily = type(uint256).max`。

**覆盖说明（我实际读了什么）：**

- ✅ 完整读过（节点本仓库）：`signature.service.ts`(`signMessage`)、`bls.service.ts`(`authorizeAndDeriveHash`)、`policy.service.ts`(`evaluate`
  / `decodeCalls` / `normalizeForPolicy`
  全部分支含 transfer/transferFrom/approve/native/generic / 常量 /
  allowlist)、`blockchain.service.ts`(`checkPolicy` / `getUserOpHash` /
  `getAccountOwner`)、`confirmation.service.ts`(`gate` / `nativeValue` /
  `confirm`)、`configuration.ts`(相关键)、`sign.dto.ts`。
- ✅ 读过（上游合约）：`PolicyRegistry.sol` 的 `checkPolicy`
  全体 + 治理 modifier +
  `recordSpend / setAssetPolicy / tighten* / freezeSender`
  签名。`AssetPolicy / ContractScope` 字段由"使用处 +
  setter 入参"确认；**未单独打开 `IPolicyRegistry` 接口看 struct 定义体**。
- ✅
  **已补读（关闭第 5 条缺口）**：`contracts/src/AAStarValidator.sol`（`validateAggregateSignature`
  / `_validateBLSSignature` / `_getPublicKeysByNodes`：仅
  `nodeIds.length>0` + 已注册 +
  pairing，无阈值）；`contracts/src/AAStarAccountBase.sol`（`_validateSignatureBase`
  / `_parseAndValidateAAStarSignature` / `_parseAAStarSignature`：三重校验 +
  **无条件 ECDSA 回退**）；`AAStarAccountV7.sol`（`validateUserOp → _validateSignatureBase`，V6/V8 同构）。
- ⚠️ **仍未读**：`notification.service.ts`
  `notifyLargeSpend`（不在表内，fire-and-forget 通知）。

> 一句话：第 1–4、6–9 条都落到了具体代码 file:line；**第 5 条已核到底，但结论被推翻**——这些参考账户既无最小节点数阈值，又有 owner-ECDSA 回退，所以"大额必须多方共签 /
> DVT 防私钥泄露"在 V6/V7/V8 上**当前不成立**，要靠"去掉 ECDSA 回退、强制 BLS 路径的账户变体"才能实现。

---

## 2. 在交易生命周期中的角色

```
1. dApp/SDK 构造 PackedUserOperation（sender = 智能账户）
2. 账户 owner 用 ECDSA 对 userOpHash 签名 → ownerAuth
3. 协调器把【完整 userOp + ownerAuth】发给 N 个 DVT 节点  ──► POST /signature/sign
        每个节点跑下面的「四道门」，通过才产出 BLS 签名
4. 协调器收齐各节点 BLS 签名 ──► POST /signature/aggregate（任意节点都能做）
        → 聚合成 1 个 BLS 签名 + 聚合公钥，编码成 EIP-2537 链上格式
5. 聚合签名写进 UserOp 的签名字段
6. Bundler 把 UserOp 提交给 EntryPoint
7. EntryPoint → account.validateUserOp → AAStarValidator（EIP-2537 验 BLS 聚合）
8. 验证通过 → 交易执行
```

DVT 的职责边界是
**第 3~4 步**：在 owner 授权下，产出一个能被链上 BLS 验证器接受的聚合签名——**并且有权拒绝**。

---

## 3. 完整调用链：四道门（`SignatureService.signMessage`）

`POST /signature/sign` 收到 `{ userOp, ownerAuth }`，按序过四道门。
**任何一道不过 → 403，绝不返回"无签名的 200"（统一 fail-closed）。**

```
 ① 身份门 (Stage1)  blsService.authorizeAndDeriveHash(userOp, ownerAuth)
     · 形状校验（sender 合法、必填字段齐）                    失败 → 403
     · userOpHash = blockchain.getUserOpHash(userOp)          [链上 EntryPoint，节点自算]
     · owner      = blockchain.getAccountOwner(sender)        [链上 account.owner()]
     · verifyMessage(getBytes(userOpHash), ownerAuth) == owner ?  否 → 403
        → 只回答"是不是 owner 授权的"。任何节点都能做，是 authentication，无差异化价值。

 ② 策略门 (Stage2)  policyService.evaluate(userOp)   ← DVT 真正的核心价值
     · decodeCalls(callData): execute / executeBatch → [{to, value, func, selector}]
     · normalizeForPolicy: 解 ERC20 transfer/transferFrom → 真实 (asset, amount, recipient)
     · Layer2 本地运营底线（owner / CA 不可覆盖）:
          POLICY_PER_TX_MAX_WEI 单笔原生上限
          POLICY_RECIPIENT_ALLOWLIST 白名单（合约地址 + 真实收款人都要在内）
     · Layer1 链上 per-account 注册器（配了才查，并发查，revert → 拒）:
          checkPolicy(sender, target, asset, amount, selector) → (decision, remainingDaily)
          fail-closed：只有 decision ∈ {ALLOW=0, REQUIRE_DVT=1} 放行；REJECT / 未知一律拒
     · 任意环节不可解码 → fail-closed 拒
        不通过 → 403 "operation rejected by node policy"

 ③ 带外确认门  confirmationService.gate(userOp, userOpHash)   高额操作
     · undeliverable → 403   · pending → 返回 pending_confirmation（挂起，等用户独立通道批准）

 ④ 签名      blsService.signDerivedHash(userOpHash, node)   ← 对【同一个已授权 hash】做 BLS 签名
 ⑤ 通知      notificationService.notifyLargeSpend(...)      fire-and-forget，绝不阻塞签名
```

**关键区分**：① 是"验 owner 签名"（任何节点都能做）；② 才是 DVT 的核心——按额度/规则分层的策略门。`POLICY_PER_TX_MAX_WEI`
是"额度大于多少就拒/走校验"的本地阈值；链上 `checkPolicy` 的 `REQUIRE_DVT=1`
是注册器层面标记"这一档必须由 DVT 协同 + 策略校验才放行"， `remainingDaily`
是每日额度。

---

## 4. 为什么需要 DVT？既然链上已经验签了

链上验签（`AAStarValidator` +
EntryPoint）只能回答：**"这是不是登记过的密钥签出的有效签名？"** 它**不能**回答
**"这笔交易该不该发生？"**，原因有三：

1. **它只信任"谁持有密钥"**。owner 私钥一旦被盗，攻击者就是"合法签名者"，链上验签照常通过 → 资金清空，无人能拦。
2. **复杂策略全塞链上不现实**：每日额度、收款白名单、带外确认……上链既贵（gas）又僵（改规则要发交易），而且**仍挡不住"持私钥者本人作恶"**。
3. **缺一个独立的、偷不走的第二道关卡**。

DVT 的价值正在这里：**一个独立的、链下的、持有自己密钥的协同签名方，它在签名之前执行策略、并且可以拒签——哪怕请求带着一个有效的 owner 签名。**
因为最终上链的**聚合签名必须包含 DVT 那一份**，DVT 拒签 → 聚合签名凑不齐 →
UserOp 过不了 `validateUserOp`。

> 身份门防的是**未授权调用方**；策略门 + 确认门**意在**防
> **owner 私钥泄露**。两者都不阻止 owner 在策略范围内的正常操作。

> 🔴 **修正（基于合约核对）**：上面"聚合签名必须包含 DVT 那一份 →
> DVT 拒签即可阻断"这句， **只在账户合约强制 BLS 路径时成立**。本仓库参考账户
> `AAStarAccountBase`（V6/V7/V8）的 `_validateSignatureBase`
> 有**无条件 ECDSA 回退**：owner 用普通 ECDSA 独签即通过，根本不进 BLS 路径，DVT 无从拒起。所以在这些账户上，**策略门 / 确认门防不住 owner 私钥泄露**——它们只在"调用方选择走 DVT 路径"时生效。真正的"防私钥泄露"要求账户**禁用 owner 单签、强制三重校验（owner
> ECDSA + messagePoint ECDSA + DVT
> BLS 聚合）**，即一个去掉回退的账户变体。这是 DVT 价值能否兑现的**关键合约前提**，应在 #40
> / 账户合约侧明确并落实。

---

## 5. 与合约的交互

| 方向   | 合约 / 方法                                                                                    | 用途                                                         |
| ------ | ---------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| 读     | `EntryPoint.getUserOpHash(userOp)`                                                             | 节点自算权威哈希（绑死 sender / chainId / EntryPoint）       |
| 读     | `account.owner()`                                                                              | 拿到 owner 地址，校验 ownerAuth                              |
| 读     | `IPolicyRegistry.checkPolicy(sender,target,asset,amount,selector) → (decision,remainingDaily)` | **策略门 Layer1：每账户链上策略 + 每日额度**                 |
| 读     | `AAStarValidator.getRegisteredNodes(offset,limit)`                                             | 发现已注册节点 / 公钥集合                                    |
| 写     | `AAStarValidator.registerPublicKey / revoke`                                                   | 节点上线 / 下线时登记自己的 BLS 公钥（需 `ETH_PRIVATE_KEY`） |
| 消费方 | `EntryPoint → account.validateUserOp → AAStarValidator`（EIP-2537 验 BLS 聚合）                | 最终验证聚合签名                                             |

链下策略（DVT 读 PolicyRegistry 决定签不签）+ 链上验签（validator 独立验聚合签名）是
**两道独立的关**；缺 DVT 那道，链上那道就只剩"验签有效性"。

---

## 6. SDK 请求里的关键数据（`SignMessageDto`）

- **`userOp`（完整 PackedUserOperation，不是哈希）**：
  `sender / nonce / initCode / callData / accountGasLimits / preVerificationGas / gasFees / paymasterAndData / signature?`。其中
  **`callData`
  是策略门的命脉**——DVT 自己解码它，取出真实收款人、金额、selector。
- **`ownerAuth`**：账户 owner 用 ECDSA 对**"EntryPoint 派生出的 userOpHash"**做的 EIP-191 签名。

> 关键设计：**调用方只能给"事实"（完整 userOp），不能给"结论"（哈希）**。哈希、owner、收款人、金额，全部由 DVT 自己从链上 /
> calldata 重新推导。

---

# 7. 策略门深度分析（本文重点）

## 7.1 能设置哪些策略

策略分两层。**Layer 2 是节点运营方的本地底线，Layer 1 是每账户的链上规则。**

### Layer 2 — 本地运营底线（节点运营方掌握，owner / CA 不可覆盖）

通过环境变量配置（`src/config/configuration.ts`），改动需要改 env + 重启节点：

| 参数 (env)                   | 类型       | 作用                                                                        | 默认             |
| ---------------------------- | ---------- | --------------------------------------------------------------------------- | ---------------- |
| `POLICY_ENABLED`             | bool       | 总开关。`!=true` 时退回 Stage1（只有身份门，无策略门）                      | `false`          |
| `POLICY_PER_TX_MAX_WEI`      | wei        | **单笔原生 ETH** 上限；超过即拒                                             | unset（不限）    |
| `POLICY_RECIPIENT_ALLOWLIST` | 地址逗号表 | 收款白名单。**调用涉及的每个地址（被调合约 + 解出的真实收款人）都必须在内** | 空（不限收款人） |
| `POLICY_REGISTRY_ADDRESS`    | address    | Layer1 链上注册器地址；空 = Layer1 关闭                                     | unset            |
| `POLICY_ETH_SENTINEL`        | address    | `checkPolicy` 里代表"原生 ETH"的资产 key                                    | `0xEee…EeE`      |

> **防空门保护**：`POLICY_ENABLED=true`
> 但三项规则全空 → 节点**拒绝启动**（避免"开了策略却等于全放行"给运营方虚假安全感）。见
> `policy.service.ts` 构造函数。

### Layer 1 — 每账户链上注册器（`PolicyRegistry.checkPolicy`）

DVT 只 **读**；规则由注册器合约的治理方在**链上**设置。源码：
`AAStarCommunity/SuperPaymaster` `contracts/src/core/PolicyRegistry.sol`（基线
`v5.4.0-beta.1`，节点 pin 见 `scripts/check-deps.mjs`）。单次查询入参
`(sender, target, asset, amount, selector)`，返回 `(decision, remainingDaily)`。

合约内部按两个维度判定，**每个维度都是 per-account（sender 维度）+ 各自细粒度**：

**(A) ASSET 维度 —
`mapping(sender => asset => AssetPolicy)`，按"每个代币合约地址"独立配额度。**
`asset`
既可以是某个 ERC-20 的合约地址，也可以是原生 ETH 哨兵地址。每个 asset 可设：

| AssetPolicy 字段               | 含义                                                                                   |
| ------------------------------ | -------------------------------------------------------------------------------------- |
| `perTxHardCap`                 | **该代币单笔硬顶**；`amount > perTxHardCap` ⇒ REJECT                                   |
| `dailyLimit` + `windowSeconds` | **该代币滚动日额度**；`已花 + amount > dailyLimit` ⇒ REJECT，否则返回 `remainingDaily` |
| `dvtTriggerAmount`             | **该代币的 DVT 触发额**；`amount ≥ dvtTriggerAmount` ⇒ REQUIRE_DVT（=0 关闭）          |

> **即：任何 token 都能注册自己的"单笔上限 + 每日上限 + 超额触发 DVT"——这正是 Layer1 对代币金额的完整管控，不依赖本地 Layer2。**

**(B) CONTRACT-SCOPE 维度 —
`mapping(sender => target => ContractScope)`，按"被调合约"管控。**

| ContractScope 字段                           | 含义                                                                       |
| -------------------------------------------- | -------------------------------------------------------------------------- |
| `allowed`                                    | 目标合约白名单；未 allowed ⇒ REJECT                                        |
| `_selectorAllowed[sender][target][selector]` | **按函数 selector 白名单**（可精确到 `transfer` / `approve` / 某业务函数） |
| `velocityLimit` + `velocityWindow`           | 对该目标的**速率/频次限额**                                                |
| `requireDVTAlways`                           | 该目标**永远** ⇒ REQUIRE_DVT（不看金额）                                   |

**判定与合成（合约语义）**：

- `_frozen[sender]` 冻结 ⇒ **硬 REJECT**（最高优先级，配合 guardian 应急）。
- **OPT-IN，默认 ALLOW**：某维度**没配置 = 不限制**（unconfigured ⇒
  unrestricted，`remainingDaily = max`）。
- 合成：任一已配置维度判 REJECT ⇒ REJECT；否则任一判 REQUIRE_DVT ⇒
  REQUIRE_DVT；否则 ALLOW。
- 节点侧 fail-closed：只认 `ALLOW(0) / REQUIRE_DVT(1)`，`REJECT`
  及任何未知值一律拒签（Codex F4）。

Layer1 因此能表达：**按账户 × 按代币（单笔顶 / 日额度 / 超额触发 DVT）× 按目标合约（白名单 /
selector / 速率 / 强制 DVT）的细粒度策略 + 冻结开关。**

### 相邻的两道"价值门"（不属 Policy，但同属 DVT 防护体系）

| 参数 (env)                                                                    | 作用                                                         |
| ----------------------------------------------------------------------------- | ------------------------------------------------------------ |
| `CONFIRM_ENABLED` / `CONFIRM_THRESHOLD_WEI` / `CONFIRM_TTL_MS`（默认 10 min） | **带外确认门**：高额操作挂起，等用户经独立通道批准；超时作废 |
| `NOTIFY_ENABLED` / `NOTIFY_THRESHOLD_WEI`（0 = 每次都通知）                   | **大额通知**：fire-and-forget 多通道告警，绝不阻塞签名       |

## 7.2 每个参数的"变动影响"（调参手册）

| 调整                                  | 影响                               | 风险 / 副作用                                                                |
| ------------------------------------- | ---------------------------------- | ---------------------------------------------------------------------------- |
| `POLICY_PER_TX_MAX_WEI` 调小          | 单笔原生转账上限收紧，更安全       | 太小会拦掉正常大额操作；**只管原生 ETH，不管 ERC-20 金额**                   |
| `POLICY_PER_TX_MAX_WEI` 调大 / unset  | 放宽                               | 失去本地金额底线，单点防护只剩白名单                                         |
| `POLICY_RECIPIENT_ALLOWLIST` 增减地址 | 收款面收紧 / 放宽                  | 白名单为空 = 不限收款人；地址写错会误伤                                      |
| 启用 `POLICY_REGISTRY_ADDRESS`        | 获得每账户细粒度 + 每日额度 + 分层 | 多一次链上 RPC（已并发化）；registry revert → fail-closed 拒（可用性换安全） |
| `CONFIRM_THRESHOLD_WEI` 调小          | 更多操作要带外确认，更安全         | 体验下降；**没配联系人通道 → undeliverable → 403**（高额直接做不了）         |
| `CONFIRM_TTL_MS` 调小                 | 确认窗口短，挂起态更少             | 用户来不及批准会作废                                                         |
| `POLICY_ENABLED=false`                | 退回 Stage1                        | **失去全部策略防护**，只剩 owner 验签                                        |

## 7.3 没有 DVT 拦不住、但 DVT 策略门能拦住的（有/无对比）

**场景：owner 的 ECDSA 私钥被钓鱼 / 泄露。**

| 攻击                            | 没有 DVT（单签账户）                         | 有 DVT 策略门                                                                                       |
| ------------------------------- | -------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| 把全部 USDC 转到陌生地址        | 偷来的私钥签名 → 链上验签通过 → **资金清空** | 收款人不在 allowlist / registry 返回 REJECT → **DVT 拒签** → 聚合签名凑不齐 → `validateUserOp` 失败 |
| 蚂蚁搬家（连续小额转出）        | 每笔验签通过 → 慢慢搬空                      | registry `remainingDaily` 每日额度卡死 → 超额部分拒签                                               |
| 大额给新地址                    | 立即成交                                     | 触发**带外确认门** → 用户独立通道收到"是否批准转 X" → 不批 → 挂起 / 拒                              |
| 分层额度（小额日常 / 大额管控） | 无此概念                                     | 小额 `ALLOW` 直通，大额 `REQUIRE_DVT` 强制走 DVT 协同 + 策略                                        |
| 正常用户小额转白名单            | 成交                                         | 四道门全过 → 正常签名（**不打扰正常使用**）                                                         |

## 7.4 拦不住的（局限、漏洞与风险）——必须诚实列出

策略门是**纵深防御的一层，不是银弹**。以下是它**当前拦不住或拦得不彻底**的情况：

1. **callData 解码面有限**：只解 `execute` /
   `executeBatch`。非标准账户调用面（自定义 multicall、其它 ABI）→
   **fail-closed 拒签**（安全，但可能误伤合法操作）。

2. **只解一层调用 + 泛化合约调用看不出金额**：`normalizeForPolicy` 能把
   `transfer` / `transferFrom` / `approve` / 原生转账解出真实
   `(asset, amount, recipient)` （含 approve 的授权额度，见 `policy.service.ts`
   `ERC20_APPROVE` 分支 / Codex
   F7），但对**泛化合约调用**（`execute(DEXrouter, 0, swap(...))`
   等）解不出内部金额 → `amount = 0`，只剩 **CONTRACT-SCOPE 维度（目标白名单 /
   selector / 速率 / requireDVT）** 兜底。也就是说：只要那个 router /
   bridge 在白名单内，**策略看不穿它内部把钱最终转去哪**——多跳 / 代理 /
   swap 类的资金流是真实盲区，要靠"只把可信合约加白名单 + 对它设速率 /
   requireDVT"来缓解。

   > 注：approve 不是盲区——它的授权额度会被解出并按 ASSET 维度（`perTxHardCap` /
   > `dailyLimit` / `dvtTriggerAmount`）和 Layer2 白名单（按 spender）一起管控。

3. **本地 Layer2 是"粗底线"，不是代币金额关**：`POLICY_PER_TX_MAX_WEI`
   只卡**原生 ETH**，这是设计取舍（本地 env 只做最粗的运营兜底）。**代币的单笔顶 / 日额度由 Layer1 的
   `AssetPolicy`（`perTxHardCap` /
   `dailyLimit`）完整承担**——见 7.1(A)，对任意 token 都能配。因此这不是"漏洞"，而是分工：**要管代币金额，就配 Layer1
   registry**。真正的注意点是下一条——
   **没配 registry 的账户在 Layer1 是 unrestricted（opt-in 默认 ALLOW）**，此时只剩本地白名单/ 原生上限兜底，务必为高价值账户在链上配齐
   `AssetPolicy` / `ContractScope`。

4. **依赖聚合阈值与节点独立性**：DVT 的"拒签即可阻断"只有在**链上 validator 要求足够多节点签名**、且**各节点由独立运营方、独立执行诚实策略**时才成立。若阈值是 k-of-n 且攻击者控制了 k 个节点 / 让多数节点用同一份被篡改的配置，则可绕过。**去中心化程度 = 安全上限。**

5. **节点主机安全**：Layer2 策略是 env 配置，攻陷节点主机 = 可改 env
   / 关策略。Layer1 在链上，篡改门槛更高。**Layer2 的强度受限于主机安全；高价值场景应以 Layer1 为准。**

6. **不防 owner 在策略内作恶 / 误操作**：策略只划边界，边界内的转账 DVT 照签（设计如此）。

7. **不覆盖 gas /
   paymaster 维度**：策略看 callData 的 value/recipient，不看 gas 字段；gas
   griefing / paymaster 滥用不在本门射程内。

> 设计取向：**凡是看不清的，一律 fail-closed 拒签**（解码失败、registry
> revert、未知decision）。这把"漏过坏交易"换成了"可能误拒个别合法交易"——对一道安全门是正确取向。

## 7.5 策略如何"变动 / 修改 / 生效"

- **Layer 2（本地底线）**：改 `POLICY_*` 环境变量 → **重启节点**
  生效。**只有节点运营方能改**（需要主机访问权），**账户 owner 无法用一个签名覆盖它**——这正是"owner 不可凌驾运营底线"的来源。
- **Layer 1（链上注册器）**：在 `PolicyRegistry` 合约上发交易修改每账户的
  `AssetPolicy` / `ContractScope`（`setAssetPolicy` / `tightenAssetPolicy` /
  `setContractScope`）。**DVT 只读，不改**——它在**每次签名时实时读最新规则**（无缓存 → 无过期策略窗口），registry
  revert 即 fail-closed。治理模型是**非对称的（这是关键安全属性）**：
  - **收紧 / 冻结 = 即时**：`guardian`（AirAccount 2-of-3
    RecoveryService）可立即 tighten 或 `_frozen[sender]`
    冻结账户（冻结 = 硬 REJECT，最高优先级）——账户被盗时能马上止血。
  - **放松 = 受 timelock 约束**：放宽限额必须经 OZ
    `TimelockController`（`minDelay = 2 days`），且 timelock 地址
    `immutable`（不可静默改指向）。**攻击者即便拿到治理权，也无法即时放宽限额来放行盗刷**——必须等 2 天，留出发现与冻结的窗口。
  - 仅 `_authorizedConsumer`（如 DVT / paymaster）可调 `checkPolicy`
    的配套写入（`recordSpend`），额度计数不被任意外部地址污染。

## 7.6 如何保证策略"独立、不受干扰地执行"

1. **执行点不可绕过**：策略门在进程内、签名之前；`signDerivedHash` 只有在
   `evaluate()` 返回 `allowed`
   后才会被调用——**签名在代码路径上无法越过策略门**。
2. **先身份后策略**：策略门只在 owner-auth 通过后可达 → 未授权者连探测策略的机会都没有（无策略 oracle、无 pre-auth 链上 RPC 的 DoS 面）。
3. **对调用方零信任**：哈希自算、owner 自读、收款人/金额自解码——**调用方只能提供事实，不能提供结论**，无法用伪造的"描述"诱导放行。
4. **本地底线 owner 不可覆盖**：即使链上 registry 返回 ALLOW，只要超本地
   `perTxMaxWei` 或不在 allowlist，照样拒。两层是"与"关系，不是"或"。
5. **fail-closed 贯穿**：任何不确定 → 拒，而非放行。
6. **多方独立**：多个独立运营方各跑自己的策略门 → 没有单一方能一键关闭所有节点的策略；这道门的"独立性"最终由**节点去中心化**承载（见
   `docs/aNode-dvt-operations.md`、多链/ 多实例部署策略）。
7. **能力分级**：策略门在能力注册表里是 `infra-core`（安全关键），与可选的
   `infra-app` 模块（通知/确认/keeper）分级隔离，明确它属于不可裁剪的内核职责。

---

## 8. 结语

- **链上验签**保证"签名有效"；**DVT 策略门**保证"操作合规"。
- DVT 最核心、最不可替代的价值不是"验 owner 签名"（任何节点都能做），而是
  **一道独立的、偷了私钥也跨不过的策略关**：按额度、按资产、按收款人、按 selector、按每日额度、按分层做 fail-closed 的拒签。
- 它是**纵深防御的一层**：清楚它**能拦什么**（私钥泄露后的越界转账、超额、陌生收款人、高额未确认），也要清楚它**拦不住什么**（穿透代理/路由的资金流、`approve`
  盲区需 Layer1 兜底、本地不限代币金额、阈值与主机安全的依赖），并据此配置 Layer1
  registry 与多节点部署，才能把这道门的价值发挥到位。
