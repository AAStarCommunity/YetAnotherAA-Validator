# DVT Node Protocol — 签名格式（规范源 / normative）

> 状态: **规范源（root）** · 关联: #42（节点协议根）· #40 · 协调 hub:
> #42 本仓库是 DVT 节点协议的根（#42）。本文档是**签名格式的唯一规范源**；下游（SuperPaymaster
> verifier #283 / airaccount-contract #110 / aastar-sdk #63 / AirAccount
> #70）一律**对齐本规范**。任何变更 = 跨仓库 breaking
> change，须在 #42 同步。最后更新: 2026-06-14

## 0. 为什么这份在本仓库

依赖链 `#42 节点协议(根) → #283 → #110 / #63`。节点是 `(message→msgG2)`
的**产出方**，因此签名 preimage、DST、节点输出格式由本仓库**权威定义**，verifier/SDK/合约对齐之。

## 1. 签名 preimage（#42 冲突 #1 决策 B，已定稿）

```
userOpHash  = EntryPoint.getUserOpHash(userOp)        // ERC-4337 v0.7，已含 sender/nonce/chainId/EntryPoint
messagePoint(msgG2) = hash_to_curve( bytes(userOpHash), DST )
DST = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"   // PoP 方案，对齐 @noble/curves v2.0.1
```

- **选 B、不选 A**：`getUserOpHash`
  已绑定 account/chainId/nonce/EntryPoint，无需再
  `abi.encode(domainSeparator,…)`（冗余双绑）。
- **C1 调用约定**：BLS verifier 是 message-agnostic，绑定 `userOpHash`
  靠 co-sign entry point 传
  `expectedMessageHash = userOpHash`（airaccount-contract
  #110 在 validate 路径强制；现有 slash/reputation callers 传 proposal
  hash，DVT-of-UserOp 必须走独立 entry point）。

## 2. 节点输出（`/signature/sign`）

节点对**自身派生的** `userOpHash` 签名后返回（`bls.service.ts#signMessage`）：

| 字段               | 含义                                    | 下游用途                                              |
| ------------------ | --------------------------------------- | ----------------------------------------------------- |
| `signature`        | 本节点 BLS 签名 sigG2（EIP-2537，256B） | SDK 聚合成 aggregate sigG2                            |
| `signatureCompact` | 同上 compact 形式                       | 备用                                                  |
| `publicKey`        | 本节点公钥                              | **下游不需要**（合约从链上 key 重建 pkAgg）；仅信息性 |
| `message`          | 派生的 `userOpHash`                     | 核对                                                  |

**messagePoint 不传**：由 verifier 链上重算
`hashToG2(userOpHash)`（闭合 #45 重放）。

## 3. 链上 proof tuple（SP verifier 权威，节点/ SDK 对齐）

```
proof = (signerMask, sigG2)         // 不含 pkG1 / msgG2：合约链上重建 pkAgg + 派生 msgG2
signerMask 位序 = ROLE_DVT 注册 slot：bit i (LSB=0) → slot i+1 → validatorAtSlot[i+1]
```

## 4. 黄金向量（canonical，本仓库为基准）

固定输入 → 固定输出，四仓库 CI 逐字节断言。本仓库基准断言：`src/modules/bls/hash-to-g2.golden.spec.ts`。

```
canonical userOpHash = 0x1111111111111111111111111111111111111111111111111111111111111111
→ msgG2 (EIP-2537, 256B) = 0x000…06ee78bc…  (完整值见 golden spec)
```

- 本向量已用**终态 DST `_POP_`** 冻结 → 是 verifier 对齐的参照基准。
- 待 SP 将 `BLS.sol` DST 由 `_NUL_` 改为 `_POP_` 后，其 `(message→msgG2)`
  必与本向量逐字节一致；SP 再补 `(slot keys→pkAgg)`
  向量。建议四仓库统一用此 canonical 输入以便直比。

## 5. 状态

- §1–§4 已定稿/冻结（节点零返工，本仓库实现与本规范一致）。
- 下游待办：SP 改 DST→冻结向量→出
  `IPolicyRegistry`；之后本仓库接 layer-1 链上读取（见
  `dvt-policy-governance.md`）。
