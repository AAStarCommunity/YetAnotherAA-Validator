# aNode Roadmap — 全局版本路线图

> 本文是 aNode(本仓库 =
> DVT 签名节点参考实现)的**唯一全局路线图**。后续开发 follow 本文。配套:跨仓库整合
> [#45] · 多语言/SDK 边界设计 [#63] · 前身营养归档 [#59/#60/#61/#62] ·
> conformance 基线 `conformance/`。当前已发布:**v1.3.0**(node
> hardening + 依赖治理 + /check-deps + license + real-node E2E `validate=0`)。

---

## 0. 定位:我们是基础设施,不是应用

```
┌─ 终端应用(钱包 / dApp / 社区产品)         ← 由「应用开发者」构建
│        depends on
├─ AAStar SDK(@aastar/*)                     ← 集成/运行时「客户端库」(面向应用)
│        HTTP / RPC（单向）
├─ aNode 基础设施(本仓库)                    ← 「服务」:DVT 签名 / paymaster / validator / guardian
│        on-chain
└─ 合约(SuperPaymaster / AAStarBLSAlgorithm / EntryPoint)
```

**核心边界(不可破)**:

- **aNode
  = 基础设施服务**,由其**协议/HTTP 契约**定义。**永不依赖 SDK**(`package.json`
  禁止任何 `@aastar/*`,见 [#63])。依赖单向:`SDK → aNode`,绝不反向,绝不成环。
- **应用依赖 SDK**;SDK 是应用与基础设施之间的**适配层**,经 HTTP 调 aNode。应用一般不直连我们,走 SDK。

### 0.1 我们「可以」提供的:基础设施级应用(infra-level apps)

我们不做消费级产品,但**会提供一薄层"基础设施自带的参考/最小 UI"**——那些**与基础设施安全/正确运行内在绑定**、不该让每个应用各自重造的关键路径界面。例如:

- **社交恢复 / Guardian 基础页面**(aNode 愿景 Phase
  4):恢复是安全关键、infra 拥有的流程,提供公共物品级最小恢复 UI。
- **带外确认 / 共签批准页**([#54]):用户审批一次性 token 的参考页面。
- **节点运营方 Dashboard / Admin**(已有 `/admin`):运维向。
- **账户生命周期管理界面**(Phase 3 TEE account manager)。

**判定准则**:

> 「这个流程是否是基础设施正确/安全运行所**固有**的(恢复 / 共签批准 / 运营)?」→
> infra 可出**参考/最小 UI**(公共物品)。「这是不是一个**产品/消费体验**(钱包 /
> dApp)?」→ 那是**应用**,建在 SDK 上,不归我们。

**约束**:即便是 infra-level app,也**必须守住无环边界**——用 aNode 自己的 API
/ 内嵌薄客户端,**不依赖消费级 SDK**(否则 `App→SDK→aNode→SDK`
成环)。它们是**参考实现 / 最小公共物品**,不是完整产品。

### 0.2 待对齐契约差异

SDK 的 `@aastar/core`
自带 DVT 客户端实现(`dvtActions`/`DVTClient`/`blsSigner.dvt`/`weighted-signature-service`)。**重复实现是好事**(独立实现互为一致性校验),前提是与本节点**逐字节对齐**——由
`conformance/` 向量保证。⚠️ SDK 有
**weighted-signature**(加权门限),本节点目前等权聚合,需在协议 spec 里**明确是否支持 weighted**,避免语义漂移(在 1.5.0 对齐)。

---

## 1. 版本路线图

主线:**先把 Node.js 版做成「全面版 aNode」(到 1.5.0),再 1.6.0 并行出 Go +
Rust 初步 → 同仓库三语言并行**。贯穿原则:节点 = 协议契约,`conformance/` 守门。

### v1.3.0 ✅ 已发布 — hardening + 依赖治理

Stage1 owner-auth、Stage2 两层策略、opt-in
rate-limit/notify/带外确认、`/check-deps`
两层依赖同步 skill、license 合规、real-node E2E `validate=0`、cross-language
conformance 基线。

### v1.4.0 — 生产化地基 + 协议冻结

把"能跑"变"敢上线"的安全地基,并冻结多语言契约。

- **BLS 私钥 → KMS/HSM 可插拔 signer**(借 [#62] 的 AWS KMS / Cloudflare
  Secrets 调研)— 安全底线。
- **Telegram
  bot 通知到指定已注册账户**:用户把自己的 Telegram 账户注册/绑定到节点,大额共签等事件经 bot 私信发到**该指定账户**(per-account 绑定,非全局频道)。**Email
  / Nostr 通道延后**(后续版本)。
- **常驻 Price Keeper Phase 1**([#58]):节点 24/7,顺带兜底链上价格新鲜。
- **协议 spec + OpenAPI 升为唯一真相源** + `conformance/`
  向量正式纳入 CI([#63])。
- 技术重点:密钥管理抽象、通道适配、协议规范化。
- 分工:Crypto/Sec=KMS
  signer;Node=通道/keeper;Protocol=spec/OpenAPI/conformance。
- 关联:#50 #52 #58 #63。

### v1.5.0 — 全面版 Node.js aNode(参考节点）

功能完整的参考节点 = aNode 愿景里成熟的 **Phase 2** + 部分 Phase 3/4 接口。

- **#40 Stage2 passkey-owner**(借 [#60] 旧 Go 已跑通的 passkey→DVT)。
- **策略系统增强:层级化 + 安全过滤层**(借 [#62])— Stage2 v2。
- **可插拔验证管道重构**:owner-auth / policy / confirm /
  security-filter 形式化为 pipeline(借 [#62])。
- **M-of-N 真实多运营方** + 公网节点 URL/TLS + **provider 抽象**(多 RPC
  / 多价源)。
- **Keeper Phase 2**:CEX 价源兜底 + 护栏(多源中位/偏离阈值/上下界)。
- **对齐 SDK weighted-signature 契约**(见 0.2)。
- 技术重点:passkey 集成、策略引擎、pipeline 架构、多运营方协调。
- 分工:Node=pipeline/policy;Crypto=passkey-relay;Ops=M-of-N/public
  URL;SDK=契约对齐。
- 关联:#40 #50 #58 #62。**里程碑:这是「比较全面的 Node.js aNode」。**

### v1.6.0 — 三语言并行初步(Node + Go + Rust)

同仓库三实现并行,都过 `conformance/`。

- **冻结 协议 / OpenAPI / conformance 作契约**(前置)。
- **Go 版初步**(骨架借 [#59] 旧 Go 节点:memberlist /
  go-webauthn)过 conformance。
- **Rust 版初步**(骨架借 [#61] aNode `relay-server/src/core`)过 conformance。
- **monorepo 结构**([#45]):`node-js/ node-go/ node-rust/ + 共享 conformance/ + contracts/`。
- **gossip 互操作决策**落地(推荐:跨语言只在签名+聚合+链上层互通;gossip 退化为各部署内部实现)。
- 技术重点:BLS 库一致性(Go `gnark`/`kilic`、Rust `blst`/`arkworks`)、OpenAPI
  codegen、monorepo CI 跑三语言 conformance。
- 分工:Go dev;Rust dev;Protocol=conformance 守门;CI/Ops=monorepo。
- 关联:#45 #63 #59 #61。

### v2.0+ — PQC + Guardian + TEE + mainnet

- **PQC 迁移**(BLS→PQC / hash-based;aNode 愿景 P2/P4 已预告)。
- **Guardian**:社交恢复 / deadman's switch(Phase 4)+ 0.1 的社恢复基础页面。
- **TEE account manager**(Phase 3)+ 账户生命周期界面。
- **mainnet 审计** + live slashing(Brood PGL [#3])。

---

## 2. 三条贯穿主线(每版都在推进)

1. **安全演进**:本地 key →(1.4)KMS/HSM →(1.5)M-of-N 多运营方 →(2.0)PQC。
2. **能力完整度**:离散 gates →(1.5)可插拔验证管道 +
   passkey + 安全过滤 → 全面 Phase 2。
3. **多语言契约**:(1.3)conformance 基线 →(1.4)spec/OpenAPI 冻结 →(1.6)Go/Rust 过 conformance
   → 三语言并行。

## 3. 关键依赖 / 顺序约束(阻塞关系)

- **1.6 的 Go/Rust 强依赖 1.4 的协议冻结 +
  conformance**——否则各写各的必漂移。1.4 必须把 spec/OpenAPI 升为唯一真相源。
- **gossip 互操作决策须在 1.5 末拍板**(独立集群 vs 跨语言同集群),直接决定 1.6 工作量。
- **SDK weighted-signature 契约差异**须在 1.5 对齐,否则三语言各写不同语义。

## 4. 知识库索引

- 前身营养:[#59]/[#60](旧 Go aNode)·
  [#61]/[#62](AAStarCommunity/aNode,4 阶段愿景)。
- 方向设计:[#63](语言无关协议 + SDK 边界 + 多语言并行)。
- 整合 hub:[#45]。conformance:`conformance/README.md`。
