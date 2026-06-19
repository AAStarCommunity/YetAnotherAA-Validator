# aNode (DVT) 集成指南 / How to Integrate

> **维护说明**：本文档随集成形态演进**持续更新**。最后更新：2026-06-19。
>
> 集成有三种形态，本文档分章节维护：
>
> - **① 本地调试版（Local Dev）** — ✅ 当前可用（本文 §1）
> - **② 在线版（Hosted / Testnet）** — 🚧 待补充（本文 §2）
> - **③ 生产版（Production）** — 🚧 待补充（本文 §3）
>
> 关联文档：[`DVT_VALUE.md`](./DVT_VALUE.md)（DVT 价值 + 策略门深度分析）·
> [`aNode-dvt-operations.md`](./aNode-dvt-operations.md)（运维手册）·
> [`design/dvt-e2e-and-production.md`](./design/dvt-e2e-and-production.md)（生产化设计）。

---

## 0. 总览：上下游与角色

DVT 节点在 ERC-4337 交易生命周期里负责"在 owner 授权下产出可被链上 BLS 验证器接受的聚合签名，并有权拒绝"。

```
上游（谁调它）                         下游（它依赖谁）
┌─────────────────────────────┐
│ dApp / SDK + 协调器          │
│ + 账户 owner（出 ownerAuth） │
└──────────────┬──────────────┘
               │  HTTP POST，每个节点独立调
               ▼
       ┌────────────────┐   只读链上：EntryPoint.getUserOpHash
       │  DVT 节点群      │ ─────────────► account.owner()
       │ :3001/3002/3003 │   （策略门开启时）PolicyRegistry.checkPolicy
       └───────┬────────┘
               │  各节点返回 BLS 签名 → 协调器聚合(EIP-2537)
               ▼
   AAStarValidator(已注册公钥) ◄── EntryPoint / Bundler 最终消费聚合签名
```

- **上游**：dApp/SDK 构造 UserOperation，账户 owner 用 ECDSA 签出
  `ownerAuth`，协调器把 `{userOp, ownerAuth}` 分发给每个节点。
- **下游**：节点只读链上派生哈希、读 owner、（开启时）读策略；最终聚合签名由链上
  `AAStarValidator` 经 EIP-2537 验证。

---

## 1. 本地调试版（Local Dev）✅

一键起 3 个本地 DVT 节点，用于联调 SDK / 协调器 / 端到端签名。

### 1.1 一键启停

```bash
./scripts/e2e/dvt-nodes.sh start     # 构建(如需) + 生成密钥(如需) + 起 3 个节点(nohup 持久)
./scripts/e2e/dvt-nodes.sh status    # 查看哪些节点 UP
./scripts/e2e/dvt-nodes.sh info      # 出可分享信息：URL / nodeId / BLS 公钥
./scripts/e2e/dvt-nodes.sh logs 1    # tail node 1 日志
./scripts/e2e/dvt-nodes.sh stop      # 停全部 3 个
```

运行态（密钥/日志/pid/`common.env`）在 `.e2e/`（git 忽略）。

### 1.2 节点清单

| 节点  | URL                     | nodeId（前缀）     | 链上注册（V019）        |
| ----- | ----------------------- | ------------------ | ----------------------- |
| node1 | `http://localhost:3001` | `0xb548c8e2…`      | ✅ 已注册（BLS_TEST_1） |
| node2 | `http://localhost:3002` | `0x7f7e6290…`      | ✅ 已注册（BLS_TEST_2） |
| node3 | `http://localhost:3003` | `0x0000…26634443…` | ✅ 已注册（本轮注册）   |

> node3 原为 fresh（仅本地密钥、链上未登记）。已于 2026-06-19 注册到 V019
> validator（tx
> `0xf2016d34960b90054e800b04c43510a877a2e32cf07d437df76376ae1d72cced`），validator
> `getRegisteredNodeCount()` 现为 3。

### 1.3 绑定的链上合约（必须用最新版本）

| 用途            | 地址                                         | 来源 / 版本                                                            |
| --------------- | -------------------------------------------- | ---------------------------------------------------------------------- |
| BLS 验证器      | `0x68c381Ad3A2e3380F22840008027E9Ec2783F43A` | airaccount-contract **v0.19.0-beta.2**（canonical，`check-deps` 校验） |
| EntryPoint v0.7 | `0x0000000071727De22E5E9d8BAf0edAc6f37da032` | 规范地址                                                               |
| 链              | Sepolia                                      | `ETH_RPC_URL`（`.e2e/common.env`）                                     |

> 集群 `.e2e/common.env` 的 `VALIDATOR_CONTRACT_ADDRESS`
> 已切到 V019。每次新增节点都注册到这个 canonical 最新地址，保证 node1/2/3 一致。校验最新地址用
> `npm run check-deps`。

### 1.4 核心 endpoint 与调用约定

| 方法 + 路径                      | 用途                                                      |
| -------------------------------- | --------------------------------------------------------- |
| `POST {url}/signature/sign`      | 让该节点联合签名一笔 UserOperation                        |
| `POST {url}/signature/aggregate` | 把收齐的 N 个节点签名聚合成 EIP-2537 格式（任意节点可做） |
| `POST {url}/signature/verify`    | 本地验证聚合签名                                          |
| `POST {url}/signature/confirm`   | 带外确认：批准一笔挂起的高额操作                          |
| `GET {url}/node/info`            | 出 nodeId / BLS 公钥（私钥隐藏）                          |
| `GET {url}/api`                  | Swagger / OpenAPI 文档（完整请求/响应 schema 以此为准）   |

**`/signature/sign` 约定（核心）：**

- 请求体：`{ userOp, ownerAuth }`。
  - `userOp`：**完整的 PackedUserOperation（不是哈希）**——节点自己用
    `EntryPoint.getUserOpHash(userOp)`
    派生权威哈希，绑死 sender/chainId/EntryPoint。
  - `ownerAuth`：账户 owner 对**该派生哈希**的 **EIP-191 ECDSA 签名**。
- 成功响应：`{ nodeId, signature, publicKey }`（`signature`
  为该节点的 BLS 签名）。
- 高额且开启带外确认时：返回
  `{ status: "pending_confirmation", userOpHash, message }`（挂起，待用户经独立通道批准）。
- **统一 fail-closed**：任何鉴权失败一律 **403**（owner 不匹配 / 缺 ownerAuth /
  userOp 畸形 / 派生失败 等）。注意：请求体连 `userOp` 字段都没有时是
  **400**（DTO 校验，未进闸门）。

### 1.5 典型集成流程

```
1. dApp/SDK 构造 PackedUserOperation（sender = 智能账户）
2. owner 用 ECDSA 对 userOpHash 签名 → ownerAuth
3. 协调器把 {userOp, ownerAuth} 分发给 node1/2/3 → 各自 POST /signature/sign
4. 协调器收齐各节点 BLS 签名 → POST /signature/aggregate（任意节点）→ 聚合签名(EIP-2537)
5. 聚合签名写进 UserOp 的 signature 字段
6. Bundler 把 UserOp 提交给 EntryPoint
7. EntryPoint → account.validateUserOp → AAStarValidator（EIP-2537 验聚合）→ 执行
```

### 1.6 健康检查 / fail-closed 自测

```bash
# 健康
curl -s http://localhost:3001/node/info | jq .

# fail-closed 闸门（应分别为 403 / 403 / 400）
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:3001/signature/sign \
  -H 'content-type: application/json' -d '{"userOp":{"sender":"0x0000000000000000000000000000000000000001"}}'  # 403
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:3001/signature/sign \
  -H 'content-type: application/json' -d '{"userOp":{}}'   # 403
curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:3001/signature/sign \
  -H 'content-type: application/json' -d '{}'              # 400（DTO：缺 userOp）

# 端到端（真节点共签 → 链上 validate=0）
node scripts/e2e/realnode-e2e.mjs
```

### 1.7 故障排查

| 现象                         | 处理                                                                              |
| ---------------------------- | --------------------------------------------------------------------------------- |
| 端口 3001-3003 被占          | `dvt-nodes.sh stop` 再 `start`；或 `lsof -ti tcp:3001 \| xargs kill`              |
| 启动崩 `UnknownDependencies` | NestJS DI：可选构造参数需 `@Optional()`（见 PR #84 / #86）。重建：`npm run build` |
| node3 链上不可用             | 确认已注册到 §1.3 的 V019 地址（`getRegisteredNodeCount`）                        |
| 改了代码但行为没变           | 节点跑的是 `dist/`，需 `npm run build` 后重启                                     |

---

## 2. 在线版（Hosted / Testnet）🚧 待补充

> 面向"连到一组公开托管的 testnet DVT 节点"的集成方。待补充要点：

- [ ] 公开域名 + TLS（每节点独立 endpoint，跨机经 TLS/tunnel）
- [ ] 多实例无单点拓扑、负载/路由约定
- [ ] 协调器如何发现节点集合与门限
- [ ] testnet 上的 validator / EntryPoint 地址与注册流程
- [ ] 速率限制、鉴权、CORS 等对外约定

---

## 3. 生产版（Production）🚧 待补充

> 面向"自己运营一个生产 aNode 或接入生产门限集群"的集成方。待补充要点（细节见
> [`aNode-dvt-operations.md`](./aNode-dvt-operations.md) §A）：

- [ ] BLS 私钥进 KMS/HSM（不落明文盘），独立于 owner/CA
- [ ] N-of-M 门限：多个**独立运营方**各跑一个 aNode（不同 key/法域/软件栈）
- [ ] 开启策略门（`POLICY_ENABLED` + 链上 PolicyRegistry，见 `DVT_VALUE.md`）
- [ ] 带外确认 / 通知通道配置
- [ ] 进程守护（pm2/systemd）、监控、告警、密钥轮换与恢复
- [ ] 主网 validator / EntryPoint 地址与链上注册（`registerBLSPublicKey`）

---

## 相关文档

- [`DVT_VALUE.md`](./DVT_VALUE.md) —
  DVT 核心价值与策略门深度分析（含人话速览表）
- [`aNode-dvt-operations.md`](./aNode-dvt-operations.md)
  — 运维手册（start/monitor/stop/recover）
- [`design/dvt-e2e-and-production.md`](./design/dvt-e2e-and-production.md)
  — 生产化设计
- `scripts/e2e/README.md` — e2e 脚本说明
- Swagger：每个节点的 `GET /api`
