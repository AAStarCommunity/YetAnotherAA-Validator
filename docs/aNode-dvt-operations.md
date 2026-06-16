# aNode (DVT) — 运维手册 / Operations Runbook

> **aNode** = Mycelium DVT 共签节点（本仓库 =
> aNode 的参考实现，已发布 v1.1.0）。本手册给「技术提供方运行一个 aNode」的全套步骤：启动 → 监控 → 停止 → 恢复 → 报错排查 → 修复。关联：`scripts/e2e/`（本地多节点服务）·
> `docs/design/dvt-e2e-and-production.md`（生产化设计）· #42。

---

## A. 未来真实 DVT 该如何启动（生产，单个 aNode）

一个独立运营方跑一个生产 aNode 的步骤：

1. **准备密钥**：生成节点 BLS12-381 私钥（独立于 owner/CA）。
   - 开发：写入 `node_state.json`（`scripts/e2e/gen-nodes.mjs` 可生成）。
   - 生产：私钥进 KMS/HSM（不落明文盘）；当前 AirAccount
     KMS 仅 secp256k1，BLS 需 BLS-capable HSM。
2. **配置 env**（必填）：
   ```
   ETH_RPC_URL=<sepolia/mainnet RPC>
   VALIDATOR_CONTRACT_ADDRESS=<AAStarBLSAlgorithm / validator>
   ENTRY_POINT_ADDRESS=0x0000000071727De22E5E9d8BAf0edAc6f37da032   # v0.7 canonical
   PORT=3001
   POLICY_ENABLED=true                 # 生产开策略门（见下）
   POLICY_REGISTRY_ADDRESS=0x8c2488d46d5447418558c38AA6441720df656094  # SP PolicyRegistry (Sepolia, v5.4.0-beta.1-redeploy 2026-06-16)
   ETH_PRIVATE_KEY=<只在需链上注册/写时配；只签名可不配>
   ```
3. **构建 + 启动**：`npm ci && npm run build && npm run start:prod`。
4. **链上注册公钥**：用 SP `registerBLSPublicKey`（或本仓库
   `POST /node/register`）把节点 BLS 公钥注册到已知 slot
   —— 链上验签与 slash 都按注册 slot 寻址。
5. **接入门限**：≥N-of-M 个独立运营方各跑一个 aNode（不同 key/法域/软件栈），客户端（aastar-sdk）按门限收集共签。
6. **暴露通道**：节点 `POST /signature/sign`
   直连客户端（独立通道，不经 CA）；跨机器经 TLS/tunnel。

> 独立性三支柱（命门）：独立 BLS
> key + 独立策略（本地 layer-2 + 链上 layer-1）+ 独立通道。盲签=橡皮图章。

---

## B. 本仓库的多节点服务（开发/演示，一键）

```bash
./scripts/e2e/dvt-nodes.sh start     # 1. 启动：build + 生成密钥 + 起 3 个 aNode (nohup 持久)
./scripts/e2e/dvt-nodes.sh status    # 2. 监控：哪些节点 UP
./scripts/e2e/dvt-nodes.sh info      #    出可分享信息：URL / nodeId / BLS 公钥（给 aastar-sdk #63）
./scripts/e2e/dvt-nodes.sh logs 1    # 3. 看日志：tail node 1
./scripts/e2e/dvt-nodes.sh stop      # 4. 停止：停全部 3 个
node scripts/e2e/selftest.mjs        #    自测：3 节点签名 + Stage-1 闸门(坏 ownerAuth→403)
node scripts/e2e/realnode-e2e.mjs    #    E2E：真节点共签 → 链上 AAStarBLSAlgorithm.validate = 0
```

运行态（密钥/日志/pid）在 `.e2e/`（git 忽略）。

---

## C. 运维操作（start / monitor / stop / recover / error / fix）

| 操作             | 命令 / 做法                                                                                      |
| ---------------- | ------------------------------------------------------------------------------------------------ |
| **启动 start**   | `dvt-nodes.sh start`（生产：`npm run start:prod` + 进程守护 pm2/systemd）                        |
| **监控 monitor** | `dvt-nodes.sh status`；`curl :PORT/node/info`、`/gossip/stats`；日志告警接监控系统               |
| **停止 stop**    | `dvt-nodes.sh stop`（按 pid + 端口双杀）                                                         |
| **恢复 recover** | 节点无状态（除 `node_state.json`）→ 重启即恢复；密钥丢失从 KMS/备份恢复 `node_state.json` 再重启 |
| **报错 error**   | 见 §D 故障表（启动失败 / RPC 掉线 / 签名 403 / 链上验失败）                                      |
| **修复 fix**     | 见 §D 对应修复列                                                                                 |

---

## D. 常见故障 → 排查 → 修复

| 现象                                  | 原因                                                                                    | 修复                                                                                            |
| ------------------------------------- | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- |
| 启动即退出，报 env 校验失败           | 缺 `ETH_RPC_URL` / `VALIDATOR_CONTRACT_ADDRESS`                                         | 补齐 env（§A.2）后重启                                                                          |
| `/signature/sign` 返回 403            | Stage-1：`ownerAuth` 不是账户 `owner()` 的签名 / userOp 畸形 / owner==0x0(passkey-only) | 用账户 ECDSA owner 重签 ownerAuth；passkey-only 账户暂不支持（#40 Stage2）                      |
| `/signature/sign` 返回 403 且开了策略 | Stage-2：op 超限额/不在白名单                                                           | 调整 op 或在 PolicyRegistry/本地策略放行                                                        |
| 节点起来但签名报 RPC 错               | `ETH_RPC_URL` 带引号 / 掉线                                                             | 去引号；配多 RPC 备份（公共 Sepolia RPC 易掉线）                                                |
| 链上聚合验证失败                      | 节点 BLS 公钥未注册 / DST 非 `_POP_` / 编码错                                           | 注册公钥；确认 DST=`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`（noble 默认 `_NUL_` 必须覆盖） |
| 端口占用                              | 上次实例未停                                                                            | `dvt-nodes.sh stop` 或 `lsof -ti tcp:PORT \| xargs kill`                                        |

---

## E. 节点对外契约（消费方 aastar-sdk #63）

```
POST {url}/signature/sign
  body: { userOp:<PackedUserOperation v0.7>, ownerAuth:<owner EIP-191 sig over userOpHash> }
  → { nodeId, signature(EIP-2537 G2 256B), signatureCompact, publicKey, message:userOpHash }
GET  {url}/node/info       # 节点身份
POST {url}/signature/aggregate   # 聚合多签
GET  {url}/api             # Swagger
```

节点自派生 `userOpHash`（EntryPoint.getUserOpHash），强制 Stage-1
owner-auth，BLS 签 `hashToCurve(userOpHash)`。
