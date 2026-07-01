# AAStarBLS Signer — Rust 轻量签名服务

高性能 BLS12-381 签名服务，只能本地访问。

## 🔒 安全设计

### 网络隔离
- **仅监听 127.0.0.1:5001**（localhost）
- 完全不对外暴露
- 操作系统级别防护（kernel 路由）
- 不能被外部网络访问

### 私钥保护
- 仅从本地 `node_state.json` 加载
- 内存中不落地
- 进程退出即销毁
- 无网络传输

## 快速开始

### 编译
```bash
cd signer
cargo build --release
```

输出：`target/release/aastar-bls-signer`（单个二进制，~20MB）

### 运行
```bash
# 方案 1: 直接运行
./target/release/aastar-bls-signer

# 方案 2: Node.js 内启动（生产推荐）
# 见下方部署方案
```

## API

### POST `/sign`
签名 userOpHash

**请求**：
```json
{
  "user_op_hash": "0x8bb1b199f427dfc49e5fe40f2f3278cb1a48587824b78263051c8c4d81d77a81",
  "node_id": "node_test"
}
```

**响应**：
```json
{
  "signature": "0xab...cd (256 bytes)",
  "public_key": "0xef...01 (128 bytes)"
}
```

### GET `/health`
健康检查

**响应**：
```
OK
```

## 与 Node.js DVT 集成

### 架构
```
Node.js DVT (port 4001)
    │
    └─→ HTTP POST localhost:5001/sign
        └→ Rust Signer (port 5001)
```

### 修改 Node.js 侧

在 `src/modules/bls/bls.service.ts` 的 `signDerivedHash()` 改为：

```typescript
async signDerivedHash(userOpHash: string, node: NodeKeyPair): Promise<SignatureResult> {
  // Call local Rust signer
  const response = await fetch('http://127.0.0.1:5001/sign', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      user_op_hash: userOpHash,
      node_id: node.nodeId
    })
  });

  if (!response.ok) {
    throw new Error(`Rust signer failed: ${response.statusText}`);
  }

  const { signature, public_key } = await response.json();

  return {
    nodeId: node.nodeId,
    signature,
    publicKey: public_key,
    signatureCompact: signature,  // Already compact
    message: userOpHash
  };
}
```

## 生产部署（i.MX93）

### 方案 A: 手工启动
```bash
# 同一设备上
systemctl start aastar-bls-signer
systemctl start aastar-dvt
```

### 方案 B: supervisord 管理（推荐）
```ini
[program:aastar-bls-signer]
command=/opt/aastar/signer/target/release/aastar-bls-signer
autostart=true
autorestart=true
stdout_logfile=/var/log/aastar-signer.log

[program:aastar-dvt]
command=node /opt/aastar/dist/main.js
autostart=true
autorestart=true
stdout_logfile=/var/log/aastar-dvt.log
```

### 方案 C: Docker (if arm64 available)
```dockerfile
FROM rust:latest as builder
WORKDIR /build
COPY signer .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /build/target/release/aastar-bls-signer /usr/local/bin/
EXPOSE 5001  # 仅内部，不实际暴露
CMD ["aastar-bls-signer"]
```

## 性能

- 单签名: ~50-100ms (BLS12-381 on A55 ARM)
- 吞吐: ~10 sig/sec (本地瓶颈是网络 RPC 调用 getUserOpHash)
- 内存: ~30MB RSS
- 二进制: ~20MB (release strip)

## 安全检查清单

- [ ] 仅监听 127.0.0.1
- [ ] 无 public 端口暴露
- [ ] 无外部网络调用（自含 BLS）
- [ ] node_state.json git-ignored
- [ ] 部署时检查防火墙规则
- [ ] 定期审计访问日志

## 故障排除

### "Connection refused"
- 确保 Rust signer 已启动
- 检查 `lsof -ti :5001`

### "Key not found for node: X"
- 确保 `deploy/nodeX/node_state.json` 存在
- 检查 JSON 格式和 privateKey 字段

### 性能慢
- 检查 CPU：`top` 看 Rust signer 占用
- 检查 RPC 延迟：主要瓶颈在 eth_call，不是签名

## 相关链接

- DVT: #140 (ERC-1271 owner-auth)
- Deployment: deploy/dvt-testnet.sh
- Tests: signer/tests/ (TBD)
