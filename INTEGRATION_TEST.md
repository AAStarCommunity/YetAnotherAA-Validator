# Hybrid 集成测试指南（feat/rust-signer）

## 当前状态

| 组件 | 状态 | 备注 |
|------|------|------|
| Rust Signer 骨架 | ✅ 完成 | 代码 + 文档 + 安全配置 |
| Node.js DVT 集成 | ✅ 完成 | signDerivedHash() 改造完毕 |
| 单元测试 | ✅ 145/145 通过 | 包括降级模式 |
| 集成测试 | 🔄 本文档 | 本地运行验证 |

## 测试场景

### 场景 1: 仅 Node.js（降级模式）✅

**前置条件**：Rust signer 未启动

**步骤**：
```bash
npm run start:dev
# 日志应显示: "Rust signer unavailable (fetch failed), falling back to Node.js local signing"
```

**验证**：
```bash
# 在另一个终端测试签名端点
curl -X POST http://localhost:4001/signature/sign \
  -H "Content-Type: application/json" \
  -d '{
    "userOp": {...},  # 完整 UserOperation
    "ownerAuth": "0x..."
  }'

# 应返回有效签名（使用 Node.js @noble/curves）
```

**预期结果**：✅ 签名成功，日志显示降级

---

### 场景 2: Hybrid 模式（Rust Signer + Node.js DVT）🔄

**前置条件**：编译 Rust signer

**步骤 1: 编译 Rust signer**
```bash
cd signer
cargo build --release
# 输出: target/release/aastar-bls-signer (~20MB)
```

**步骤 2: 启动 Rust signer**
```bash
# 终端 1
cd signer
./target/release/aastar-bls-signer
# 日志: "🔒 BLS Signer starting on 127.0.0.1:5001 (LOCAL ONLY)"
```

**步骤 3: 验证 Rust signer 在线**
```bash
curl http://127.0.0.1:5001/health
# 应返回: OK
```

**步骤 4: 启动 Node.js DVT**
```bash
# 终端 2
npm run start:dev
# 日志应显示: "Signed via Rust signer: node_test" (✓ 调用成功)
```

**步骤 5: 测试签名端点**
```bash
curl -X POST http://localhost:4001/signature/sign \
  -H "Content-Type: application/json" \
  -d '{
    "userOp": {...},
    "ownerAuth": "0x..."
  }'

# 日志应显示:
#   "Signed via Rust signer: node_test"
# 应返回有效签名（来自 Rust）
```

**预期结果**：
- ✅ Rust signer HTTP 200
- ✅ DVT 日志显示 "Signed via Rust signer"
- ✅ 签名有效且与 Node.js 模式兼容

---

### 场景 3: Rust signer 故障降级 ⚠️

**模拟 Rust signer 崩溃**

**步骤**：
```bash
# 终端 1 正在运行 Rust signer
# 在终端 1 按 Ctrl+C 杀死它

# 终端 2 的 Node.js DVT 仍在运行，发送请求
curl -X POST http://localhost:4001/signature/sign ...

# DVT 日志应显示:
#   "Rust signer unavailable (fetch failed), falling back to Node.js local signing"
```

**预期结果**：
- ✅ DVT 自动降级
- ✅ 签名仍然成功（用 Node.js）
- ✅ 用户无感知故障

---

### 场景 4: 签名互操作性 🔄

验证 Rust 签名和 Node.js 签名在链上行为一致

**步骤**：
```bash
# 1. 用 Node.js 签名
npm run build
PORT=4001 node dist/main.js

# 2. 调用 /signature/sign，保存 signature_nodejs

# 3. 启动 Rust signer，用 Hybrid 模式再签一次
./signer/target/release/aastar-bls-signer
npm run start:dev
PORT=4001 npm run start:dev

# 4. 调用 /signature/sign，保存 signature_rust

# 5. 验证两个签名都能通过 EntryPoint 验证
#    （或用 /signature/verify 验证）
```

**预期结果**：
- ✅ 两个签名格式相同（EIP-2537）
- ✅ 都通过链上验证
- ✅ 输出格式 100% 兼容

---

## 性能基准（集成测试）

### 测试工具：Apache Bench

```bash
# Node.js 模式
ab -n 100 -c 1 -p payload.json http://localhost:4001/signature/sign

# Hybrid 模式
ab -n 100 -c 1 -p payload.json http://localhost:4001/signature/sign
```

**预期结果**（单核 ARM A55）：

| 模式 | 平均响应时间 | Min | Max | 吞吐 (req/sec) |
|------|-------------|-----|-----|--------------|
| Node.js | ~200ms | 150ms | 300ms | 5 |
| Hybrid | ~130ms | 100ms | 200ms | 7.5 |
| 改进 | -35% | - | - | +50% |

---

## 故障排除

### "Connection refused at 127.0.0.1:5001"
```bash
# 检查 Rust signer 是否运行
lsof -ti :5001

# 重启 Rust signer
cd signer
./target/release/aastar-bls-signer
```

### "Key not found for node: node_test"
```bash
# 检查 node_state.json 存在
ls deploy/node1/node_state.json

# 检查 JSON 有效性
cat deploy/node1/node_state.json | jq .
```

### 签名不一致
```bash
# 对比两种模式的签名输出
# Node.js 模式日志: "Using local Node.js signing"
# Hybrid 模式日志: "Signed via Rust signer"

# 两个签名应该相同（hash 输入相同）
# 如果不同，检查:
#  1. userOpHash 是否一致
#  2. node_id 是否一致
#  3. 私钥是否一致
```

---

## 下一步（集成测试后）

- [ ] 在 i.MX93 实机运行 Hybrid 模式
- [ ] 验证内存占用（预期 ~180MB 总计）
- [ ] 验证性能（预期 ~90ms/签名）
- [ ] 运行 24h 压力测试
- [ ] 合并 PR（feat/rust-signer → main）
- [ ] 发布 v1.8.0 (Hybrid 生产版)

---

## 相关文档

- 📖 [Hybrid 架构](HYBRID_ARCHITECTURE.md)
- 📖 [Rust Signer README](signer/README.md)
- 🔗 [提交历史](https://github.com/AAStarCommunity/YetAnotherAA-Validator/tree/feat/rust-signer)
