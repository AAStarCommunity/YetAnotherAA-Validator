# DVT 测试网部署方案对比

把 DVT 从"本地 mock + 临时隧道"升级成 always-on 在线服务，三套技术方案：

## 方案一：Docker + Cloudflare Tunnel（self-host origin + named tunnel）✅ 已做部署包

你的 always-on 主机跑 `docker compose`（3 节点容器 + `cloudflared`
sidecar）；Cloudflare **named tunnel**
把它们暴露成稳定公网 HTTPS（你自己的域名），**无需公网 IP、无需开端口**。

- 工件：`Dockerfile` + `docker-compose.testnet.yml` + `deploy/README.md` +
  `deploy/.env.testnet.example`
- **优**：无公网 IP / 自动 TLS / Cloudflare free / DDoS 前置防护 /
  origin 隐藏 / 稳定域名 / 可复制
- **缺**：origin 主机仍自管（你负责重启/运维）；需要一个一直开的盒子 +
  CF 账号 + 域名

## 方案二：托管容器 PaaS（Fly.io / Railway / Render）——"完全 Docker 托管"

把同一个镜像 push 到容器 PaaS，平台托管 always-on + 公网 TLS + 自动重启/健康/日志。

- **优**：零运维（平台管进程/重启/扩容）/ 自带公网 TLS / 标准 CI 部署
- **缺**：规模上有成本 / 把可用性与密钥信任交给第三方平台 / 私钥进平台 secret
- 适合：不想自管主机的**专业运营方**

## 方案三：Cloudflare Containers（全 CF 栈，CF 原生容器托管）

DVT 容器跑在 Cloudflare Containers，CF 原生 always-on + 公网 +
Workers 前置，整条栈都在 CF。

- **优**：全 CF 栈统一账号 / CF 网络与安全一体
- **缺/待核**：对**长跑有状态服务 + WebSocket gossip + 持久私钥 + 出站 RPC**
  的支持与限制需先核实；计费模型；相对新
- 适合：未来想把整条栈收敛到 Cloudflare 时

---

## 推荐：**方案一（Docker + Cloudflare Tunnel）作为主路径**

理由（由 DVT 的特性驱动）：

1. **DVT 要去中心化多方**
   → 部署门槛必须低、可复制、每方独立。方案一让"任何人 clone + 自己 CF 账号 + 域名 + 一台 always-on 机器"就能跑自己的节点——这正是
   `deploy/README.md` 做到的。
2. **CF
   tunnel 一次解决最烦的三件事**：无公网 IP、自动 TLS、DDoS 前置——比方案二（要么自配反代+证书，要么付费 PaaS）省事，比方案三（限制待核）成熟。
3. **不锁死 origin**：origin 可以是任意 always-on 机器（VPS
   / 家用机 / 后续迁云），灵活。
4. 已**实测可行**：本地用 quick
   tunnel 就跑通了 SDK 跨仓库 E2E（`validate()===0`）；正式只是把 quick
   tunnel 换成 **named tunnel（稳定域名）**。

**分场景落地**：

- **AAStar 官方参考节点 / 社区运营方** → 方案一（默认）。
- **不想自管主机的专业运营方** → 方案二（Fly.io 等）作为备选，同一个镜像即可。
- 方案三留作"未来全 CF 栈"选项，待核实 Containers 对本服务的适配。

> 共同前提（三套都一样）：① 3 套**独立保密**
> BLS 密钥（不复用公开夹具）② 公钥在 v0.20.0 validator 注册（当前
> `registerPublicKey` 是 `onlyOwner`，是协调步骤）③ 策略门可选开启。
