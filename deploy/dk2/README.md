# Run a DVT-only node on the STM32MP157F-DK2 (ARMv7, 512 MB, systemd)

The deployment path for **node2** in the AAStar 3-node production topology
(2-of-3 DVT + 1 KMS; see CC-30 / CC-32). The DK2 is a **different architecture**
from the i.MX93 — 32-bit **ARMv7-A**, not arm64 — and has a **quarter of the
RAM** (512 MB vs 2 GB). This directory is a thin delta over
[`../imx93`](../imx93/README.md): same self-contained-bundle + systemd shape,
but cross-packaged for `linux-armv7l` and tuned for 512 MB.

> Why not just reuse the i.MX93 path? Two hard blockers: (1) an arm64 Node
> binary gives **`Exec format error`** on ARMv7 — the bundle must be armv7l; (2)
> 512 MB can't spare what an on-board `npm run build` (V8 + tsc) peaks at, so we
> **cross-build on your Mac/CI** and the board only unpacks.

## DK2 hardware profile

| Item      | Value                                                                  |
| --------- | ---------------------------------------------------------------------- |
| Board     | STM32MP157F-DK2                                                        |
| CPU       | Dual Cortex-A7 @ 800 MHz                                               |
| Arch      | **ARMv7-A 32-bit** + TrustZone (**not** arm64)                         |
| RAM       | **512 MB** DDR3L (the main constraint)                                 |
| Node role | **DVT-only** (no KMS co-located → local EIP-2335 keystore signing)     |
| Network   | On-board WiFi 802.11 b/g/n; today USB-Eth direct to host `192.168.7.2` |
| SSH       | `root@192.168.7.2` (passwordless)                                      |
| Serial    | `screen /dev/ttyUSB0 115200` (UART adapter)                            |

## Why this shape (DK2 / 512 MB / armv7)

| Concern                      | How it's handled                                                                                                                  |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| 32-bit ARM, not arm64        | Bundle ships its **own** `linux-armv7l` glibc Node; `install-dk2.sh` refuses a mismatched-arch bundle before systemd ever runs it |
| 512 MB RAM (build won't fit) | **Never build on the board** — cross-package on your Mac; board only unpacks                                                      |
| 512 MB RAM (runtime)         | `MemoryMax=320M` + `NODE_OPTIONS=--max-old-space-size=224`; leaves ~190 MB for OS + WiFi (tune on real hardware)                  |
| DVT-only (no KMS)            | Local `node_state.json` BLS key; `RUST_SIGNER_URL` **unset** (that's node1 only)                                                  |
| No Docker/Node in the image  | Pure systemd (present) + bundled Node                                                                                             |
| Self-heal                    | `Restart=always` (crash/OOM) **+** health-probe timer (hung-but-alive)                                                            |

All production deps are pure-JS (noble/ethers/nestjs), so the `node_modules`
tree is cross-arch safe — the same tree that runs on arm64 runs on armv7l.

## 1. Build the armv7l bundle (on your Mac / CI)

```bash
./deploy/dk2/build-bundle-dk2.sh
# → dist-bundle/aastar-dvt-<version>-linux-armv7l.tar.gz  (Node runtime + app + prod deps)
```

Resolves the latest LTS `node-v20.x-linux-armv7l` (glibc), compiles the app,
installs prod-only deps resolved for `linux/arm` (32-bit), SHA-256-verifies the
Node runtime, stamps the target `ARCH`, and tars it up. For a **reproducible**
release bundle, pin the exact Node patch:

```bash
NODE_VERSION=20.20.2 ./deploy/dk2/build-bundle-dk2.sh   # locks the runtime; record it with the app tag
```

## 2. Copy to the board

```bash
scp dist-bundle/aastar-dvt-*-linux-armv7l.tar.gz  root@192.168.7.2:/tmp/
scp -r deploy/dk2  root@192.168.7.2:/tmp/dk2      # install script + units (self-contained)
```

## 3. Install on the board (creates the layout; won't start until configured)

```bash
ssh root@192.168.7.2
cd /tmp/dk2
./install-dk2.sh /tmp/aastar-dvt-*-linux-armv7l.tar.gz node2
```

`install-dk2.sh` arch-guards the bundle (armv7l stamp + `node -v` exec check, so
an arm64 bundle fails fast) → stages + atomically swaps the release + `current`
symlink → seeds the DVT-only env template (PORT=4002, no `RUST_SIGNER_URL`) →
locks the state dir to `0700` → installs the 512 MB-tuned systemd units →
**enables for boot but does NOT start** while `ETH_RPC_URL` / the BLS key are
still missing (it prints exactly what's left). This is why the key + env come
next, not before install.

## 4. Provision this node's OWN BLS key + finish env

Generate an **independent** key on your Mac (the bundle ships no `scripts/`),
copy it into the state dir the installer just created, and fill in the RPC:

```bash
node scripts/gen-node-state.mjs                    # → node_state.json (its OWN BLS12-381 key)
# optional at-rest encryption (Cortex-A7 → use pbkdf2, scrypt is heavy here):
#   KDF=pbkdf2 node scripts/encrypt-node-key.mjs
scp node_state.json root@192.168.7.2:/opt/aastar-dvt/state/node2/node_state.json
ssh root@192.168.7.2 'chmod 600 /opt/aastar-dvt/state/node2/node_state.json'
# then set ETH_RPC_URL (validator/entrypoint are pre-filled):
ssh root@192.168.7.2 'vi /opt/aastar-dvt/env/node2.env'
```

Never reuse a repo/test BLS key — each node must have its own.

## 5. Start + verify

```bash
ssh root@192.168.7.2
systemctl start aastar-dvt@node2 aastar-dvt-health@node2.timer
# (re-running ./install-dk2.sh now also auto-starts, since env + key are present)

curl -s http://127.0.0.1:4002/health            # {version:"<ver>", ...}
curl -s http://127.0.0.1:4002/node/info         # this node's BLS public key
journalctl -u aastar-dvt@node2 -f
systemctl status aastar-dvt-health@node2.timer  # 30s self-heal probe
free -m                                         # confirm headroom under the 320M cap
```

## Upgrade / rollback

Same as i.MX93 — atomic `current` symlink:

```bash
# upgrade: install a newer bundle (keeps env + state)
./install-dk2.sh /tmp/aastar-dvt-<newer>-linux-armv7l.tar.gz node2
# rollback: repoint current at a prior release + restart
ln -sfn /opt/aastar-dvt/releases/<old-ver> /opt/aastar-dvt/current
systemctl restart aastar-dvt@node2
```

## Network (WiFi, later)

The DK2 currently reaches the host over USB-Eth (`192.168.7.2`). The production
plan is on-board WiFi onto the same restricted network as the KMS/MX93 nodes
(per-device MAC registration + per-device iPSK) with a Cloudflare tunnel for
public reachability, mirroring `kms1`. **WiFi credentials + tunnel token are
provisioned locally by ops — they never enter the coordination hub or GitHub.**

## Relation to the other paths

- [`../imx93`](../imx93/README.md) — node1 (KMS+DVT co-located) & node3
  (DVT-only), **arm64/2 GB**.
- **This dir** — node2 (DVT-only), **armv7/512 MB**.
- Validator address & network switch: `deploy/sdk-dvt-config.testnet.json` is
  the single source of truth (flip `active` testnet→mainnet).
