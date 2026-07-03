# Run a DVT node on i.MX93 (Yocto, systemd) — no Docker, no firmware change

The GA deployment path for a **resource-constrained arm64 board** (NXP i.MX93, 2
GB, Yocto BSP). It avoids Docker/Podman entirely — on Yocto those need the
`meta-virtualization` layer and a **firmware rebuild + reflash**, which is not
worth it for a single signer. Instead we ship a **self-contained bundle** (its
own glibc `linux-arm64` Node runtime + compiled app + prod deps) and run it
under **systemd** — which every NXP i.MX Yocto image already has as init.

> For always-on **non-embedded** hosts (Mac mini, x86 VPS), use the Docker path
> instead — see [`../README.md`](../README.md) and `docker-compose.mainnet.yml`.

## Why this shape (i.MX93 / Yocto)

| Concern                                     | How it's handled                                                             |
| ------------------------------------------- | ---------------------------------------------------------------------------- |
| No Node.js in the Yocto image               | Bundle ships its **own** `linux-arm64` glibc Node binary                     |
| No Docker/Podman without a firmware rebuild | Pure systemd — already present                                               |
| App updates without reflashing              | Swap the bundle + `systemctl restart` (firmware untouched)                   |
| Flash wear (eMMC)                           | Near-stateless app; only writes are logs → journald (volatile-capable)       |
| 2 GB RAM                                    | `MemoryMax=512M` per node; run **one** node per board (N-of-M = more boards) |
| Self-heal                                   | `Restart=always` (crash) **+** a health-probe timer (hung-but-alive)         |

The build never happens on the board — you cross-package on your Mac/CI and the
board only unpacks. All production deps are pure-JS (noble/ethers/nestjs), so
the `node_modules` tree is cross-arch safe.

## 1. Build the bundle (on your Mac / CI)

```bash
./deploy/imx93/build-bundle.sh
# → dist-bundle/aastar-dvt-<version>-linux-arm64.tar.gz  (~80 MB: Node runtime + app + deps)
```

Resolves the latest LTS `node-v20.x-linux-arm64` (glibc — matches Yocto),
compiles the app, installs prod-only deps resolved for `linux/arm64`, and tars
it all up.

## 2. Copy to the board

```bash
scp dist-bundle/aastar-dvt-*-linux-arm64.tar.gz  root@<board-ip>:/tmp/
scp -r deploy/imx93  root@<board-ip>:/tmp/imx93     # the install script + units
```

## 3. Install (on the board)

```bash
cd /tmp/imx93
./install.sh /tmp/aastar-dvt-*-linux-arm64.tar.gz node1
```

This unpacks to `/opt/aastar-dvt/`, symlinks `current`, installs the systemd
units, and enables the node + its health timer. Then:

1. **Put the node's BLS key**: `/opt/aastar-dvt/state/node1/node_state.json`
   (its OWN secret key — `chmod 600`; never share/clone it).
2. **Fill the env**: `/opt/aastar-dvt/env/node1.env` (PORT, ETH_RPC_URL,
   VALIDATOR_CONTRACT_ADDRESS; relay/keeper keys if used).
3. Restart: `systemctl restart aastar-dvt@node1`.

## 4. Verify

```bash
systemctl status aastar-dvt@node1
curl -s http://127.0.0.1:4001/health | jq .version      # matches the bundle
systemctl list-timers 'aastar-dvt-health@*'             # probe scheduled
journalctl -u aastar-dvt@node1 -f
```

## Self-heal, exercised

```bash
# crash recovery (Restart=always):
systemctl kill -s SIGKILL aastar-dvt@node1 ; sleep 5 ; systemctl is-active aastar-dvt@node1  # → active

# hung-but-alive recovery (health timer restarts it):
#   the aastar-dvt-health@node1.timer curls /health every 30s and restarts the
#   node if it stops answering. Watch it act:
journalctl -u 'aastar-dvt-health@node1' -f
```

## Upgrade / rollback

```bash
# upgrade: build a new bundle, copy, re-run install.sh — it atomically repoints `current`.
./install.sh /tmp/aastar-dvt-<new>-linux-arm64.tar.gz node1

# rollback: point current back at a prior release and restart.
ln -sfn /opt/aastar-dvt/releases/<old-version> /opt/aastar-dvt/current
systemctl restart aastar-dvt@node1
```

## Optional: hybrid Rust signer (faster BLS on ARM)

Delegate BLS signing to a local Rust signer (byte-identical output —
golden-vector verified — and faster on the A55). Fully optional: if the signer
is down the DVT falls back to in-process Node signing. Best fit for this
constrained board.

```bash
# (on your Mac) cross-build the arm64 signer — no Docker, uses cargo-zigbuild:
#   rustup target add aarch64-unknown-linux-gnu && brew install zig && cargo install cargo-zigbuild
./signer/build-arm64.sh          # → signer/dist-arm64/aastar-bls-signer (aarch64 glibc)

# (plan b) sanity-check raw signing throughput ON THE BOARD before wiring it in:
scp signer/dist-arm64/aastar-bls-signer root@<board>:/tmp/
ssh root@<board> '/tmp/aastar-bls-signer --bench'   # prints ms/sig + sig/s (Node ≈ 150 ms/sig)

# (plan c) install it as a loopback service next to the DVT node:
scp -r deploy/imx93 root@<board>:/tmp/imx93
ssh root@<board> 'cd /tmp/imx93 && ./install-signer.sh /tmp/aastar-bls-signer node1'
#   → enables aastar-bls-signer@node1 (127.0.0.1:5001, key-holding hardening),
#     sets RUST_SIGNER_URL in the node env, restarts the DVT.
```

Verify the DVT is routing to it:
`journalctl -u aastar-dvt@node1 | grep 'Rust signer'` (“Signed via Rust
signer”). Set `RUST_SIGNER_REQUIRED=true` in the node env to fail closed instead
of falling back to Node.

## HA (whole-board failure)

Per-board self-heal does NOT cover the board dying. DVT co-signing HA = a
**second board with its OWN pre-registered BLS key** + N-of-M — never key
cloning. Relay/ Keeper are stateless → run ≥2 boards; the SDK fails over across
node URLs. BLS keys stay on their own board (later: EIP-2335 encrypted at rest,
#50④), never in a shared KMS. See issues #100 / #50.

## Notes

- **Read-only rootfs?** If your hardened Yocto image mounts `/` read-only, point
  `ROOT` in `install.sh` at a writable data partition and place the unit files
  via a systemd drop-in on a writable path.
- **Init system**: assumes systemd (NXP i.MX Yocto default). If your image was
  built with sysvinit/busybox, use an init script + cron probe instead (same two
  layers).
