# Node-admin HTTP endpoints — closed by default

The DVT node binds `0.0.0.0` and the reference deployments
(`dvt1/2/3.aastar.io`) sit behind a public cloudflared tunnel. Five HTTP routes
changed durable state and had **no authentication at all** (CC-49 round-4
HIGH-1):

| Route                            | What an anonymous caller could do                                      |
| -------------------------------- | ---------------------------------------------------------------------- |
| `POST /node/register`            | Send an on-chain tx from the node's funded account — and read back the |
|                                  | provider's raw error, which embeds the RPC URL, i.e. the API key       |
| `POST /dashboard/nodes`          | Generate and persist new BLS key material                              |
| `POST /dashboard/import-node`    | Write an attacker-supplied BLS **private key** to disk                 |
| `DELETE /dashboard/current-node` | Destroy the node's key material                                        |
| `POST /gossip/data`              | Write into the gossip state this node republishes to peers             |

None of them is on the signing hot path and none is called by a peer — the peer
protocol runs over the authenticated WebSocket transport. They are operator
actions, so they are now **off unless an operator turns them on**.

## Default posture

`NODE_ADMIN_ENABLED` unset → every route above answers `403 NODE_ADMIN_DISABLED`
and nothing behind the guard runs (in particular, no RPC read is spent on a
rejected caller).

`deploy/.env.testnet.example` and `deploy/.env.mainnet.example` set
`NODE_ADMIN_ENABLED=false` **explicitly** (rather than leaving it to the
default) and declare `NODE_ADMIN_NETWORK_MODE=proxied`, so the `dvt1/2/3`
deployments are CLI-administered and a stray shell export cannot quietly arm the
HTTP path.

**The supported way to register a node is the CLI**, which uses the operator's
own key and is idempotent:

```bash
ETH_RPC_URL=… VALIDATOR_CONTRACT_ADDRESS=0x… OPERATOR_PRIVATE_KEY=0x… \
  node scripts/register-node.mjs
```

## Network mode is declared, never inferred

`NODE_ADMIN_NETWORK_MODE` tells the node what it is behind. It has to, because a
loopback socket peer means two completely different things in the two topologies
(CC-49 round-5 MEDIUM-1):

| Mode               | What a loopback socket peer proves                                                       |
| ------------------ | ---------------------------------------------------------------------------------------- |
| `direct` (default) | The listener is the boundary — the peer really is a process on this host.                |
| `proxied`          | **Nothing.** A same-host reverse proxy / tunnel back-connects from `127.0.0.1`, so every |
|                    | public request also arrives from loopback.                                               |

The reference deployment in this repo is the second one: `dvt1/2/3.aastar.io` →
cloudflared → `127.0.0.1:3001`. Under round-4's rules that made the "loopback
only" gate silently inert, while the one warning that says _the token is now the
only barrier_ was tied to `NODE_ADMIN_ALLOW_REMOTE=true` — so it never printed
on the deployment that needed it. An operator reading that config would
reasonably conclude "I did not arm remote, so only this host can reach these
routes", and on `dvt1/2/3` that conclusion was wrong.

So, in `proxied` mode the node:

- **never** consults the socket peer — there is no local caller to distinguish;
- **always** logs, in a highlighted block at boot, that `NODE_ADMIN_TOKEN` is
  the only network barrier;
- keeps the endpoints **disabled** (`403 NODE_ADMIN_PROXIED_NOT_ALLOWED`) until
  `NODE_ADMIN_ALLOW_PROXIED=true` acknowledges that explicitly.

An unrecognised `NODE_ADMIN_NETWORK_MODE` is a **boot failure**, not a fallback
to the looser mode. So is `NODE_ADMIN_ALLOW_PROXIED=true` without
`NODE_ADMIN_NETWORK_MODE=proxied`: an operator who sets only the former believes
they declared the tunnel, while the node would still be asserting `direct` and
applying an inert loopback gate — the round-4 state, reached by accident.

`direct` is an operator **assertion** that no proxy fronts the node. If that
assertion is wrong the loopback gate is inert — which is exactly the state
round-4 shipped in, and exactly why the mode is now explicit.
`src/modules/node/node-admin.realprocess.spec.ts` puts a real same-host TCP
reverse proxy in front of the built `dist/main.js` and pins all of this.

### `X-Forwarded-For` is never trusted

Admission always reads `socket.remoteAddress`. The header is parsed **only** to
pick a rate-limit bucket, and only when the operator has declared the topology
exactly:

```bash
NODE_ADMIN_TRUSTED_PROXY_CIDRS=127.0.0.1   # who is allowed to set the header
NODE_ADMIN_TRUSTED_PROXY_HOPS=1            # how many entries they append
```

Both must be set together and only in `proxied` mode — a half-declared topology
**refuses to boot** rather than key rate limits on a value the caller controls.
At request time the socket peer must be inside one of the CIDRs
(`403 NODE_ADMIN_UNTRUSTED_PROXY`), and the client address is read at exactly
`HOPS` from the right of the header, so a client-prepended entry cannot shift
it; anything missing or unparseable is `403 NODE_ADMIN_FORWARDED_INVALID`. The
proxy must still strip or overwrite any client-supplied `X-Forwarded-For`. Left
unset, every proxied caller simply shares one anonymous bucket — which is what
the global anonymous ledger below exists for.

## Enabling the HTTP path

```bash
NODE_ADMIN_ENABLED=true
# ≥ 32 chars, from a CSPRNG, and NOT the RepCredit experiment secret (the node refuses to
# boot on reuse — the two paths have different blast radii).
NODE_ADMIN_TOKEN="$(openssl rand -hex 32)"

# Network mode — see above. Unrecognised values refuse to boot.
NODE_ADMIN_NETWORK_MODE=direct  # or: proxied
NODE_ADMIN_ALLOW_PROXIED=false  # proxied mode stays CLOSED until this is true

# Optional
NODE_ADMIN_ALLOW_REMOTE=false   # direct mode only: accept non-loopback peers
NODE_ADMIN_RATE_WINDOW_MS=60000 # always on (unlike the opt-in RATE_LIMIT_*)
NODE_ADMIN_RATE_MAX=10          # unauthenticated attempts, per source
NODE_ADMIN_ANON_GLOBAL_RATE_MAX=60  # unauthenticated attempts, all sources together
NODE_ADMIN_OPERATOR_RATE_MAX=120    # authenticated requests, separate ledger
```

Callers present the token in `X-Node-Admin-Token`. Comparison is constant-time
over SHA-256 digests, so neither the value nor its length leaks through timing.

Gate order — fail-closed, nothing falls through:

1. `NODE_ADMIN_ENABLED=true`, else `403`.
2. `proxied` mode armed with `NODE_ADMIN_ALLOW_PROXIED=true`, else `403`.
3. `NODE_ADMIN_TOKEN` set — enabled without a token rejects everything (`503`),
   never opens.
4. **`direct` mode only**: loopback source, unless
   `NODE_ADMIN_ALLOW_REMOTE=true` — else `403`. The check reads the socket peer
   address, not `req.ip`, so an `X-Forwarded-For` header cannot claim loopback.
   Skipped in `proxied` mode, where loopback proves nothing.
5. Rate-limit bucket key: the socket peer, or the trusted-proxy-derived client
   address. Fail-closed — `403` on any mismatch with the declared topology.
6. Constant-time token comparison — **before** any budget is charged.
7. Throttle, on **separate ledgers** — `429`.

> Whenever the endpoints are enabled the node says so at boot. In `proxied` mode
> and with `NODE_ADMIN_ALLOW_REMOTE=true` it says it in a highlighted block: a
> bearer token is then the ONLY barrier to on-chain registration and
> key-material changes. Front it with TLS and an IP allow-list, or prefer the
> CLI.

## An anonymous flood cannot lock the operator out

The round-4 throttle was one per-source ledger, charged before authentication
and counting successes as well as failures. Behind a tunnel every caller shares
the source key `127.0.0.1`, so ~10 unauthenticated requests per minute held the
admin plane shut for the operator too (CC-49 round-5 MEDIUM-2).

Now the token is verified **first**, in constant time, and the two classes of
caller are charged to physically separate ledgers:

| Caller                 | Ledger                                         | Default         |
| ---------------------- | ---------------------------------------------- | --------------- |
| missing or wrong token | per source **and** a global brute-force ledger | 10 / 60 overall |
| correct token          | its own operator ledger                        | 120             |

Exhausting the anonymous ledgers still bounds token guessing — a wrong token is
`429`d with the flood — but it can never `429` a correct one. The global ledger
is what bounds a flood spread across many client addresses, which a per-source
bound alone would not catch. Both anonymous ledgers are charged on every failed
attempt (not short-circuited), so an attacker cannot keep the global one clean
by spending the cheaper per-source one first.

Neither the presented token nor the configured one is ever written to a log
line, a metric or a response body.

The browser dashboard asks for the token once per tab and keeps it in
`sessionStorage` only — it is never rendered into the page source and never
persisted.

## Provider errors are never echoed

`POST /node/register` used to answer
`200 {"success":false,"message":"Registration failed: <raw ethers error>"}`. An
ethers error embeds the request URL — which carries the provider API key — in
its `message`, `stack` and `info.requestUrl`. Because the handler caught its own
error, the global `ScrubbingExceptionFilter` never saw it.

Now: the log line goes through `scrubProviderError`, and the response carries
**no provider text at all** — only `502 NODE_REGISTER_UPSTREAM_FAILED`, pointing
the operator at the (scrubbed) node log.
`src/modules/node/node-admin.realprocess.spec.ts` spawns the built
`dist/main.js` against a credential-bearing RPC URL that always 401s and asserts
that no fragment of that credential appears in any response body or anywhere in
the process log.

## Error codes

Every rejection carries the versioned envelope described in
[RepCredit error codes](./REPCREDIT_EXPERIMENT.md#error-codes-for-repo-sdk):

| `errorCode`                             | HTTP  | Meaning                                              |
| --------------------------------------- | ----- | ---------------------------------------------------- |
| `NODE_ADMIN_DISABLED`                   | `403` | `NODE_ADMIN_ENABLED` is not `true`                   |
| `NODE_ADMIN_PROXIED_NOT_ALLOWED`        | `403` | `proxied` mode without `NODE_ADMIN_ALLOW_PROXIED`    |
| `NODE_ADMIN_TOKEN_UNSET`                | `503` | Enabled but `NODE_ADMIN_TOKEN` is empty              |
| `NODE_ADMIN_REMOTE_FORBIDDEN`           | `403` | `direct` mode, non-loopback source, remote not armed |
| `NODE_ADMIN_UNTRUSTED_PROXY`            | `403` | Peer outside `NODE_ADMIN_TRUSTED_PROXY_CIDRS`        |
| `NODE_ADMIN_FORWARDED_INVALID`          | `403` | No client address at the declared hop                |
| `NODE_ADMIN_RATE_LIMITED`               | `429` | Anonymous or operator throttle ledger spent          |
| `NODE_ADMIN_TOKEN_MISSING`              | `401` | No `X-Node-Admin-Token` header                       |
| `NODE_ADMIN_TOKEN_INVALID`              | `403` | Wrong token                                          |
| `NODE_REGISTER_STATE_MISSING`           | `503` | No `node_state.json` loaded                          |
| `NODE_REGISTER_BLOCKCHAIN_UNCONFIGURED` | `503` | `ETH_PRIVATE_KEY`/`ETH_RPC_URL` unset                |
| `NODE_REGISTER_UPSTREAM_FAILED`         | `502` | RPC/chain refused; see the scrubbed node log         |

## What is NOT gated

Read-only routes stay open — they expose only values that are already public
on-chain: `GET /node/info`, `GET /node/health`, `GET /identity`, `GET /health`,
the dashboard HTML page and its read endpoints, and the `GET /gossip/*` views.
