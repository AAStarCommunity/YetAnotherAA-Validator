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

| Mode        | What a loopback socket peer proves                                                        |
| ----------- | ----------------------------------------------------------------------------------------- |
| `direct`    | The listener is the boundary — the peer really is a process on this host.                 |
| `proxied`   | **Nothing.** A same-host reverse proxy / tunnel back-connects from `127.0.0.1`, so every  |
|             | public request also arrives from loopback.                                                |

There is **no default**: `NODE_ADMIN_NETWORK_MODE` is mandatory whenever
`NODE_ADMIN_ENABLED=true`, and a missing value is a **boot failure** (CC-49
round-6 MEDIUM-1). It used to default to `direct`, which meant an operator who
declared nothing got a node asserting _"loopback callers only"_ in its boot
banner on their behalf — false, and unwarned, behind the cloudflared tunnel this
repo documents. That was the round-4 hole, reachable by doing nothing at all.
While the endpoints are **disabled** there is nothing to reach and nothing to
declare, so the value stays optional there (`dvt1/2/3` are unaffected).

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

An unrecognised — or missing — `NODE_ADMIN_NETWORK_MODE` is a **boot failure**,
not a fallback to the looser mode. So is `NODE_ADMIN_ALLOW_PROXIED=true` without
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

Two consequences worth knowing before you declare a proxy:

- **There is no local escape hatch on the HTTP path.** Once the topology is
  declared, a request made _on this host_ straight to the listener has no
  `X-Forwarded-For` at the declared hop, so it is answered
  `403 NODE_ADMIN_FORWARDED_INVALID` — correct token included (CC-49 round-6
  LOW-1). That is fail-closed on purpose: the alternative is a bypass keyed on
  something the node cannot verify. If the proxy is down, administer the node
  with the CLI (`scripts/register-node.mjs`). The node says this at boot.
- **Write IPv4 CIDRs for IPv4 peers.** A dual-stack listener reports
  `::ffff:127.0.0.1`, which is normalised to its 4-byte IPv4 form, so an IPv6
  range can never contain it. `NODE_ADMIN_TRUSTED_PROXY_CIDRS=::ffff:0:0/96` or
  `::/0` would match nothing at all and reject every request; both are now a
  **boot failure** naming the fix rather than a node that starts and then 403s
  forever (CC-49 round-6 LOW-3). Use `127.0.0.0/8`; `::1/128` and real IPv6
  ranges such as `2001:db8::/32` are accepted as written.

## Enabling the HTTP path

```bash
NODE_ADMIN_ENABLED=true
# ≥ 32 chars, from a CSPRNG, and NOT the RepCredit experiment secret (the node refuses to
# boot on reuse — the two paths have different blast radii).
NODE_ADMIN_TOKEN="$(openssl rand -hex 32)"

# Network mode — see above. REQUIRED here; missing or unrecognised values refuse to boot.
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
4. The socket peer address is read, and **only** that: there is no `req.ip`
   fallback, because `req.ip` is `X-Forwarded-For`-derived once express
   `trust proxy` is on. A request whose peer cannot be read is
   `403 NODE_ADMIN_PEER_UNKNOWN`, never admitted on a header-derived address
   (CC-49 round-6 LOW-2).
5. **`direct` mode only**: loopback source, unless
   `NODE_ADMIN_ALLOW_REMOTE=true` — else `403`. Skipped in `proxied` mode,
   where loopback proves nothing.
6. Rate-limit bucket key: the socket peer, or the trusted-proxy-derived client
   address. Fail-closed — `403` on any mismatch with the declared topology.
7. Constant-time token comparison — **before** any budget is charged.
8. Throttle, on **separate ledgers** — `429`.

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
bound alone would not catch. It is charged **first**, so an attacker cannot keep
it clean by spending the cheaper per-source one — and once it is spent the node
short-circuits: no per-source entry is allocated or refreshed for an
unauthenticated caller (see the next section).

These are **application-level** ledgers, not per-route ones (CC-49 round-6
MEDIUM-2). `@UseGuards(NodeAdminGuard)` makes Nest build one guard instance per
_module_, so the state used to be split three ways across `/node`, `/dashboard`
and `/gossip`: the configured "global" bound was really 3x itself, the
per-source bound likewise, and the boot banner printed three times. The
decision and the ledgers now live in a single `NodeAdminPolicy` provider
(`NodeAdminModule`, `@Global`), so the numbers above are the numbers the node
enforces, whichever route is called.

### The throttle bounds what the node SPENDS, not just what it answers

A limiter that returns `429` while still allocating a ledger entry per request
is not a bound. With a declared trusted proxy the bucket key comes from a
header, so one host forging 25k `X-Forwarded-For` values grew the ledger and the
`O(n)` table sweep it ran on every insert — on the process that also runs the
signing hot path (CC-49 round-6 MEDIUM-3). Now:

- the global anonymous budget is charged first and **short-circuits**, so the
  number of distinct per-source keys a window can create is bounded by that
  budget (default 60), not by how many headers an attacker forges;
- every ledger has a **hard key capacity** (1024). Reaching it reclaims keys
  whose window has fully passed; if they are all still live the ledger refuses
  the new key rather than forgetting a live budget — evicting one would hand a
  source a second budget;
- bookkeeping is `O(1)` amortised: timestamps are pruned only for the key being
  touched, and reclamation stops at the first live entry;
- the `brute-force budget spent` log line is itself rate-limited to one per
  window (with a suppressed count), so a refused flood cannot become 25k log
  lines on the operator's disk.

`src/modules/node/node-admin.realprocess.spec.ts` runs the 25k-forged-header
flood against the built `dist/main.js` and against a control process with the
endpoints disabled (`403` before any bookkeeping), and asserts the gated node
adds no measurable memory over the control and does not get slower as the number
of forged keys grows.

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
| `NODE_ADMIN_PEER_UNKNOWN`               | `403` | Socket peer address unreadable; no `req.ip` fallback |
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
