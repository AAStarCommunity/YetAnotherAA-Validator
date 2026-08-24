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

**The supported way to register a node is the CLI**, which uses the operator's
own key and is idempotent:

```bash
ETH_RPC_URL=… VALIDATOR_CONTRACT_ADDRESS=0x… OPERATOR_PRIVATE_KEY=0x… \
  node scripts/register-node.mjs
```

## Enabling the HTTP path

```bash
NODE_ADMIN_ENABLED=true
# ≥ 32 chars, from a CSPRNG, and NOT the RepCredit experiment secret (the node refuses to
# boot on reuse — the two paths have different blast radii).
NODE_ADMIN_TOKEN="$(openssl rand -hex 32)"

# Optional
NODE_ADMIN_ALLOW_REMOTE=false   # default: loopback callers only
NODE_ADMIN_RATE_WINDOW_MS=60000 # always on (unlike the opt-in RATE_LIMIT_*)
NODE_ADMIN_RATE_MAX=10
```

Callers present the token in `X-Node-Admin-Token`. Comparison is constant-time
over SHA-256 digests, so neither the value nor its length leaks through timing.

Gate order — fail-closed, nothing falls through:

1. `NODE_ADMIN_ENABLED=true`, else `403`.
2. `NODE_ADMIN_TOKEN` set — enabled without a token rejects everything (`503`),
   never opens.
3. Loopback source, unless `NODE_ADMIN_ALLOW_REMOTE=true` — else `403`. The
   check reads the socket peer address, not `req.ip`, so an `X-Forwarded-For`
   header cannot claim loopback.
4. Per-source-IP throttle, counting failed attempts — else `429`.
5. Constant-time token comparison — `401` if absent, `403` if wrong.

> `NODE_ADMIN_ALLOW_REMOTE=true` makes a bearer token the ONLY barrier to
> on-chain registration and key-material changes. The node logs a warning saying
> exactly that at boot. Front it with TLS and an IP allow-list, or prefer the
> CLI.

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

| `errorCode`                             | HTTP  | Meaning                                      |
| --------------------------------------- | ----- | -------------------------------------------- |
| `NODE_ADMIN_DISABLED`                   | `403` | `NODE_ADMIN_ENABLED` is not `true`           |
| `NODE_ADMIN_TOKEN_UNSET`                | `503` | Enabled but `NODE_ADMIN_TOKEN` is empty      |
| `NODE_ADMIN_REMOTE_FORBIDDEN`           | `403` | Non-loopback source, remote not armed        |
| `NODE_ADMIN_RATE_LIMITED`               | `429` | Per-IP throttle spent                        |
| `NODE_ADMIN_TOKEN_MISSING`              | `401` | No `X-Node-Admin-Token` header               |
| `NODE_ADMIN_TOKEN_INVALID`              | `403` | Wrong token                                  |
| `NODE_REGISTER_STATE_MISSING`           | `503` | No `node_state.json` loaded                  |
| `NODE_REGISTER_BLOCKCHAIN_UNCONFIGURED` | `503` | `ETH_PRIVATE_KEY`/`ETH_RPC_URL` unset        |
| `NODE_REGISTER_UPSTREAM_FAILED`         | `502` | RPC/chain refused; see the scrubbed node log |

## What is NOT gated

Read-only routes stay open — they expose only values that are already public
on-chain: `GET /node/info`, `GET /node/health`, `GET /identity`, `GET /health`,
the dashboard HTML page and its read endpoints, and the `GET /gossip/*` views.
