// Cloudflare named-tunnel setup via API. Idempotent: creates (or reuses) a tunnel
// named TUNNEL_NAME, sets its ingress to the 3 local DVT ports, and points the 3
// hostnames' DNS at it. Prints the tunnel RUN token for `cloudflared tunnel run`.
//
// Needs CLOUDFLARE_TUNNEL_TOKEN in deploy/.env.testnet to be a Cloudflare API token
// with Account:Cloudflare Tunnel:Edit + Zone:DNS:Edit on the target zone.
//
// Usage: node deploy/cf-tunnel-setup.mjs
import fs from "fs";

const env = Object.fromEntries(
  fs
    .readFileSync("deploy/.env.testnet", "utf8")
    .split("\n")
    .filter(l => l.includes("="))
    .map(l => {
      const i = l.indexOf("=");
      return [l.slice(0, i).trim(), l.slice(i + 1).trim()];
    })
);
const API = env.CLOUDFLARE_TUNNEL_TOKEN;
const ZONE_NAME = "aastar.io";
const TUNNEL_NAME = "aastar-dvt-testnet";
const HOSTS = [
  { name: "dvt1", port: 4001 },
  { name: "dvt2", port: 4002 },
  { name: "dvt3", port: 4003 },
];

const cf = async (method, path, body) => {
  const r = await fetch("https://api.cloudflare.com/client/v4" + path, {
    method,
    headers: { Authorization: "Bearer " + API, "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const j = await r.json();
  if (!j.success) throw new Error(`${method} ${path} → ${JSON.stringify(j.errors)}`);
  return j.result;
};

const accountId = (await cf("GET", "/accounts"))[0].id;
const zoneId = (await cf("GET", `/zones?name=${ZONE_NAME}`))[0].id;
console.log("account=" + accountId.slice(0, 10) + "… zone=" + zoneId.slice(0, 10) + "…");

// 1. tunnel (reuse by name, else create)
let tunnels = await cf("GET", `/accounts/${accountId}/cfd_tunnel?name=${TUNNEL_NAME}&is_deleted=false`);
let tunnel = tunnels.find(t => t.name === TUNNEL_NAME);
if (!tunnel) {
  tunnel = await cf("POST", `/accounts/${accountId}/cfd_tunnel`, {
    name: TUNNEL_NAME,
    config_src: "cloudflare",
  });
  console.log("created tunnel " + tunnel.id.slice(0, 10) + "…");
} else {
  console.log("reusing tunnel " + tunnel.id.slice(0, 10) + "…");
}

// 2. ingress → local DVT ports
await cf("PUT", `/accounts/${accountId}/cfd_tunnel/${tunnel.id}/configurations`, {
  config: {
    ingress: [
      ...HOSTS.map(h => ({
        hostname: `${h.name}.${ZONE_NAME}`,
        service: `http://localhost:${h.port}`,
      })),
      { service: "http_status:404" },
    ],
  },
});
console.log("ingress set: " + HOSTS.map(h => `${h.name}→:${h.port}`).join(" "));

// 3. DNS CNAME (proxied) → <tunnel>.cfargotunnel.com
for (const h of HOSTS) {
  const fqdn = `${h.name}.${ZONE_NAME}`;
  const existing = await cf("GET", `/zones/${zoneId}/dns_records?name=${fqdn}`);
  const rec = {
    type: "CNAME",
    name: fqdn,
    content: `${tunnel.id}.cfargotunnel.com`,
    proxied: true,
  };
  if (existing.length) {
    await cf("PUT", `/zones/${zoneId}/dns_records/${existing[0].id}`, rec);
    console.log(`DNS ${fqdn} updated`);
  } else {
    await cf("POST", `/zones/${zoneId}/dns_records`, rec);
    console.log(`DNS ${fqdn} created`);
  }
}

// 4. run token for `cloudflared tunnel run --token`
const runToken = await cf("GET", `/accounts/${accountId}/cfd_tunnel/${tunnel.id}/token`);
fs.writeFileSync("deploy/.cf-run-token", runToken, { mode: 0o600 });
console.log("run token → deploy/.cf-run-token (start cloudflared with it)");
