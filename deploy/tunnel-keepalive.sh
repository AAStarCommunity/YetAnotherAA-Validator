#!/usr/bin/env bash
# Keep dvt{1,2,3}.aastar.io reachable. Probe the PUBLIC endpoints; if they are down, restart the
# cloudflared container; then re-probe and report whether it actually came back.
#
# Usage:  deploy/tunnel-keepalive.sh            # probe, restart if needed, verify
#         deploy/tunnel-keepalive.sh --check    # probe only, never restart (for a human)
#
# WHY THIS PROBES THE PUBLIC URL AND NOTHING ELSE
# The outage this exists for looked like this: all three node containers reported
# `Up 3 days (healthy)` while every public hostname returned Cloudflare 1033 for days. The container
# healthcheck runs INSIDE the container and never traverses the tunnel, so it cannot see a dead
# tunnel — and 1033 is emitted on Cloudflare's side, so nothing local goes red either. Any check
# that asks Docker how it feels would have stayed green through the whole thing. The only probe that
# can fail when this fails is an end-to-end request over the public hostname.
#
# WHY IT REFETCHES THE RUN TOKEN INSTEAD OF TRUSTING deploy/.env.testnet
# `CLOUDFLARE_TUNNEL_TOKEN` in that file is a Cloudflare *API* token (what cf-tunnel-setup.mjs
# needs). The compose `cloudflared` service needs a *tunnel RUN token* — a different secret behind
# the same name (issue #317). A plain `docker compose up cloudflared` therefore crash-loops with
# "Provided Tunnel token is not valid." So this script derives the run token from the API token at
# run time and passes it in-process. Nothing is written to disk and no token is ever printed.
# When #317 is fixed this block becomes redundant, not wrong.
#
# EXIT CODES — distinct, because they call for different actions and collapsing them makes the
# number stop being read (same reasoning as deploy/local-heartbeat.sh):
#   0  public endpoints serving (either already, or after a restart that worked)
#   1  still down after a restart attempt -- a real problem, look at it
#   2  could not reach a conclusion (this host has no working internet, or the API was unreachable);
#      deliberately NOT a restart, because restarting a tunnel you cannot see is thrashing
#   3  the node containers are not all reporting healthy -- the tunnel is not the problem. Restarting
#      it would front an empty origin, and worse: compose destroys the old cloudflared BEFORE
#      checking its `service_healthy` dependency, so the restart would leave no tunnel at all
set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_DIR" || exit 2

ENV_FILE="deploy/.env.testnet"
TUNNEL_ID="de08f3f4-1260-4836-bc6d-2860d778986b" # aastar-dvt-testnet
HOSTS=(dvt1.aastar.io dvt2.aastar.io dvt3.aastar.io)
CONTAINERS=(dvt-node-1 dvt-node-2 dvt-node-3)
RUN_DIR="$REPO_DIR/deploy/.run"
LOG="$RUN_DIR/tunnel-keepalive.log"
STAMP="$RUN_DIR/heartbeat-tunnel.txt"
CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

mkdir -p "$RUN_DIR"
stamp() { date -u +%Y-%m-%dT%H:%M:%SZ; }
say() { echo "[$(stamp)] $*" | tee -a "$LOG"; }

# One probe of one host. 200 is the only pass: a 1033/530/502 page is still an HTTP response, and
# treating "got bytes back" as success is precisely the mistake that let this outage hide.
probe_one() {
  curl -s -o /dev/null -w "%{http_code}" --max-time 10 "https://$1/health" 2>/dev/null
}

# All three, with retries. Returns the number serving. Retries because a single timeout on a laptop
# is not evidence of an outage -- one flaky request should never trigger a restart.
probe_all() {
  local tries=${1:-3} ok=0 h code
  for ((t = 1; t <= tries; t++)); do
    ok=0
    for h in "${HOSTS[@]}"; do
      code=$(probe_one "$h")
      [ "$code" = "200" ] && ok=$((ok + 1))
    done
    [ "$ok" -eq 3 ] && break
    [ "$t" -lt "$tries" ] && sleep 5
  done
  echo "$ok"
}

# Is it us or is it them? If this host cannot reach Cloudflare at all, the tunnel is not the thing
# that is broken and restarting it proves nothing.
internet_up() {
  curl -s -o /dev/null --max-time 8 https://api.cloudflare.com/client/v4/ips && return 0
  return 1
}

# Gate on HEALTH, not on Running -- it must match the condition compose itself enforces.
#
# This was `.State.Running` and that was a live bug (PR #318 review). `docker-compose.testnet.yml`
# gates cloudflared on `depends_on: condition: service_healthy`, and compose DESTROYS the old
# cloudflared container before evaluating that condition. So a node that is Running but unhealthy
# passed this check, reached the restart, and left the tunnel destroyed-and-not-recreated -- every
# 300 s, forever.
#
# The coupling is what makes it bite rather than being a corner case: the node healthcheck fetches
# `/health`, the SAME endpoint probe_one requests. The condition that makes the public probe fail is
# therefore the condition that makes compose refuse to start. A 2-of-3 degradation would have been
# converted by this script into a 3-of-3 outage.
#
# Empty status (a container with no healthcheck defined) counts as NOT healthy: compose's
# service_healthy would not be satisfiable either, so fail-closed is the truthful direction.
nodes_healthy() {
  local c st
  for c in "${CONTAINERS[@]}"; do
    st=$(docker inspect -f '{{.State.Health.Status}}' "$c" 2>/dev/null)
    [ "$st" = "healthy" ] || return 1
  done
  return 0
}

# Derive the tunnel RUN token from the API token. Retries: an api.cloudflare.com timeout is common
# on a home connection and is not a reason to give up. Prints the token on stdout ONLY to be
# captured into a variable by the caller; never logged.
fetch_run_token() {
  node -e '
const fs=require("fs");
const env=Object.fromEntries(fs.readFileSync(process.argv[1],"utf8").split("\n")
  .filter(l=>l.includes("=")).map(l=>{const i=l.indexOf("=");
    return [l.slice(0,i).trim(), l.slice(i+1).trim().replace(/^["\x27]|["\x27]$/g,"")];}));
const api=env.CLOUDFLARE_TUNNEL_TOKEN;
if(!api){process.stderr.write("no CLOUDFLARE_TUNNEL_TOKEN in env file\n");process.exit(2);}
const h={Authorization:"Bearer "+api};
const get=async u=>{for(let i=0;i<4;i++){try{
  const r=await fetch(u,{headers:h,signal:AbortSignal.timeout(20000)});return await r.json();
}catch(e){await new Promise(s=>setTimeout(s,2000*(i+1)));}}return null;};
(async()=>{
  const acc=await get("https://api.cloudflare.com/client/v4/accounts");
  if(!acc||!acc.success){process.stderr.write("cloudflare API unreachable\n");process.exit(2);}
  const aid=acc.result[0].id;
  const t=await get(`https://api.cloudflare.com/client/v4/accounts/${aid}/cfd_tunnel/${process.argv[2]}/token`);
  if(!t||!t.success){process.stderr.write("run-token fetch failed\n");process.exit(2);}
  process.stdout.write(t.result);
})();' "$ENV_FILE" "$TUNNEL_ID" 2>>"$LOG"
}

# ---------------------------------------------------------------------------

stamp >"$STAMP"
serving=$(probe_all 2)

if [ "$serving" -eq 3 ]; then
  say "OK 3/3 public endpoints serving"
  exit 0
fi

say "DOWN $serving/3 public endpoints serving"

if ! internet_up; then
  say "UNDETERMINED: this host cannot reach Cloudflare's API -- not restarting a tunnel we cannot see"
  exit 2
fi

if ! nodes_healthy; then
  say "NODES DOWN or NOT HEALTHY: one or more of ${CONTAINERS[*]} is not reporting healthy. The \
tunnel is not the problem; restarting it would front an empty origin -- and compose would destroy \
the running tunnel and then refuse to recreate it, turning a partial outage into a total one. \
Start or repair the node stack first."
  exit 3
fi

if [ "$CHECK_ONLY" -eq 1 ]; then
  say "--check: would restart cloudflared, but not restarting"
  exit 1
fi

say "restarting cloudflared"
RUNTOKEN="$(fetch_run_token)"
if [ -z "$RUNTOKEN" ]; then
  say "UNDETERMINED: could not obtain the tunnel run token -- see the log above"
  exit 2
fi

CLOUDFLARE_TUNNEL_TOKEN="$RUNTOKEN" \
  docker compose --env-file "$ENV_FILE" \
  -f docker-compose.testnet.yml -f docker-compose.local-mesh.yml \
  up -d --force-recreate cloudflared >>"$LOG" 2>&1
rc=$?
unset RUNTOKEN
[ "$rc" -ne 0 ] && say "docker compose exited $rc (continuing to verify -- the container may still be up)"

# VERIFY. A restart command that returned 0 is not the same as a tunnel that is serving; this script
# exists because something looked fine while being broken, so it does not get to make that mistake
# itself. The tunnel needs a few seconds to register its connections.
sleep 8
serving=$(probe_all 4)
if [ "$serving" -eq 3 ]; then
  say "RECOVERED 3/3 public endpoints serving after restart"
  exit 0
fi

say "STILL DOWN $serving/3 after restart -- needs a human. Check: docker logs --tail 30 dvt-cloudflared"
exit 1
