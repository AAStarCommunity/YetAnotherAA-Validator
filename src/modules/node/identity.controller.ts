import { Controller, Get, Header } from "@nestjs/common";
import { ConfigService } from "@nestjs/config";
import { ApiExcludeEndpoint } from "@nestjs/swagger";
import { NodeService } from "./node.service.js";

/**
 * Public, no-auth node identity page (CC-34). Shows the node's PUBLIC identifiers — BLS public
 * key (on-chain registered) and the keeper EOA (funded on-chain) — so anyone can verify the node
 * or fund the keeper. These are public values, so the middle-masking is UX (avoid a wall of hex),
 * not secrecy: the full value is one click away and also in the page source. No private key is
 * ever read or rendered. The keeper address comes from KEEPER_ADDRESS (config); unset → shown as
 * not provisioned. The board has no /admin panel (capability off) so this is the public face.
 */
@Controller()
export class IdentityController {
  constructor(
    private readonly nodeService: NodeService,
    private readonly configService: ConfigService
  ) {}

  @ApiExcludeEndpoint()
  @Get("identity")
  @Header("Content-Type", "text/html; charset=utf-8")
  @Header("Cache-Control", "no-store")
  identityPage(): string {
    const node = this.nodeService.getCurrentNode();
    return renderIdentity({
      nodeId: node?.nodeId || "",
      nodeName: node?.nodeName || "",
      blsPublicKey: node?.publicKey ? "0x" + node.publicKey.replace(/^0x/, "") : "",
      keeperAddress: this.configService.get<string>("keeperAddress") || "",
    });
  }
}

/** Mask the middle of a long public hex so the page isn't a wall of hex (full value is 1 click away). */
function mask(v: string): string {
  if (!v) return "";
  return v.length <= 20 ? v : `${v.slice(0, 12)}…${v.slice(-8)}`;
}

/** Minimal HTML escape for the few dynamic values (all hex/ascii, but be safe). */
function esc(v: string): string {
  return v.replace(/[&<>"']/g, c => `&#${c.charCodeAt(0)};`);
}

function row(label: string, value: string, hint: string): string {
  if (!value) {
    return `<div class="row"><div class="label">${esc(label)}</div><div class="val none">— not provisioned —</div></div>`;
  }
  const full = esc(value);
  const masked = esc(mask(value));
  // Full value lives in a data attribute (it's public); the button toggles the visible text.
  return `<div class="row">
    <div class="label">${esc(label)}<span class="hint">${esc(hint)}</span></div>
    <div class="val"><code data-full="${full}" data-masked="${masked}" class="masked">${masked}</code>
      <button class="reveal" type="button" aria-label="reveal full value">reveal</button>
      <button class="copy" type="button" aria-label="copy full value">copy</button></div>
  </div>`;
}

function renderIdentity(d: {
  nodeId: string;
  nodeName: string;
  blsPublicKey: string;
  keeperAddress: string;
}): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DVT node identity${d.nodeName ? " — " + esc(d.nodeName) : ""}</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 15px/1.5 system-ui, sans-serif; margin: 0; padding: 2rem 1rem; background: Canvas; color: CanvasText; }
  .card { max-width: 760px; margin: 0 auto; border: 1px solid color-mix(in srgb, CanvasText 15%, transparent); border-radius: 12px; padding: 1.5rem 1.75rem; }
  h1 { font-size: 1.15rem; margin: 0 0 .25rem; }
  .sub { opacity: .65; margin: 0 0 1.5rem; font-size: .9rem; }
  .row { padding: .85rem 0; border-top: 1px solid color-mix(in srgb, CanvasText 10%, transparent); }
  .label { font-weight: 600; font-size: .82rem; letter-spacing: .02em; text-transform: uppercase; opacity: .8; }
  .hint { display: block; font-weight: 400; text-transform: none; letter-spacing: 0; opacity: .6; font-size: .8rem; margin-top: .1rem; }
  .val { margin-top: .4rem; display: flex; gap: .5rem; align-items: center; flex-wrap: wrap; }
  code { font-family: ui-monospace, monospace; font-size: .92rem; word-break: break-all; background: color-mix(in srgb, CanvasText 7%, transparent); padding: .3rem .5rem; border-radius: 6px; }
  code.none, .val.none { opacity: .5; font-style: italic; }
  button { font: inherit; font-size: .8rem; padding: .25rem .6rem; border-radius: 6px; border: 1px solid color-mix(in srgb, CanvasText 25%, transparent); background: transparent; color: inherit; cursor: pointer; }
  button:hover { background: color-mix(in srgb, CanvasText 10%, transparent); }
  .foot { margin-top: 1.5rem; opacity: .55; font-size: .8rem; }
</style></head><body>
<div class="card">
  <h1>DVT node identity</h1>
  <p class="sub">Public identifiers — verify this node or fund its keeper. No private key is ever exposed (it is sealed in the KMS TEE).</p>
  ${row("Node ID", d.nodeId, "keccak256(EIP-2537 BLS pubkey) — matches on-chain registerWithProof")}
  ${row("BLS public key", d.blsPublicKey, "compressed G1 (48 bytes) — the co-signing key, sealed in KMS TEE")}
  ${row("Keeper EOA", d.keeperAddress, "secp256k1 address for on-chain keeper txs — fund with ETH")}
  <p class="foot">JSON: <code>/node/info</code>. Values are public; masking is display-only.</p>
</div>
<script>
  for (const el of document.querySelectorAll("code[data-full]")) {
    const val = el.closest(".val");
    val.querySelector(".reveal").addEventListener("click", () => {
      const masked = el.classList.toggle("masked");
      el.textContent = masked ? el.dataset.masked : el.dataset.full;
      val.querySelector(".reveal").textContent = masked ? "reveal" : "hide";
    });
    const copyBtn = val.querySelector(".copy");
    copyBtn.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(el.dataset.full); copyBtn.textContent = "copied"; setTimeout(() => (copyBtn.textContent = "copy"), 1200); }
      catch { copyBtn.textContent = "copy failed"; }
    });
  }
</script></body></html>`;
}
