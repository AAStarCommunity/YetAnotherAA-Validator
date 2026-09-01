import { jest } from "@jest/globals";
import { readFileSync } from "fs";
import { resolve } from "path";
import { SEPOLIA_DEFAULTS as RELAY } from "../modules/relay/relay.constants.js";
import { SEPOLIA_DEFAULTS as X402 } from "../modules/x402-facilitator/x402-facilitator.constants.js";

/**
 * `deploy/sdk-dvt-config.testnet.json` is a PUBLISHED contract: @aastar/sdk and other repos read it
 * to learn which addresses this node serves. Nothing in `src/` reads it back, so it can drift away
 * from the constants the node actually uses and stay internally plausible for as long as nobody
 * cross-checks two repos by hand.
 *
 * That is not hypothetical. On 2026-09-02 `repo:superpaymaster` reported — and this repo confirmed
 * on chain — that the file names TWO different aPNTs contracts: the relay whitelist says
 * `0x9e66B457…` and the x402 leg says `0x696A7370…`. Both are real, both are `XPNTs-3.4.0`, both
 * carry the symbol `aPNTs`, and they have different supplies and different `communityOwner`s. A
 * balance or allowance on one says nothing about the other. It is the fourth split of this shape on
 * Sepolia, and the reason they survive is always the same: **the divergence lives on chain and
 * nothing turns red because of it.**
 *
 * This suite makes something turn red. It deliberately does NOT assert that all aPNTs addresses are
 * equal — see the pinned-divergence test for why that assertion would be wrong today. It asserts the
 * weaker, always-true property: the published file says exactly what the code says, and any change
 * to either has to be made in both places on purpose.
 */
const cfg = JSON.parse(
  readFileSync(resolve(process.cwd(), "deploy/sdk-dvt-config.testnet.json"), "utf8")
);
const sepolia = cfg.environments.sepolia;
const lower = (a: string) => a.toLowerCase();

describe("published SDK config must not drift from the constants the node uses", () => {
  it("relay whitelist matches src/modules/relay/relay.constants.ts", () => {
    const w = sepolia.capabilities.relay.whitelist;
    expect(lower(w.paymentToken_usdc)).toBe(lower(RELAY.usdc));
    expect(lower(w.targetToken_gtoken)).toBe(lower(RELAY.gtoken));
    expect(lower(w.targetToken_apnts)).toBe(lower(RELAY.apnts));
    expect(lower(w.buyHelper)).toBe(lower(RELAY.buyHelper));
  });

  it("x402 supported assets match src/modules/x402-facilitator/x402-facilitator.constants.ts", () => {
    const x = sepolia.capabilities.x402;
    expect(lower(x.facilitatorContract)).toBe(lower(X402.facilitatorContract));
    expect(lower(x.supportedAssets.apnts_aastar)).toBe(lower(X402.apnts));
    expect(lower(x.supportedAssets.pnts_mycelium)).toBe(lower(X402.pnts));
  });

  it("chainId is consistent across the file and both modules", () => {
    expect(sepolia.chainId).toBe(RELAY.chainId);
    expect(sepolia.chainId).toBe(X402.chainId);
  });
});

describe("the aPNTs divergence is PINNED, not assumed away", () => {
  /**
   * Why this is pinned rather than unified.
   *
   * The obvious "fix" is to point both at the ecosystem-current token `0x696A7370…`, which is what
   * SuperPaymaster's own `deployments/config.sepolia.json` names. I did not do that, because the two
   * are not obviously the same kind of thing:
   *
   *   - the x402 asset IS the ecosystem token — settled via the xPNTs factory's `direct` scheme;
   *   - the relay's aPNTs is bound to a SALE deployment (`relay.constants.ts` header:
   *     "Path-A canonical-bound stack", MushroomDAO/launch#27, `SaleContractV2`). A sale can
   *     legitimately sell a sale-specific token.
   *
   * On-chain evidence does not settle it: at block 11611567 the buyHelper holds ZERO of both — and
   * zero of the gtoken in the same whitelist, which is the control proving that probe is
   * uninformative rather than proving there is no inventory. buyHelper pulls via allowance from a
   * seller rather than holding stock, so "which token" depends on which sale is live and who funds
   * it — facts that are not on chain.
   *
   * So this test does the honest thing: it FREEZES the current pair. Resolving the split is a
   * deliberate decision by whoever owns the sale, and when they make it this test fails and forces
   * the config, the constants and this comment to be updated together.
   */
  it("freezes the known relay/x402 aPNTs split so an accidental change fails", () => {
    expect(lower(RELAY.apnts)).toBe("0x9e66b457e0abb1f139fd8a596d00f784eba2873b");
    expect(lower(X402.apnts)).toBe("0x696a73701b104c6ccbbaaddd2216788ea08eab89");
    // Documented as intentional-until-decided. If these ever become equal, that is the resolution
    // landing — update this test and the comment above rather than deleting them.
    expect(lower(RELAY.apnts)).not.toBe(lower(X402.apnts));
  });

  it("every address the config publishes is well-formed and distinct where it claims to be", () => {
    const w = sepolia.capabilities.relay.whitelist;
    const x = sepolia.capabilities.x402.supportedAssets;
    const all = [...Object.values(w), ...Object.values(x)] as string[];
    for (const a of all) expect(a).toMatch(/^0x[0-9a-fA-F]{40}$/);
    // The x402 leg advertises two DIFFERENT communities' tokens; collapsing them would silently
    // route Mycelium payments to AAStar's token.
    expect(lower(x.apnts_aastar)).not.toBe(lower(x.pnts_mycelium));
  });
});
