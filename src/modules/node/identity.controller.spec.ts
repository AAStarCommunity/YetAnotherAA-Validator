import { describe, it, expect } from "@jest/globals";
import { IdentityController } from "./identity.controller.js";

const NODE = {
  nodeId: "0xf177545fd7889a4a0670944da3b3ae2ca12718cec89c830e59a05ebc4b6dd664",
  nodeName: "dvt-kms-tee",
  publicKey:
    "949ffed8a9a5bbd153714a6752f327ff94834c636a1e35acf8af3e405af01a5a0e6f8d6b76987722262b12a9865e1436",
};
const KEEPER = "0xca23b643243e74f3a7502eafa6cfb509b5e49b7c";

function make(keeper: string | null) {
  const nodeService: any = { getCurrentNode: () => ({ ...NODE, privateKey: "0xSECRET" }) };
  const configService: any = { get: (k: string) => (k === "keeperAddress" ? keeper : undefined) };
  return new IdentityController(nodeService, configService);
}

describe("IdentityController /identity", () => {
  it("renders both public values (masked) with the full value one click away", () => {
    const html = make(KEEPER).identityPage();
    // full values present (for reveal/copy), and masked display present
    expect(html).toContain(`data-full="${NODE.nodeId}"`);
    expect(html).toContain(`data-full="${KEEPER}"`);
    expect(html).toContain(`data-full="0x${NODE.publicKey}"`); // 0x-normalized BLS pubkey
    expect(html).toMatch(/0xf177545fd7…4b6dd664/); // masked node id shown by default
    expect(html).toContain("reveal");
    expect(html).toContain("Keeper EOA");
  });

  it("NEVER leaks the private key", () => {
    const html = make(KEEPER).identityPage();
    expect(html).not.toContain("SECRET");
    expect(html.toLowerCase()).not.toContain("privatekey");
  });

  it("shows 'not provisioned' when the keeper EOA is unset", () => {
    const html = make(null).identityPage();
    expect(html).toContain("not provisioned");
    // the BLS pubkey is still shown
    expect(html).toContain(`data-full="0x${NODE.publicKey}"`);
  });

  it("returns a self-contained HTML document (no external requests)", () => {
    const html = make(KEEPER).identityPage();
    expect(html.startsWith("<!doctype html>")).toBe(true);
    expect(html).not.toMatch(/src=|href=|@import|fetch\(/); // no external assets/calls
  });
});
