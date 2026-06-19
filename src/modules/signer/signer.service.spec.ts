import { jest } from "@jest/globals";

// Mock bls.util so the test does not pull in the ESM-only curve lib; assert the port
// delegates to the BLS primitives with the signer's key (custody seam, not the algorithm).
jest.unstable_mockModule("../../utils/bls.util.js", () => {
  const getPublicKey = jest.fn((sk: Uint8Array) => ({ kind: "pk", sk }));
  const sign = jest.fn(async (mp: any, sk: Uint8Array) => ({ kind: "sig", mp, sk }));
  return {
    sigs: { getPublicKey, sign },
    bls: {},
    BLS_DST: "TEST",
    encodeG2Point: () => new Uint8Array(256),
  };
});

const { LocalKeySigner } = await import("./local-key.signer.js");
const { SignerService } = await import("./signer.service.js");

describe("SignerService / LocalKeySigner (BLS key-custody port)", () => {
  const node = { privateKey: "0x" + "00".repeat(31) + "11" } as any;

  it("LocalKeySigner parses 0x-prefixed key and delegates getPublicKey/sign to bls primitives", async () => {
    const s = new LocalKeySigner(node.privateKey);
    expect(s.backend).toBe("local");
    const pk: any = await s.getPublicKey();
    expect(pk.kind).toBe("pk");
    expect(pk.sk).toBeInstanceOf(Uint8Array);
    expect(pk.sk.length).toBe(32);
    expect(pk.sk[31]).toBe(0x11); // last byte of the key
    const sig: any = await s.sign({ point: true });
    expect(sig.kind).toBe("sig");
    expect(sig.mp).toEqual({ point: true });
  });

  it("LocalKeySigner rejects malformed private keys (fail-fast, not silent bad key)", () => {
    expect(() => new LocalKeySigner("0x" + "11".repeat(31))).toThrow(/32 bytes/); // too short (31)
    expect(() => new LocalKeySigner("0x" + "11".repeat(33))).toThrow(/32 bytes/); // too long (33)
    expect(() => new LocalKeySigner("0x" + "0".repeat(63))).toThrow(/32 bytes/); // odd length
    expect(() => new LocalKeySigner("0x" + "zz".repeat(32))).toThrow(/32 bytes/); // non-hex
    expect(() => new LocalKeySigner(node.privateKey)).not.toThrow(); // valid 32-byte key
  });

  it("forNode returns a local signer by default", () => {
    const svc = new SignerService({ get: () => undefined } as any);
    const signer = svc.forNode(node);
    expect(signer.backend).toBe("local");
  });

  it("forNode honors SIGNER_BACKEND=local", () => {
    const svc = new SignerService({ get: () => "local" } as any);
    expect(svc.forNode(node).backend).toBe("local");
  });

  it("forNode throws on an unknown backend (fail-closed, no silent fallback)", () => {
    const svc = new SignerService({ get: () => "kms" } as any);
    expect(() => svc.forNode(node)).toThrow(/unknown SIGNER_BACKEND/);
  });
});
