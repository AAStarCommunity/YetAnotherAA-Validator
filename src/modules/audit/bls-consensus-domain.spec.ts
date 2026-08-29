import { ethers } from "ethers";
import {
  domainSeparator,
  executeSlashMessageHash,
  signersCommitment,
} from "./bls-consensus-domain.js";

// The plain-ESM encoding the cc89-cosign.mjs script imports — pinned equal to the TS helper below.
// Loaded via a variable-path dynamic import so tsc does not pull a file outside `src` into the
// program (rootDir), while jest's ESM loader still resolves it at runtime.
type ScriptEncoding = {
  domainSeparator: (d: unknown) => string;
  executeSlashMessageHash: (...a: unknown[]) => string;
  overIssueEvidenceHash: (t: string, o: string, e: bigint) => string;
};
let scriptLib: ScriptEncoding;
beforeAll(async () => {
  const p = "../../../scripts/lib/bls-consensus-encoding.mjs";
  scriptLib = (await import(p)) as ScriptEncoding;
});

const S1 = ethers.getAddress("0x0000000000000000000000000000000000001111");
const S2 = ethers.getAddress("0x0000000000000000000000000000000000002222");
const S3 = ethers.getAddress("0x0000000000000000000000000000000000003333");
const OPERATOR = ethers.getAddress("0x000000000000000000000000000000000000abcd");
const TOKEN = ethers.getAddress("0x000000000000000000000000000000000000beef");
const DOMAIN = {
  chainId: 11155111n,
  aggregator: ethers.getAddress("0x00000000000000000000000000000000000000a9"),
  registry: ethers.getAddress("0x00000000000000000000000000000000000000b5"),
};

describe("bls-consensus-domain helper", () => {
  // ── fix 5: canonical signer order is enforced, not assumed ──────────────
  describe("signersCommitment canonical-order enforcement", () => {
    const mh = "0x" + "cd".repeat(32);

    it("accepts strictly-ascending signers and is order-deterministic", () => {
      const sorted = signersCommitment(DOMAIN, 42n, mh, 0x7n, [S1, S2, S3]);
      expect(sorted).toMatch(/^0x[0-9a-f]{64}$/);
      // Recomputing with the same sorted input is identical.
      expect(signersCommitment(DOMAIN, 42n, mh, 0x7n, [S1, S2, S3])).toBe(sorted);
    });

    it("REJECTS slot-order (unsorted) input rather than silently producing a wrong commitment", () => {
      // e.g. [0x3333, 0x1111, 0x2222] — a caller passing raw slot order. SP sorts internally, so
      // this would yield a different, always-failing commitment; the helper must refuse it.
      expect(() => signersCommitment(DOMAIN, 42n, mh, 0x7n, [S3, S1, S2])).toThrow(
        /not strictly ascending/
      );
    });

    it("REJECTS duplicate and zero-address signers", () => {
      expect(() => signersCommitment(DOMAIN, 42n, mh, 0x7n, [S1, S1])).toThrow(
        /not strictly ascending/
      );
      expect(() => signersCommitment(DOMAIN, 42n, mh, 0x7n, [ethers.ZeroAddress, S1])).toThrow(
        /zero address/
      );
    });
  });

  // ── fix 3: the cc89-cosign.mjs encoding lib stays byte-identical to the TS helper ──
  describe("cross-language single-source (script .mjs == TS helper)", () => {
    const evidenceHash = ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ["string", "address", "address", "uint256"],
        ["DVT_OVERISSUE_EVIDENCE_V1", TOKEN, OPERATOR, 1000n]
      )
    );

    it("domainSeparator matches", () => {
      expect(scriptLib.domainSeparator(DOMAIN)).toBe(domainSeparator(DOMAIN));
    });

    it("executeSlashMessageHash matches AND equals the pinned golden vector", () => {
      const viaScript = scriptLib.executeSlashMessageHash(
        DOMAIN,
        42n,
        OPERATOR,
        2,
        1000n,
        evidenceHash
      );
      const viaHelper = executeSlashMessageHash(DOMAIN, 42n, OPERATOR, 2, 1000n, evidenceHash);
      expect(viaScript).toBe(viaHelper);
      // Same golden pinned in guardian-fraud-proof.spec.ts + Foundry test_Golden_CrossLanguage_SPLayout.
      expect(viaScript).toBe("0x7e794aa98ce38cd7e22a456963f67a1a7de057e15ee261a62373af7516cb820d");
    });

    it("overIssueEvidenceHash matches the DVT convention", () => {
      expect(scriptLib.overIssueEvidenceHash(TOKEN, OPERATOR, 1000n)).toBe(evidenceHash);
    });
  });
});
