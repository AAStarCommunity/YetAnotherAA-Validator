import { ethers } from "ethers";
import { BlockchainService } from "./blockchain.service.js";

/**
 * Focused unit tests for the durable over-slash guard read `getRecentSlashExecuted` (Codex round-2
 * HIGH fail-closed + MEDIUM level-narrowing). BlockchainService is constructed with a stub
 * ConfigService (no RPC dial), then its private `provider` is replaced with a mock exposing only the
 * `getLogs` the method calls.
 */
const CONTRACT = "0x" + "11".repeat(20);
const OPERATOR = "0x" + "22".repeat(20);
const OTHER_OPERATOR = "0x" + "33".repeat(20);

/** SlashExecuted(uint256 indexed proposalId, address indexed operator, uint8 level) — level NON-indexed. */
const SLASH_IFACE = new ethers.Interface([
  "event SlashExecuted(uint256 indexed proposalId, address indexed operator, uint8 level)",
]);

/** Build a real, decodable SlashExecuted log for (proposalId, operator, level). */
function makeSlashExecutedLog(proposalId: bigint, operator: string, level: number) {
  const encoded = SLASH_IFACE.encodeEventLog("SlashExecuted", [proposalId, operator, level]);
  return { topics: encoded.topics, data: encoded.data };
}

/** A BlockchainService whose `provider.getLogs` is the supplied stub. */
function makeService(getLogs: (filter: any) => Promise<any[]>): BlockchainService {
  const config = { get: (_k: string) => undefined } as any;
  const svc = new BlockchainService(config);
  (svc as any).provider = { getLogs };
  return svc;
}

describe("BlockchainService.getRecentSlashExecuted", () => {
  const LEVEL = 1; // SlashLevel.MINOR — the credit-over-limit rule's level.

  it("HIGH fail-closed: a getLogs/provider error returns null (indeterminate), NEVER false", async () => {
    const svc = makeService(async () => {
      throw new Error("RPC range too wide");
    });
    const result = await svc.getRecentSlashExecuted(CONTRACT, OPERATOR, LEVEL, 0);
    // Must be null ("cannot determine"), so the caller fails CLOSED rather than reading "not slashed".
    expect(result).toBeNull();
  });

  it("MEDIUM level-narrowing: a slash for a DIFFERENT level does NOT match (returns false)", async () => {
    // Only a level-2 slash exists; the rule asks about level-1 → no match.
    const svc = makeService(async () => [makeSlashExecutedLog(7n, OPERATOR, 2)]);
    const result = await svc.getRecentSlashExecuted(CONTRACT, OPERATOR, LEVEL, 0);
    expect(result).toBe(false);
  });

  it("a slash for the SAME operator + SAME level matches (returns true)", async () => {
    const svc = makeService(async () => [makeSlashExecutedLog(7n, OPERATOR, LEVEL)]);
    const result = await svc.getRecentSlashExecuted(CONTRACT, OPERATOR, LEVEL, 0);
    expect(result).toBe(true);
  });

  it("a clean scan with no matching logs returns false (determinate 'not slashed')", async () => {
    const svc = makeService(async () => []);
    const result = await svc.getRecentSlashExecuted(CONTRACT, OPERATOR, LEVEL, 0);
    expect(result).toBe(false);
  });

  it("an undecodable log (matched the topic filter but wrong shape) is ignored, not a match", async () => {
    // A log whose topics[0] is neither event's hash → parseLog throws → ignored → false.
    const svc = makeService(async () => [
      { topics: [ethers.id("SomethingElse(uint256)")], data: "0x" },
    ]);
    const result = await svc.getRecentSlashExecuted(CONTRACT, OTHER_OPERATOR, LEVEL, 0);
    expect(result).toBe(false);
  });
});
