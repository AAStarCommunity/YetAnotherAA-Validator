import { ethers } from "ethers";
import { BlockchainService, decodeStrictBlsPublicKey } from "./blockchain.service.js";
import {
  clearRegisteredSecrets,
  registerSensitiveUrl,
  scrubProviderError,
  scrubSecrets,
} from "../../config/redact.js";

/**
 * CC-49 round-3 MEDIUM — `getBlsPublicKeyAtSlotStrict` exercised through a REAL
 * `ethers.JsonRpcProvider` and a REAL `ethers.Contract`, not a stubbed service method.
 *
 * The reader exists for a NEGATIVE check: "this key is not registered on the production
 * aggregator, so signing with it cannot produce a portable slash proof". For that direction a
 * `null` means "absent" and lets the signature through, so every non-answer — a transport
 * failure, a 401/429, a decoy contract returning the wrong shape, a truncated word — must
 * THROW instead. Only a genuine empty/inactive registration may return `null`.
 *
 * The transport is faked at the HTTP layer (`FetchRequest.getUrlFunc`), so ABI encoding,
 * JSON-RPC framing, decoding and ethers' own error wrapping all run for real.
 */
const AGGREGATOR = "0x" + "ab".repeat(20);
const VALIDATOR = "0x" + "cd".repeat(20);
const KEY_WORD = (n: number) => "0x" + n.toString(16).padStart(2, "0").repeat(32);
const RPC_KEY = "sUp3rS3cr3tProviderKey";
const RPC_URL = `https://rpc.example.test/v2/${RPC_KEY}`;

const IFACE = new ethers.Interface([
  "function validatorAtSlot(uint8 slot) view returns (address)",
  "function getBLSPublicKey(address validator) view returns (tuple(bytes32 x_a, bytes32 x_b, bytes32 y_a, bytes32 y_b) publicKey, uint8 slot, bool isActive)",
]);

type CallHandler = (fn: string, args: readonly unknown[]) => string | { httpStatus: number };

/** A BlockchainService whose provider is a real JsonRpcProvider over a scripted transport. */
function serviceWith(handler: CallHandler): BlockchainService {
  const request = new ethers.FetchRequest(RPC_URL);
  request.getUrlFunc = async req => {
    const payload = JSON.parse(Buffer.from(req.body ?? new Uint8Array()).toString("utf8"));
    const calls = Array.isArray(payload) ? payload : [payload];
    const results: unknown[] = [];
    for (const call of calls) {
      const data: string = call.params?.[0]?.data ?? "0x";
      const parsed = IFACE.parseTransaction({ data });
      const outcome = handler(parsed?.name ?? "", parsed?.args ?? []);
      if (typeof outcome !== "string") {
        // A provider-level failure (401/429). ethers wraps this into an Error whose message
        // embeds the request URL — which is exactly the leak this suite also pins.
        return {
          statusCode: outcome.httpStatus,
          statusMessage: "Unauthorized",
          headers: {} as Record<string, string>,
          body: Buffer.from(JSON.stringify({ error: "nope" }), "utf8"),
        };
      }
      results.push({ jsonrpc: "2.0", id: call.id, result: outcome });
    }
    return {
      statusCode: 200,
      statusMessage: "OK",
      headers: { "content-type": "application/json" },
      body: Buffer.from(JSON.stringify(Array.isArray(payload) ? results : results[0]), "utf8"),
    };
  };
  const provider = new ethers.JsonRpcProvider(request, 31337, { staticNetwork: true });
  const service = new BlockchainService({ get: () => undefined } as any);
  (service as any).provider = provider;
  return service;
}

function encodeKey(words: string[], isActive: boolean, slot = 1): string {
  return IFACE.encodeFunctionResult("getBLSPublicKey", [words, slot, isActive]);
}

const ACTIVE_WORDS = [KEY_WORD(0x11), KEY_WORD(0x22), KEY_WORD(0x33), KEY_WORD(0x44)];

describe("getBlsPublicKeyAtSlotStrict over a real provider (CC-49 round-3 MEDIUM)", () => {
  it("returns the concatenated lowercase key for an active registration", async () => {
    const service = serviceWith(fn =>
      fn === "validatorAtSlot"
        ? IFACE.encodeFunctionResult("validatorAtSlot", [VALIDATOR])
        : encodeKey(ACTIVE_WORDS, true)
    );
    await expect(service.getBlsPublicKeyAtSlotStrict(AGGREGATOR, 1)).resolves.toBe(
      ("0x" + ACTIVE_WORDS.map(w => w.slice(2)).join("")).toLowerCase()
    );
  });

  it("returns null for a genuinely empty slot — the ONE legitimate null", async () => {
    const service = serviceWith(fn =>
      fn === "validatorAtSlot"
        ? IFACE.encodeFunctionResult("validatorAtSlot", [ethers.ZeroAddress])
        : encodeKey(ACTIVE_WORDS, true)
    );
    await expect(service.getBlsPublicKeyAtSlotStrict(AGGREGATOR, 7)).resolves.toBeNull();
  });

  it("returns null for a registered but inactive validator", async () => {
    const service = serviceWith(fn =>
      fn === "validatorAtSlot"
        ? IFACE.encodeFunctionResult("validatorAtSlot", [VALIDATOR])
        : encodeKey(ACTIVE_WORDS, false)
    );
    await expect(service.getBlsPublicKeyAtSlotStrict(AGGREGATOR, 1)).resolves.toBeNull();
  });

  it("THROWS on a provider failure instead of reporting the key as absent", async () => {
    const service = serviceWith(() => ({ httpStatus: 401 }));
    await expect(service.getBlsPublicKeyAtSlotStrict(AGGREGATOR, 1)).rejects.toThrow();
  });

  it("THROWS on a truncated/undecodable getBLSPublicKey response", async () => {
    const service = serviceWith(
      fn =>
        fn === "validatorAtSlot"
          ? IFACE.encodeFunctionResult("validatorAtSlot", [VALIDATOR])
          : "0x" + "11".repeat(64) // too short for (tuple, uint8, bool)
    );
    await expect(service.getBlsPublicKeyAtSlotStrict(AGGREGATOR, 1)).rejects.toThrow();
  });

  it("THROWS when a decoy contract answers validatorAtSlot with garbage", async () => {
    const service = serviceWith(() => "0x");
    await expect(service.getBlsPublicKeyAtSlotStrict(AGGREGATOR, 1)).rejects.toThrow();
  });

  it("THROWS on an out-of-range slot before spending a read", async () => {
    const service = serviceWith(() => {
      throw new Error("must not be reached");
    });
    for (const slot of [0, -1, 1.5, NaN, 256]) {
      await expect(service.getBlsPublicKeyAtSlotStrict(AGGREGATOR, slot)).rejects.toThrow(
        /invalid slot/
      );
    }
  });

  it("never lets the RPC credential reach a log line via the thrown provider error", async () => {
    clearRegisteredSecrets();
    registerSensitiveUrl(RPC_URL);
    try {
      const service = serviceWith(() => ({ httpStatus: 401 }));
      const error = await service.getBlsPublicKeyAtSlotStrict(AGGREGATOR, 1).catch(e => e);
      // The raw ethers error DOES carry the URL — that is the leak being closed.
      expect(String((error as Error).message)).toContain(RPC_KEY);
      // Everything the node logs goes through the scrubber first.
      const logged = scrubProviderError(error);
      expect(logged).not.toContain(RPC_KEY);
      expect(logged).not.toContain("/v2/");
      // ethers exposes a URL-free `shortMessage`, which the scrubber prefers; the verbose
      // `message` still keeps its host (useful) and loses the credential (required).
      expect(logged).toContain("401");
      const scrubbedLongForm = scrubSecrets((error as Error).message);
      expect(scrubbedLongForm).not.toContain(RPC_KEY);
      expect(scrubbedLongForm).toContain("rpc.example.test");
    } finally {
      clearRegisteredSecrets();
    }
  });
});

/**
 * Shapes a decoy or upgraded contract can return that a real ABI decode would never produce,
 * so they are pinned directly on the decoder. Each one used to be — or would naturally become
 * — a silent `null`, i.e. "the key is not on this aggregator, go ahead and sign".
 */
describe("decodeStrictBlsPublicKey malformed shapes (CC-49 round-3 MEDIUM)", () => {
  const ok = { publicKey: ACTIVE_WORDS, isActive: true };

  it("decodes the happy path", () => {
    expect(decodeStrictBlsPublicKey(ok, 1, AGGREGATOR)).toBe(
      ("0x" + ACTIVE_WORDS.map(w => w.slice(2)).join("")).toLowerCase()
    );
  });

  it("returns null ONLY for an explicit isActive === false", () => {
    expect(decodeStrictBlsPublicKey({ ...ok, isActive: false }, 1, AGGREGATOR)).toBeNull();
  });

  it("throws when isActive is undefined rather than treating it as inactive", () => {
    expect(() => decodeStrictBlsPublicKey({ publicKey: ACTIVE_WORDS }, 3, AGGREGATOR)).toThrow(
      /isActive/
    );
  });

  it("throws for a truthy-but-not-boolean isActive", () => {
    for (const isActive of [1, "true", {}, null]) {
      expect(() => decodeStrictBlsPublicKey({ ...ok, isActive }, 3, AGGREGATOR)).toThrow(
        /isActive/
      );
    }
  });

  it("throws on an empty or absent response", () => {
    for (const res of [null, undefined]) {
      expect(() => decodeStrictBlsPublicKey(res, 1, AGGREGATOR)).toThrow();
    }
  });

  it("throws when the key words are missing, short, over-long or non-string", () => {
    const bad: unknown[][] = [
      [KEY_WORD(0x11), KEY_WORD(0x22), KEY_WORD(0x33)], // only three words
      [KEY_WORD(0x11), KEY_WORD(0x22), KEY_WORD(0x33), "0x1234"], // short word
      [KEY_WORD(0x11), KEY_WORD(0x22), KEY_WORD(0x33), KEY_WORD(0x44) + "ff"], // over-long
      [KEY_WORD(0x11), KEY_WORD(0x22), KEY_WORD(0x33), undefined],
      [KEY_WORD(0x11), KEY_WORD(0x22), KEY_WORD(0x33), 42],
      [KEY_WORD(0x11), KEY_WORD(0x22), KEY_WORD(0x33), "0x" + "zz".repeat(32)], // non-hex
    ];
    for (const words of bad) {
      expect(() =>
        decodeStrictBlsPublicKey({ publicKey: words, isActive: true }, 5, AGGREGATOR)
      ).toThrow(/malformed BLS public key words/);
    }
    expect(() => decodeStrictBlsPublicKey({ isActive: true }, 5, AGGREGATOR)).toThrow();
  });
});
