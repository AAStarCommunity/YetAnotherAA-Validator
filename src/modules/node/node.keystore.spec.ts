import { jest } from "@jest/globals";
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { ConfigService } from "@nestjs/config";
import { NodeService } from "./node.service.js";
import { encryptKeystore } from "../../utils/keystore.util.js";

/**
 * #5 — node.service loads its BLS key from an EIP-2335 keystore (NODE_KEY_PASSPHRASE)
 * and NEVER writes the decrypted plaintext back to disk. Exercises the private
 * resolvePrivateKey / saveNodeState via a temp node_state.json (no NestJS bootstrap).
 */
describe("NodeService — EIP-2335 keystore load (#5)", () => {
  const SK_HEX = "0000000000000000000000000000000000000000000000000000000000000001";
  const PASS = "corr3ct-h0rse";

  const makeService = (passphrase?: string): NodeService => {
    const config = {
      get: (k: string) =>
        k === "keyPassphrase" ? passphrase : k === "validatorContractAddress" ? "0x00" : undefined,
    } as unknown as ConfigService;
    // BlsService/BlockchainService are unused on the load path we test.
    return new NodeService({} as any, {} as any, config);
  };

  const withState = (
    state: object,
    fn: (svc: NodeService, file: string) => void,
    pass?: string
  ) => {
    const dir = mkdtempSync(join(tmpdir(), "ks-"));
    const file = join(dir, "node_state.json");
    writeFileSync(file, JSON.stringify(state));
    const svc = makeService(pass);
    (svc as any).nodeStateFilePath = file;
    try {
      fn(svc, file);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };

  const keystoreState = () => ({
    nodeId: "0xabc",
    nodeName: "n",
    publicKey: "0x97f1",
    createdAt: "t",
    description: "d",
    keystore: encryptKeystore(Buffer.from(SK_HEX, "hex"), PASS, { kdf: "pbkdf2" }),
  });

  it("decrypts the keystore with the passphrase and populates privateKey", () => {
    withState(
      keystoreState(),
      svc => {
        (svc as any).loadExistingNodeState();
        expect((svc as any).nodeState.privateKey).toBe("0x" + SK_HEX);
      },
      PASS
    );
  });

  it("fails closed when the keystore has no passphrase", () => {
    withState(keystoreState(), svc => {
      expect(() => (svc as any).loadExistingNodeState()).toThrow(/NODE_KEY_PASSPHRASE is not set/);
    });
  });

  it("fails closed on a wrong passphrase (checksum mismatch)", () => {
    withState(
      keystoreState(),
      svc => {
        expect(() => (svc as any).loadExistingNodeState()).toThrow(/wrong passphrase/i);
      },
      "nope"
    );
  });

  it("saveNodeState NEVER writes the decrypted plaintext key back to disk", () => {
    withState(
      keystoreState(),
      (svc, file) => {
        (svc as any).loadExistingNodeState(); // populates in-memory privateKey
        expect((svc as any).nodeState.privateKey).toBe("0x" + SK_HEX);
        (svc as any).saveNodeState();
        const onDisk = JSON.parse(readFileSync(file, "utf8"));
        expect(onDisk.privateKey).toBeUndefined(); // the whole point
        expect(onDisk.keystore?.version).toBe(4);
      },
      PASS
    );
  });

  it("still supports a plaintext privateKey (dev/legacy)", () => {
    withState(
      {
        nodeId: "0x1",
        nodeName: "n",
        publicKey: "0x",
        createdAt: "t",
        description: "d",
        privateKey: "0x" + SK_HEX,
      },
      svc => {
        (svc as any).loadExistingNodeState();
        expect((svc as any).nodeState.privateKey).toBe("0x" + SK_HEX);
      }
    );
  });

  // ── KMS-TEE (merged) mode: key-less node_state, BLS key sealed in the TEE ──────────
  const withStateCfg = (
    state: object,
    cfg: Record<string, unknown>,
    fn: (svc: NodeService) => void
  ) => {
    const dir = mkdtempSync(join(tmpdir(), "ks-"));
    const file = join(dir, "node_state.json");
    writeFileSync(file, JSON.stringify(state));
    const config = { get: (k: string) => cfg[k] } as unknown as ConfigService;
    const svc = new NodeService({} as any, {} as any, config);
    (svc as any).nodeStateFilePath = file;
    try {
      fn(svc);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };
  const keylessState = () => ({
    nodeId: "0x1",
    nodeName: "n",
    publicKey: "0xabcd",
    description: "d",
  });

  it("KMS-TEE: key-less node_state boots when RUST_SIGNER_URL + RUST_SIGNER_REQUIRED=true", () => {
    withStateCfg(
      keylessState(),
      { rustSignerUrl: "http://127.0.0.1:3100", rustSignerRequired: true },
      svc => {
        expect(() => (svc as any).loadExistingNodeState()).not.toThrow();
        expect((svc as any).nodeState.privateKey).toBeUndefined(); // key stays in the TEE
        expect((svc as any).nodeState.publicKey).toBe("0xabcd");
      }
    );
  });

  it("KMS-TEE: key-less node_state FAILS CLOSED without RUST_SIGNER_REQUIRED (could not sign)", () => {
    withStateCfg(keylessState(), { rustSignerUrl: "http://127.0.0.1:3100" }, svc => {
      expect(() => (svc as any).loadExistingNodeState()).toThrow(
        /neither a keystore nor a plaintext privateKey/
      );
    });
    // and with neither url nor required set
    withStateCfg(keylessState(), {}, svc => {
      expect(() => (svc as any).loadExistingNodeState()).toThrow(
        /neither a keystore nor a plaintext privateKey/
      );
    });
  });

  it("KMS-TEE: delegated but NO publicKey → throws (pubkey still needed for nodeId/announce)", () => {
    withStateCfg(
      { nodeId: "0x1", nodeName: "n", description: "d" },
      { rustSignerUrl: "http://127.0.0.1:3100", rustSignerRequired: true },
      svc => {
        expect(() => (svc as any).loadExistingNodeState()).toThrow(/still needs the publicKey/);
      }
    );
  });
});
