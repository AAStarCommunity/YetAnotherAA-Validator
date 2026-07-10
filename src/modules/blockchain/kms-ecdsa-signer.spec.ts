import { describe, it, expect, jest } from "@jest/globals";
import { ethers } from "ethers";
import { KmsEcdsaSigner } from "./kms-ecdsa-signer.js";

/**
 * The KMS TEE holds the real key; here a local ethers.Wallet stands in for it. The mock KMS
 * signs the exact 32-byte digest KmsEcdsaSigner sends (KMS "does not hash"), so if our digest
 * computation + {r,s,v} assembly is correct, the output is BYTE-IDENTICAL to what the Wallet
 * would have produced directly. That equality is the golden `ecrecover(digest,sig)==address`
 * invariant KMS golden-tests against on hardware (CC-34).
 */
const KEY = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
const wallet = new ethers.Wallet(KEY);
const URL = "http://127.0.0.1:3100";
const TOKEN = "keeper-token-abc";

/** A mock KMS /kms/sign that signs the incoming digest with `signWith` and reports `reportAddr`. */
function mockKms(opts?: { signWith?: ethers.SigningKey; reportAddr?: string; captured?: any }) {
  const signWith = opts?.signWith ?? wallet.signingKey;
  const reportAddr = opts?.reportAddr ?? wallet.address;
  return jest.fn(async (url: any, init: any) => {
    const body = JSON.parse(init.body);
    if (opts?.captured) {
      opts.captured.url = url;
      opts.captured.headers = init.headers;
      opts.captured.body = body;
    }
    const sig = signWith.sign(body.digest);
    return {
      ok: true,
      status: 200,
      json: async () => ({ signature: sig.serialized, address: reportAddr }),
    } as any;
  }) as unknown as typeof fetch;
}

function signer(fetchImpl: typeof fetch, over?: Partial<{ token: string; address: string }>) {
  return new KmsEcdsaSigner({
    url: URL,
    address: over?.address ?? wallet.address,
    token: over?.token ?? TOKEN,
    fetchImpl,
  });
}

describe("KmsEcdsaSigner", () => {
  it("getAddress returns the configured keeper EOA (checksummed)", async () => {
    expect(await signer(mockKms()).getAddress()).toBe(wallet.address);
  });

  it("signMessage is byte-identical to ethers.Wallet", async () => {
    const s = signer(mockKms());
    const msg = "co-sign this liveness attest";
    expect(await s.signMessage(msg)).toBe(await wallet.signMessage(msg));
    // and recovers to the keeper EOA
    expect(ethers.verifyMessage(msg, await s.signMessage(msg))).toBe(wallet.address);
  });

  it("signTransaction is byte-identical to ethers.Wallet (EIP-1559)", async () => {
    const tx: ethers.TransactionRequest = {
      to: "0x539B9681aFd5BFbCaa655Fe4c6BdcFe1fa7864bC",
      value: 0n,
      data: "0x1234",
      nonce: 7,
      gasLimit: 120000n,
      maxFeePerGas: 30_000_000_000n,
      maxPriorityFeePerGas: 1_000_000_000n,
      chainId: 11155111,
      type: 2,
    };
    const fromKms = await signer(mockKms()).signTransaction(tx);
    expect(fromKms).toBe(await wallet.signTransaction(tx));
    // the serialized tx recovers to the keeper EOA
    expect(ethers.Transaction.from(fromKms).from).toBe(wallet.address);
  });

  it("sends the digest (not the message) + X-Signer-Token, and asks KMS not to hash", async () => {
    const captured: any = {};
    const s = signer(mockKms({ captured }));
    const msg = "hello";
    await s.signMessage(msg);
    expect(captured.body.digest).toBe(ethers.hashMessage(msg)); // 32B digest, KMS won't re-hash
    expect(captured.headers["X-Signer-Token"]).toBe(TOKEN);
    expect(captured.url).toBe(`${URL}/kms/sign`);
  });

  it("omits X-Signer-Token when no token configured", async () => {
    const captured: any = {};
    const s = new KmsEcdsaSigner({
      url: URL,
      address: wallet.address,
      fetchImpl: mockKms({ captured }),
    });
    await s.signMessage("x");
    expect(captured.headers["X-Signer-Token"]).toBeUndefined();
  });

  it("rejects when KMS reports a different address (wrong board key)", async () => {
    const other = ethers.Wallet.createRandom().address;
    await expect(signer(mockKms({ reportAddr: other })).signMessage("x")).rejects.toThrow(
      /address mismatch/i
    );
  });

  it("rejects when the signature does not recover to the keeper EOA", async () => {
    // KMS signs with a DIFFERENT key but (buggily) still claims our address → must be caught.
    const rogue = ethers.Wallet.createRandom().signingKey;
    await expect(
      signer(mockKms({ signWith: rogue, reportAddr: wallet.address })).signMessage("x")
    ).rejects.toThrow(/does not recover/i);
  });

  it("rejects a non-2xx KMS response (fail-closed)", async () => {
    const badFetch = jest.fn(async () => ({
      ok: false,
      status: 403,
      json: async () => ({}),
    })) as any;
    await expect(signer(badFetch).signMessage("x")).rejects.toThrow(/HTTP 403/);
  });

  it("rejects a malformed keeper address at construction", () => {
    expect(() => signer(mockKms(), { address: "not-an-address" })).toThrow();
  });
});
