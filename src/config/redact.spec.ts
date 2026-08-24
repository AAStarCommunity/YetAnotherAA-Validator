import { redactRpcUrl, REDACTED_RPC_URL } from "./redact.js";

describe("redactRpcUrl (CC-49 MEDIUM-3)", () => {
  const SECRETS = ["s3cr3t-api-key", "AbCdEfGh12345", "hunter2"];

  it("keeps protocol + host so the operator can still tell which network is configured", () => {
    expect(redactRpcUrl("https://eth-sepolia.g.alchemy.com/v2/s3cr3t-api-key")).toBe(
      "https://eth-sepolia.g.alchemy.com"
    );
    expect(redactRpcUrl("http://127.0.0.1:8545")).toBe("http://127.0.0.1:8545");
  });

  it("never leaks a path, query, fragment or userinfo credential", () => {
    const urls = [
      "https://eth-sepolia.g.alchemy.com/v2/s3cr3t-api-key",
      "https://mainnet.infura.io/v3/AbCdEfGh12345",
      "https://rpc.example.com/?apiKey=s3cr3t-api-key",
      "https://rpc.example.com/#s3cr3t-api-key",
      "https://user:hunter2@rpc.example.com/v2/AbCdEfGh12345",
      "wss://rpc.example.com/ws/s3cr3t-api-key",
    ];
    for (const url of urls) {
      const redacted = redactRpcUrl(url);
      for (const secret of SECRETS) {
        expect(redacted).not.toContain(secret);
      }
      expect(redacted).not.toContain("?");
      expect(redacted).not.toContain("#");
      expect(redacted).not.toContain("@");
      // No path segment survives beyond the host.
      expect(redacted.split("//")[1]).not.toContain("/");
    }
  });

  it("collapses unset or unparseable values to a fixed sentinel instead of echoing them", () => {
    expect(redactRpcUrl(undefined)).toBe(REDACTED_RPC_URL);
    expect(redactRpcUrl("")).toBe(REDACTED_RPC_URL);
    expect(redactRpcUrl("not a url s3cr3t-api-key")).toBe(REDACTED_RPC_URL);
    expect(redactRpcUrl("not a url s3cr3t-api-key")).not.toContain("s3cr3t");
  });
});
