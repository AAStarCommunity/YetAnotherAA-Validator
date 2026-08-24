import {
  clearRegisteredSecrets,
  redactRpcUrl,
  REDACTED_RPC_URL,
  registerSensitiveUrl,
  scrubProviderError,
  scrubSecrets,
} from "./redact.js";

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

/**
 * CC-49 round-3 HIGH. ethers embeds the full request URL in the Error it raises for a non-2xx
 * or transport-level provider failure, so `logger.error(error.message)` on any RPC path writes
 * the provider API key into stdout/journald/a log shipper on exactly the 401/429/transport
 * failures an operator is most likely to hit and to paste into a ticket.
 */
describe("scrubProviderError (CC-49 round-3 HIGH)", () => {
  const KEY = "sUp3rS3cr3tAlchemyKey";
  const RPC = `https://eth-sepolia.g.alchemy.com/v2/${KEY}`;

  beforeEach(() => {
    clearRegisteredSecrets();
    registerSensitiveUrl(RPC);
  });
  afterEach(() => clearRegisteredSecrets());

  /** Shapes ethers v6 actually produces, transcribed from real failures. */
  const providerErrors: Array<[string, unknown]> = [
    [
      "401 from the provider",
      new Error(
        `server response 401 Unauthorized (request={ "method": "eth_call" }, ` +
          `response={ "statusCode": 401 }, url="${RPC}", code=SERVER_ERROR, version=6.17.0)`
      ),
    ],
    [
      "429 rate limit",
      new Error(`could not coalesce error (error={ "code": 429 }, url="${RPC}?apikey=${KEY}")`),
    ],
    [
      "transport failure",
      new Error(`connect ECONNREFUSED - failed to fetch ${RPC} (code=NETWORK_ERROR)`),
    ],
    [
      "userinfo credential",
      new Error(`bad response from https://operator:${KEY}@rpc.example.com/v2/${KEY}`),
    ],
    [
      "shortMessage preferred over message",
      Object.assign(new Error(`long form with ${RPC}`), {
        shortMessage: `server response 401 Unauthorized url="${RPC}"`,
      }),
    ],
  ];

  it.each(providerErrors)("never leaks the API key: %s", (_label, error) => {
    const text = scrubProviderError(error);
    expect(text).not.toContain(KEY);
    expect(text).not.toContain("/v2/");
    expect(text).not.toContain("apikey=");
    expect(text).not.toContain("@rpc.example.com");
  });

  it("keeps the host so the operator can still tell which endpoint failed", () => {
    const text = scrubProviderError(new Error(`server response 401 url="${RPC}"`));
    expect(text).toContain("https://eth-sepolia.g.alchemy.com");
    expect(text).toContain("401");
  });

  it("scrubs a registered credential echoed back without its scheme", () => {
    // Some providers echo just the path, or the key alone, in the error body.
    expect(scrubSecrets(`upstream said: /v2/${KEY}`)).not.toContain(KEY);
    expect(scrubSecrets(`invalid api key: ${KEY}`)).not.toContain(KEY);
  });

  it("registers an unparseable RPC value wholesale rather than assuming it is safe", () => {
    clearRegisteredSecrets();
    registerSensitiveUrl("not-a-url-but-still-a-secret");
    expect(scrubSecrets("boom: not-a-url-but-still-a-secret")).not.toContain("still-a-secret");
  });

  it("leaves ordinary error text intact", () => {
    expect(scrubProviderError(new Error("execution reverted: NotAuthorized"))).toBe(
      "execution reverted: NotAuthorized"
    );
    expect(scrubProviderError(undefined)).toBe("unknown error");
  });

  it("reads only the error's own text, never its request/info payload", () => {
    // ethers attaches the request (including the URL) on `.info`; stringifying the whole
    // error object would leak it even if `message` is clean.
    const error = Object.assign(new Error("could not coalesce error"), {
      info: { url: RPC, request: { url: RPC } },
    });
    expect(scrubProviderError(error)).not.toContain(KEY);
    expect(scrubProviderError(error)).toBe("could not coalesce error");
  });
});
