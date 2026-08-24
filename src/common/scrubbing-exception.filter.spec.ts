import { jest } from "@jest/globals";
import { HttpException, HttpStatus } from "@nestjs/common";
import { BaseExceptionFilter } from "@nestjs/core";
import {
  ScrubbingExceptionFilter,
  scrubExceptionForLogging,
} from "./scrubbing-exception.filter.js";
import { clearRegisteredSecrets, registerSensitiveUrl } from "../config/redact.js";

/**
 * CC-49 round-3 HIGH. A real-process smoke test of the RepCredit endpoints reproduced the leak
 * this filter closes: an upstream RPC 401 returned a clean `500 Internal server error` to the
 * caller and wrote six copies of the live provider API key into the node log, because Nest's
 * own `ExceptionsHandler` logs an unhandled exception's message, stack and (via the inspector)
 * its own enumerable properties — and ethers puts the request URL in all three.
 *
 * The filter must scrub without changing status codes or response bodies, so these tests
 * assert on what `BaseExceptionFilter` is handed.
 */
const KEY = "sUp3rS3cr3tProviderKey";
const RPC = `https://eth-sepolia.g.alchemy.com/v2/${KEY}`;

/** An error shaped like the one ethers v6 raises for a non-2xx provider response. */
function ethersLikeError() {
  const error = new Error(
    `server response 401 Unauthorized (request={ }, info={ "requestUrl": "${RPC}" }, ` +
      `code=SERVER_ERROR, version=6.17.0)`
  );
  error.stack = `Error: server response 401 Unauthorized url="${RPC}"\n    at JsonRpcProvider._send`;
  return Object.assign(error, {
    code: "SERVER_ERROR",
    info: { requestUrl: RPC, responseStatus: "401 Unauthorized" },
    shortMessage: "server response 401 Unauthorized",
  });
}

const capture = scrubExceptionForLogging;

describe("ScrubbingExceptionFilter (CC-49 round-3 HIGH)", () => {
  beforeEach(() => {
    clearRegisteredSecrets();
    registerSensitiveUrl(RPC);
  });
  afterEach(() => clearRegisteredSecrets());

  it("scrubs the message, the stack and info.requestUrl of a provider error", () => {
    const handled = capture(ethersLikeError()) as Error & { info: { requestUrl: string } };
    expect(handled.message).not.toContain(KEY);
    expect(handled.stack).not.toContain(KEY);
    expect(handled.info.requestUrl).not.toContain(KEY);
    // The host survives — the operator still learns which endpoint failed.
    expect(handled.message).toContain("eth-sepolia.g.alchemy.com");
    expect(handled.stack).toContain("JsonRpcProvider._send");
  });

  it("keeps an HttpException's identity so status and body are unchanged", () => {
    const exception = new HttpException("nope", HttpStatus.FORBIDDEN);
    const handled = capture(exception) as HttpException;
    expect(handled).toBe(exception);
    expect(handled.getStatus()).toBe(HttpStatus.FORBIDDEN);
    expect(handled.getResponse()).toBe("nope");
  });

  it("passes clean errors and non-Error values through untouched", () => {
    const clean = new Error("execution reverted: NotAuthorized");
    expect(capture(clean)).toBe(clean);
    expect(capture("a string")).toBe("a string");
    expect(capture(undefined)).toBeUndefined();
  });

  it("hands the SCRUBBED exception to the base filter, which still owns the response", () => {
    const base = jest
      .spyOn(BaseExceptionFilter.prototype, "catch")
      .mockImplementation(() => undefined);
    try {
      const host = {} as any;
      new ScrubbingExceptionFilter().catch(ethersLikeError(), host);
      expect(base).toHaveBeenCalledTimes(1);
      const [handed, passedHost] = base.mock.calls[0];
      expect(String((handed as Error).message)).not.toContain(KEY);
      expect(passedHost).toBe(host);
    } finally {
      base.mockRestore();
    }
  });
});
