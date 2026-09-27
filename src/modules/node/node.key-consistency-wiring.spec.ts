import { jest } from "@jest/globals";
import { mkdtempSync, writeFileSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";
import { ConfigService } from "@nestjs/config";
import { NodeService } from "./node.service.js";

/**
 * CC-36 wiring: NodeService kicks off the key-consistency self-check's self-scheduling
 * loop (`start()`) after loading node_state.json — synchronously, never awaited (startup
 * must never block on a slow/unavailable RPC) — and exposes the last result via
 * getKeyConsistency(). The check's own branch coverage (ok/mismatch_local/mismatch_onchain/
 * not_registered/unknown/skipped) lives in node-key-consistency.service.spec.ts, and its
 * retry/backoff/recheck scheduling lives in node-key-consistency.service.scheduling.spec.ts.
 * This file only covers the NodeService glue.
 */
describe("NodeService — key-consistency self-check wiring (CC-36)", () => {
  const nodeState = {
    nodeId: "0x1",
    nodeName: "n",
    publicKey: "0xabcd",
    createdAt: "t",
    description: "d",
    privateKey: "0x" + "1".padStart(64, "0"),
  };

  it("calls start() once after loading node state, and initializeNode does not wait on it", async () => {
    const dir = mkdtempSync(join(tmpdir(), "kc-"));
    const file = join(dir, "node_state.json");
    writeFileSync(file, JSON.stringify(nodeState));
    const config = {
      get: (k: string) => (k === "validatorContractAddress" ? "0xcontract" : undefined),
    } as unknown as ConfigService;

    const startFn = jest.fn();
    const keyConsistencyService = { start: startFn, getLastResult: () => null } as any;

    const svc = new NodeService({} as any, {} as any, config, keyConsistencyService);
    // initializeNode() recomputes nodeStateFilePath from process.cwd() (fixed-name
    // convention), so point cwd at the temp dir rather than poking the private field —
    // this exercises the same path onModuleInit() takes in production.
    const cwdSpy = jest.spyOn(process, "cwd").mockReturnValue(dir);

    try {
      await (svc as any).initializeNode();
      expect(startFn).toHaveBeenCalledTimes(1);
      expect(startFn).toHaveBeenCalledWith(expect.objectContaining({ nodeId: "0x1" }), "0xcontract");
    } finally {
      cwdSpy.mockRestore();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("getKeyConsistency() delegates to the injected service's getLastResult()", () => {
    const fakeResult = { status: "ok", checkedAt: "t", derivedMatches: true, nodeId: "0x1" } as any;
    const keyConsistencyService = {
      start: jest.fn(),
      getLastResult: () => fakeResult,
    } as any;
    const config = { get: () => undefined } as unknown as ConfigService;
    const svc = new NodeService({} as any, {} as any, config, keyConsistencyService);
    expect(svc.getKeyConsistency()).toBe(fakeResult);
  });

  it("getKeyConsistency() returns null when no consistency service is wired (defensive @Optional())", () => {
    const config = { get: () => undefined } as unknown as ConfigService;
    const svc = new NodeService({} as any, {} as any, config);
    expect(svc.getKeyConsistency()).toBeNull();
  });

  it("never throws from initializeNode when start() itself throws synchronously", async () => {
    const dir = mkdtempSync(join(tmpdir(), "kc-"));
    const file = join(dir, "node_state.json");
    writeFileSync(file, JSON.stringify(nodeState));
    const config = {
      get: (k: string) => (k === "validatorContractAddress" ? "0xcontract" : undefined),
    } as unknown as ConfigService;
    const keyConsistencyService = {
      start: jest.fn(() => {
        throw new Error("boom — should never happen");
      }),
      getLastResult: () => null,
    } as any;
    const svc = new NodeService({} as any, {} as any, config, keyConsistencyService);
    const cwdSpy = jest.spyOn(process, "cwd").mockReturnValue(dir);
    try {
      await expect((svc as any).initializeNode()).resolves.toBeUndefined();
    } finally {
      cwdSpy.mockRestore();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
