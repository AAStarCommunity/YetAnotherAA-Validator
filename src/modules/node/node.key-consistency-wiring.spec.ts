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
      expect(startFn).toHaveBeenCalledWith(
        expect.objectContaining({ nodeId: "0x1" }),
        "0xcontract"
      );
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

/**
 * CC-36 round 2 (High-2): the self-check is bound to one node identity. dashboard.service.ts
 * calls reloadNodeState() after every create/import/delete — it must restart the check
 * against the NEW identity, or stop + clear it entirely when the node was deleted, so
 * /health never keeps confidently reporting a status for an identity that no longer exists.
 */
describe("NodeService — reloadNodeState() restarts/stops the self-check on identity change (CC-36 round 2)", () => {
  const makeState = (nodeId: string) => ({
    nodeId,
    nodeName: "n",
    publicKey: "0xabcd",
    createdAt: "t",
    description: "d",
    privateKey: "0x" + "1".padStart(64, "0"),
  });

  const makeSvc = (
    file: string,
    keyConsistencyService: {
      start: jest.Mock;
      stop: jest.Mock;
      clearResult: jest.Mock;
      getLastResult: () => null;
    }
  ) => {
    const config = {
      get: (k: string) => (k === "validatorContractAddress" ? "0xcontract" : undefined),
    } as unknown as ConfigService;
    const svc = new NodeService({} as any, {} as any, config, keyConsistencyService as any);
    (svc as any).nodeStateFilePath = file;
    (svc as any).contractAddress = "0xcontract"; // normally set by initializeNode() before boot
    return svc;
  };

  it("create: reloadNodeState() starts the check against the newly-created identity", () => {
    const dir = mkdtempSync(join(tmpdir(), "kc-reload-"));
    const file = join(dir, "node_state.json");
    const start = jest.fn();
    const stop = jest.fn();
    const clearResult = jest.fn();
    const svc = makeSvc(file, { start, stop, clearResult, getLastResult: () => null });

    try {
      // No node yet — the file doesn't exist. reloadNodeState() must stop+clear, not start.
      svc.reloadNodeState();
      expect(start).not.toHaveBeenCalled();
      expect(stop).toHaveBeenCalledTimes(1);
      expect(clearResult).toHaveBeenCalledTimes(1);

      // Dashboard "create" writes node_state.json, then calls reloadNodeState().
      writeFileSync(file, JSON.stringify(makeState("0xnew")));
      svc.reloadNodeState();
      expect(start).toHaveBeenCalledTimes(1);
      expect(start).toHaveBeenCalledWith(
        expect.objectContaining({ nodeId: "0xnew" }),
        "0xcontract"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("delete: reloadNodeState() stops the check and clears its result — /health must not keep a stale identity's ok", () => {
    const dir = mkdtempSync(join(tmpdir(), "kc-reload-"));
    const file = join(dir, "node_state.json");
    writeFileSync(file, JSON.stringify(makeState("0xold")));
    const start = jest.fn();
    const stop = jest.fn();
    const clearResult = jest.fn();
    const svc = makeSvc(file, { start, stop, clearResult, getLastResult: () => null });

    try {
      svc.reloadNodeState(); // node exists -> start()
      expect(start).toHaveBeenCalledTimes(1);
      expect(stop).not.toHaveBeenCalled();

      // Dashboard "delete" removes node_state.json, then calls reloadNodeState().
      rmSync(file);
      svc.reloadNodeState();
      expect(stop).toHaveBeenCalledTimes(1);
      expect(clearResult).toHaveBeenCalledTimes(1);
      expect(start).toHaveBeenCalledTimes(1); // not called again — still just the one from before
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("replace: reloadNodeState() restarts the check against the NEW identity, never the old one", () => {
    const dir = mkdtempSync(join(tmpdir(), "kc-reload-"));
    const file = join(dir, "node_state.json");
    writeFileSync(file, JSON.stringify(makeState("0xold")));
    const start = jest.fn();
    const svc = makeSvc(file, {
      start,
      stop: jest.fn(),
      clearResult: jest.fn(),
      getLastResult: () => null,
    });

    try {
      svc.reloadNodeState();
      expect(start).toHaveBeenLastCalledWith(
        expect.objectContaining({ nodeId: "0xold" }),
        "0xcontract"
      );

      // A delete followed by an import with a DIFFERENT identity (the dashboard's replace flow).
      rmSync(file);
      writeFileSync(file, JSON.stringify(makeState("0xnew")));
      svc.reloadNodeState();
      expect(start).toHaveBeenLastCalledWith(
        expect.objectContaining({ nodeId: "0xnew" }),
        "0xcontract"
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
