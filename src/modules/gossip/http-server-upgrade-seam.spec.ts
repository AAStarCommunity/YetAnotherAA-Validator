import { describe, it, expect, afterEach } from "@jest/globals";
import { Module } from "@nestjs/common";
import { NestFactory } from "@nestjs/core";
import type { INestApplication } from "@nestjs/common";
import * as http from "http";
import { WebSocketServer, WebSocket } from "ws";

// THE SEAM NEST OWNS AND THIS REPO DEPENDS ON, ASSERTED RATHER THAN ASSUMED.
//
// `main.ts:50` hands `app.getHttpServer()` to `GossipService.setHttpServer()`, and
// `gossip.service.ts:257` mounts `new WebSocketServer({ server, path: "/ws" })` on it. The upgrade
// then goes through NEITHER Express NOR Nest: `ws` listens for the Node `http.Server`'s own
// `'upgrade'` event. So the thing this repo relies on is not a framework API, it is that
// `getHttpServer()` keeps returning a real `http.Server` whose upgrade event still fires.
//
// Nothing checked that. The NestJS 11 -> 12 upgrade booted cleanly and answered `GET /health`, which
// reaches the HTTP layer and stops there — a broken upgrade path would have looked exactly the same.
// Neither end of the seam moved in that upgrade (`express` 5.2.1 and `ws` 8.21.3 are unchanged;
// only `platform-express` crossed a major), which is a good argument and not a reading. @clestons
// made both points and asked for the reading; this is it.
//
// Deliberately NOT the three-node gossip stack: that verifies gossip's PROTOCOL behaviour, while what
// changed underneath is where the server object comes from. A handshake is the smallest thing that
// can fail if the seam breaks.
describe("platform-express -> ws upgrade seam", () => {
  let app: INestApplication | undefined;
  let wss: WebSocketServer | undefined;

  afterEach(async () => {
    wss?.close();
    await app?.close();
    app = undefined;
    wss = undefined;
  });

  @Module({})
  class BareModule {}

  it("getHttpServer() returns a Node http.Server that completes a /ws upgrade", async () => {
    // A bare module on purpose: this is about the platform adapter, and pulling in AppModule would
    // drag along env validation that fails the test for reasons that have nothing to do with the seam.
    app = await NestFactory.create(BareModule, { logger: false });

    const server = app.getHttpServer();
    // The type GossipService.setHttpServer declares. If a future adapter returns a wrapper instead,
    // `new WebSocketServer({ server })` would still construct and the upgrade would silently never
    // fire, so the instanceof check is the part that names the failure.
    expect(server).toBeInstanceOf(http.Server);

    wss = new WebSocketServer({ server, path: "/ws" });
    const connected = new Promise<void>(resolve => wss!.on("connection", () => resolve()));

    await app.listen(0, "127.0.0.1");
    const address = server.address();
    if (address === null || typeof address === "string")
      throw new Error(`expected a TCP address, got ${JSON.stringify(address)}`);

    const client = new WebSocket(`ws://127.0.0.1:${address.port}/ws`);
    const open = new Promise<void>((resolve, reject) => {
      client.on("open", () => resolve());
      client.on("error", reject);
    });

    await Promise.all([open, connected]);
    expect(client.readyState).toBe(WebSocket.OPEN);
    client.close();
  }, 20000);

  it("refuses the upgrade on a path the gossip server does not own", async () => {
    // Non-vacuity: without this, a `ws` that accepted every path would pass the test above while
    // proving nothing about `path: "/ws"` being honoured — and "the handshake succeeded" would stop
    // being evidence that the mount point is what we think it is.
    app = await NestFactory.create(BareModule, { logger: false });
    const server = app.getHttpServer();
    wss = new WebSocketServer({ server, path: "/ws" });

    await app.listen(0, "127.0.0.1");
    const address = server.address();
    if (address === null || typeof address === "string")
      throw new Error(`expected a TCP address, got ${JSON.stringify(address)}`);

    const client = new WebSocket(`ws://127.0.0.1:${address.port}/not-ws`);
    const outcome = await new Promise<string>(resolve => {
      client.on("open", () => resolve("opened"));
      client.on("error", () => resolve("rejected"));
    });

    expect(outcome).toBe("rejected");
  }, 20000);
});
