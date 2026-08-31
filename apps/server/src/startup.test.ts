import Fastify from "fastify";
import { createServer } from "node:net";
import { describe, expect, it } from "vitest";
import { listenWithCleanup } from "./startup.js";

describe("server startup cleanup", () => {
  it("stops Warden when the HTTP port is already occupied", async () => {
    const occupiedPort = createServer();
    await new Promise<void>((resolve) => occupiedPort.listen(0, "127.0.0.1", resolve));
    const address = occupiedPort.address();
    if (!address || typeof address === "string") throw new Error("test port did not bind");

    const app = Fastify({ logger: false });
    let stopCalls = 0;
    try {
      await expect(
        listenWithCleanup(
          app,
          {
            stop: async () => {
              stopCalls += 1;
            },
          },
          { host: "127.0.0.1", port: address.port },
        ),
      ).rejects.toMatchObject({ code: "EADDRINUSE" });
      expect(stopCalls).toBe(1);
      expect(app.server.listening).toBe(false);
    } finally {
      await new Promise<void>((resolve) => occupiedPort.close(() => resolve()));
    }
  });
});
