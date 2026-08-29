import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { timingSafeEqual } from "node:crypto";
import type { WardenControl } from "./control.js";

/**
 * Control listener inside the broker container.
 *
 * Published to 127.0.0.1 on the host only, and additionally gated by a
 * per-boot shared secret. The Runtime network cannot reach this port at all:
 * it is bound on the egress interface, and the internal network has no route
 * to the host's published ports.
 */
export class WardenControlServer {
  private server: Server | null = null;

  constructor(
    private readonly control: WardenControl,
    private readonly secret: string,
    private readonly host: string,
    private readonly port: number,
    /**
     * Local addresses that must never serve the control API. The broker is
     * dual-homed, so binding 0.0.0.0 would otherwise expose control to the
     * Runtime network. Requests arriving on the internal interface are refused
     * before authentication is even considered.
     */
    private readonly blockedLocalAddresses: readonly string[] = [],
  ) {}

  async listen(): Promise<number> {
    const server = createServer((request, response) => {
      void this.handle(request, response);
    });
    this.server = server;
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(this.port, this.host, () => {
        server.removeListener("error", reject);
        resolve();
      });
    });
    const address = server.address();
    return typeof address === "object" && address ? address.port : this.port;
  }

  async close(): Promise<void> {
    const server = this.server;
    if (!server) return;
    this.server = null;
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }

  private authorized(request: IncomingMessage): boolean {
    const header = request.headers.authorization ?? "";
    const candidate = header.startsWith("Bearer ") ? header.slice(7) : "";
    const expected = Buffer.from(this.secret);
    const given = Buffer.from(candidate);
    return given.length === expected.length && timingSafeEqual(given, expected);
  }

  private async body(request: IncomingMessage): Promise<Record<string, unknown>> {
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of request) {
      const buffer = chunk as Buffer;
      size += buffer.byteLength;
      if (size > 262_144) throw new Error("Control request body too large");
      chunks.push(buffer);
    }
    if (chunks.length === 0) return {};
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const url = new URL(request.url ?? "/", "http://control.local");
    const send = (status: number, payload: unknown) => {
      const body = JSON.stringify(payload);
      response.writeHead(status, {
        "content-type": "application/json",
        "content-length": Buffer.byteLength(body),
      });
      response.end(body);
    };

    const localAddress = (request.socket.localAddress ?? "").replace(/^::ffff:/, "");
    if (this.blockedLocalAddresses.includes(localAddress)) {
      // Do not confirm that a control API exists here.
      response.socket?.destroy();
      return;
    }

    if (url.pathname === "/control/health") {
      send(200, { ok: true });
      return;
    }
    if (!this.authorized(request)) {
      send(401, { error: "Control channel authentication required" });
      return;
    }

    try {
      const path = url.pathname;
      const method = request.method ?? "GET";

      if (method === "POST" && path === "/control/runs") {
        send(200, await this.control.beginRun((await this.body(request)) as never));
        return;
      }
      if (method === "POST" && path === "/control/runs/end") {
        send(200, { grant: await this.control.endRun((await this.body(request)) as never) });
        return;
      }
      if (method === "POST" && path === "/control/grants/revoke") {
        const payload = (await this.body(request)) as { grantId: string; reason: string };
        send(200, { grant: await this.control.revokeGrant(payload.grantId, payload.reason) });
        return;
      }
      if (method === "GET" && path === "/control/grants") {
        const id = url.searchParams.get("id");
        send(200, id ? { grant: await this.control.getGrant(id) } : { grants: await this.control.listGrants() });
        return;
      }
      if (method === "GET" && path === "/control/traces") {
        const id = url.searchParams.get("id");
        const agentId = url.searchParams.get("agentId") ?? undefined;
        send(200, id ? { trace: await this.control.getTrace(id) } : { traces: await this.control.listTraces(agentId) });
        return;
      }
      if (method === "GET" && path === "/control/policy") {
        send(200, await this.control.getPolicy());
        return;
      }
      if (method === "GET" && path === "/control/templates") {
        send(200, await this.control.listTemplates());
        return;
      }
      if (method === "POST" && path === "/control/policy/template") {
        const payload = (await this.body(request)) as { id: string };
        send(200, await this.control.applyTemplate(payload.id));
        return;
      }
      if (method === "POST" && path === "/control/policy/check") {
        send(200, await this.control.checkPolicy((await this.body(request)) as never));
        return;
      }
      if (method === "GET" && path === "/control/status") {
        send(200, await this.control.status());
        return;
      }
      send(404, { error: "Unknown control route" });
    } catch (error) {
      send(500, { error: error instanceof Error ? error.message : "Control failure" });
    }
  }
}
