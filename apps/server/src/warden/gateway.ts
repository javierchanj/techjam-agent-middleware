import {
  createServer,
  request as httpRequest,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { request as httpsRequest } from "node:https";
import { lookup } from "node:dns/promises";
import { connect as netConnect } from "node:net";
import type { Duplex } from "node:stream";
import type { GrantVault } from "./grants.js";
import type { WardenLedger } from "./ledger.js";
import type { Redactor } from "./redact.js";
import { isBlockedLiteralAddress } from "./policy.js";
import type { EgressPlane, Grant, PolicyDecision, SpanAttributeValue } from "./types.js";

/** Bytes of response tail retained for token metering. Usage lands in the final event. */
const USAGE_TAIL_BYTES = 65_536;
/**
 * Extracts the JSON object following a "usage" key by balancing braces.
 *
 * A regex cannot do this. `"usage"\s*:\s*\{[^{}]*\}` fails the moment the
 * object contains a nested one -- and real providers nest:
 *
 *   "usage":{"input_tokens":84,"total_tokens":196,
 *            "output_tokens_details":{"reasoning_tokens":96}}
 *
 * Reasoning models always send those detail blocks, so regex matching silently
 * degraded every call to byte estimation.
 */
function usageBlocks(text: string): string[] {
  const blocks: string[] = [];
  let index = text.indexOf('"usage"');
  while (index !== -1) {
    const open = text.indexOf("{", index);
    if (open === -1) break;
    let depth = 0;
    let inString = false;
    let escaped = false;
    for (let cursor = open; cursor < text.length; cursor += 1) {
      const character = text[cursor];
      if (escaped) {
        escaped = false;
        continue;
      }
      if (character === "\\") {
        escaped = true;
        continue;
      }
      if (character === '"') {
        inString = !inString;
        continue;
      }
      if (inString) continue;
      if (character === "{") depth += 1;
      else if (character === "}") {
        depth -= 1;
        if (depth === 0) {
          blocks.push(text.slice(open, cursor + 1));
          break;
        }
      }
    }
    index = text.indexOf('"usage"', index + 1);
  }
  return blocks;
}

/**
 * ModelArk surface the Runtime is permitted to reach. Anything else on the
 * provider — file upload, batch, fine-tuning, account endpoints — is refused
 * even though the credential Warden holds would authorise it.
 */
export const DEFAULT_MODEL_PATHS: readonly string[] = [
  "POST /responses",
  "POST /chat/completions",
  "GET /models",
  "GET /models/{id}",
];

/**
 * Entries are exact `METHOD /path` matches. A trailing `/{id}` in an entry —
 * only `GET /models/{id}` by default — permits exactly one further segment,
 * and that segment may not contain a slash or a dot-segment.
 *
 * Exactness matters: an earlier version allowed one trailing segment on every
 * entry, which silently permitted `POST /responses/anything`.
 */
export function isAllowedModelPath(
  method: string,
  path: string,
  allowlist: readonly string[],
): boolean {
  const raw = (path.split("?")[0] ?? "").replace(/^\/v1/, "");
  if (raw.includes("..")) return false;
  const cleanPath = raw.replace(/\/+$/, "") || "/";
  const upperMethod = method.toUpperCase();
  return allowlist.some((entry) => {
    const [entryMethod = "", entryPath = ""] = entry.trim().split(/\s+/);
    if (entryMethod.toUpperCase() !== upperMethod) return false;
    if (entryPath.endsWith("/{id}")) {
      const base = entryPath.slice(0, -"/{id}".length);
      if (cleanPath === base) return true;
      if (!cleanPath.startsWith(base + "/")) return false;
      const segment = cleanPath.slice(base.length + 1);
      return segment.length > 0 && !segment.includes("/");
    }
    return entryPath === cleanPath;
  });
}

export interface UsageReading {
  totalTokens: number;
  estimated: boolean;
}

/**
 * Extracts token usage from a Responses-API payload, JSON or SSE.
 * Exported so metering is unit-testable without a live upstream.
 */
export function extractUsageTokens(text: string): UsageReading | null {
  const blocks = usageBlocks(text);
  const lastBlock = blocks.length > 0 ? blocks[blocks.length - 1] : null;
  if (!lastBlock) return null;
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(lastBlock) as Record<string, unknown>;
  } catch {
    return null;
  }
  const numeric = (key: string): number => {
    const value = parsed[key];
    return typeof value === "number" && Number.isFinite(value) ? value : 0;
  };
  const total = numeric("total_tokens");
  if (total > 0) return { totalTokens: total, estimated: false };
  const sum =
    numeric("input_tokens") +
    numeric("output_tokens") +
    numeric("prompt_tokens") +
    numeric("completion_tokens");
  if (sum > 0) return { totalTokens: sum, estimated: false };
  return null;
}

export function estimateTokens(byteLength: number): number {
  return Math.ceil(byteLength / 4);
}

/** Accepts `Bearer <token>` or `Basic base64(user:token)`. */
export function parseCredentials(headerValue: string | undefined): string | null {
  if (!headerValue) return null;
  const [schemeRaw, ...rest] = headerValue.trim().split(/\s+/);
  const scheme = (schemeRaw ?? "").toLowerCase();
  const payload = rest.join(" ").trim();
  if (!payload) return null;
  if (scheme === "bearer") return payload;
  if (scheme === "basic") {
    const decoded = Buffer.from(payload, "base64").toString("utf8");
    const separator = decoded.indexOf(":");
    return separator === -1 ? decoded : decoded.slice(separator + 1);
  }
  return null;
}

export function parseHostPort(authority: string, fallbackPort: number): { host: string; port: number } {
  const trimmed = authority.trim();
  const ipv6 = /^\[(.+)\]:(\d+)$/.exec(trimmed);
  if (ipv6) return { host: ipv6[1] ?? trimmed, port: Number(ipv6[2]) };
  if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
    return { host: trimmed.slice(1, -1), port: fallbackPort };
  }
  const separator = trimmed.lastIndexOf(":");
  if (separator > 0 && /^\d+$/.test(trimmed.slice(separator + 1))) {
    return { host: trimmed.slice(0, separator), port: Number(trimmed.slice(separator + 1)) };
  }
  return { host: trimmed, port: fallbackPort };
}

export interface ResolvedDestination {
  address: string;
}

/**
 * Policy matches a NAME. This resolves it and screens the ADDRESS, so an
 * allowlisted hostname (or a rebinding attack) cannot land on loopback, a
 * sibling container or the cloud metadata endpoint. Callers then connect to the
 * returned address, pinning the destination that was screened.
 */
export async function resolveAndScreen(host: string): Promise<ResolvedDestination | null> {
  const resolved = await lookup(host, { all: true });
  const usable = resolved.find((entry) => !isBlockedLiteralAddress(entry.address));
  return usable ? { address: usable.address } : null;
}

export interface WardenGatewayOptions {
  vault: GrantVault;
  ledger: WardenLedger;
  redactor: Redactor;
  /** Real upstream, e.g. https://ark.cn-beijing.volces.com/api/v3 */
  upstreamBaseUrl: string;
  /** Real Ark key. Held only here; never enters a Runtime container. */
  upstreamApiKey: string;
  host: string;
  port: number;
  tunnelTimeoutMs?: number | undefined;
  modelPaths?: readonly string[] | undefined;
}

interface DenyPayload {
  error: {
    type: "warden_policy_denied";
    code: string;
    message: string;
    grant_id: string | null;
    trace_id: string | null;
  };
}

/**
 * The single egress choke point.
 *
 * Model plane  : reverse proxy. Terminates plaintext HTTP inside the internal
 *                container network, injects the real credential, meters tokens.
 * Network plane: forward proxy (CONNECT + absolute-URI). Host/port allowlist
 *                enforced before a socket is ever opened.
 */
export class WardenGateway {
  private server: Server | null = null;
  private readonly upstream: URL;
  /** Live tunnels and upstream calls, keyed by grant, so revocation can kill them. */
  private readonly liveByGrant = new Map<string, Set<{ destroy(): void }>>();

  constructor(private readonly options: WardenGatewayOptions) {
    this.upstream = new URL(options.upstreamBaseUrl);
  }

  get upstreamHost(): string {
    return this.upstream.hostname;
  }

  get upstreamPort(): number {
    return this.upstream.port ? Number(this.upstream.port) : this.upstream.protocol === "http:" ? 80 : 443;
  }

  async listen(): Promise<{ host: string; port: number }> {
    const server = createServer();
    server.on("request", (request, response) => {
      void this.handleRequest(request, response);
    });
    server.on("connect", (request, socket, head) => {
      this.handleConnect(request, socket, head);
    });
    server.on("clientError", (_error, socket) => {
      if (socket.writable) socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
    });
    this.server = server;
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(this.options.port, this.options.host, () => {
        server.removeListener("error", reject);
        resolve();
      });
    });
    const address = server.address();
    const port = typeof address === "object" && address ? address.port : this.options.port;
    return { host: this.options.host, port };
  }

  /**
   * Revocation must terminate work in flight, not merely refuse the next call.
   * An open CONNECT tunnel would otherwise keep exfiltrating after the operator
   * has revoked authority.
   */
  closeForGrant(grantId: string): number {
    const live = this.liveByGrant.get(grantId);
    if (!live) return 0;
    const count = live.size;
    for (const item of live) item.destroy();
    this.liveByGrant.delete(grantId);
    return count;
  }

  private track(grantId: string, item: { destroy(): void }): () => void {
    let set = this.liveByGrant.get(grantId);
    if (!set) {
      set = new Set();
      this.liveByGrant.set(grantId, set);
    }
    set.add(item);
    return () => {
      set?.delete(item);
      if (set && set.size === 0) this.liveByGrant.delete(grantId);
    };
  }

  async close(): Promise<void> {
    for (const grantId of [...this.liveByGrant.keys()]) this.closeForGrant(grantId);
    const server = this.server;
    if (!server) return;
    this.server = null;
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }

  // ---------------------------------------------------------------- requests

  private async handleRequest(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const url = request.url ?? "/";
    if (url === "/warden/health") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: true, plane: "gateway" }));
      return;
    }
    if (/^https?:\/\//i.test(url)) {
      await this.handlePlainForwardProxy(request, response, url);
      return;
    }
    await this.handleModelPlane(request, response, url);
  }

  private async handleModelPlane(
    request: IncomingMessage,
    response: ServerResponse,
    url: string,
  ): Promise<void> {
    const token = parseCredentials(request.headers.authorization);
    const method = (request.method ?? "GET").toUpperCase();
    const { decision, grant } = this.options.vault.authorize(token, {
      plane: "model",
      host: this.upstreamHost,
      port: this.upstreamPort,
      method,
      path: url,
      nowMs: Date.now(),
    });

    if (decision.effect === "deny" || !grant) {
      this.recordDenial(grant, "model", this.upstreamHost, this.upstreamPort, method, url, decision);
      this.sendDenial(response, grant, decision);
      request.resume();
      return;
    }

    // Holding a model-plane capability is not the same as holding the whole
    // provider API. Restrict to the inference surface Codex actually needs.
    const allowlist = this.options.modelPaths ?? DEFAULT_MODEL_PATHS;
    if (!isAllowedModelPath(method, url, allowlist)) {
      const pathDecision: PolicyDecision = {
        effect: "deny",
        code: "path_not_allowed",
        message:
          "Provider path " + method + " " + url + " is outside the permitted inference surface.",
      };
      this.recordDenial(grant, "model", this.upstreamHost, this.upstreamPort, method, url, pathDecision);
      this.sendDenial(response, grant, pathDecision);
      request.resume();
      return;
    }

    const spanId = this.options.ledger.startSpan({
      traceId: grant.traceId,
      runId: grant.runId,
      agentId: grant.agentId,
      kind: "model_call",
      name: method + " " + url,
      attributes: {
        plane: "model",
        decision: "allow",
        upstream_host: this.upstreamHost,
        grant_id: grant.id,
        human_principal: grant.humanPrincipal.id,
        agent_principal: grant.agentPrincipal.id,
        model_calls_used: grant.usage.modelCalls + 1,
        model_calls_budget: grant.budget.maxModelCalls,
      },
    });

    const target = this.buildUpstreamPath(url);
    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries(request.headers)) {
      const key = name.toLowerCase();
      if (["host", "authorization", "connection", "proxy-authorization", "accept-encoding"].includes(key)) {
        continue;
      }
      if (value === undefined) continue;
      headers[key] = Array.isArray(value) ? value.join(", ") : value;
    }
    headers.host = this.upstreamHost;
    // The credential is attached here and only here.
    headers.authorization = "Bearer " + this.options.upstreamApiKey;
    // Identity encoding keeps the streamed tail parseable for token metering.
    headers["accept-encoding"] = "identity";

    const send = this.upstream.protocol === "http:" ? httpRequest : httpsRequest;
    const upstreamRequest = send(
      {
        protocol: this.upstream.protocol,
        hostname: this.upstreamHost,
        port: this.upstreamPort,
        method,
        path: target,
        headers,
      },
      (upstreamResponse) => {
        response.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers);
        let tail = "";
        let bytes = 0;
        upstreamResponse.on("data", (chunk: Buffer) => {
          bytes += chunk.byteLength;
          tail = (tail + chunk.toString("utf8")).slice(-USAGE_TAIL_BYTES);
        });
        upstreamResponse.pipe(response);
        upstreamResponse.on("end", () => {
          const status = upstreamResponse.statusCode ?? 500;
          const failed = status >= 400;
          // A failed upstream call consumed no model tokens. Charging an
          // estimate for a 401 body inflates the budget AND latches the
          // "partly estimated" flag for the rest of the grant, which made the
          // panel report degraded accounting for a run that had none.
          const reading: UsageReading = failed
            ? { totalTokens: 0, estimated: false }
            : (extractUsageTokens(tail) ?? {
                totalTokens: estimateTokens(bytes),
                estimated: true,
              });
          const updated = this.options.vault.recordTokenUsage(
            grant.id,
            reading.totalTokens,
            reading.estimated,
          );
          this.options.ledger.endSpan(grant.traceId, spanId, {
            status: (upstreamResponse.statusCode ?? 500) < 400 ? "ok" : "error",
            attributes: {
              http_status: upstreamResponse.statusCode ?? 0,
              response_bytes: bytes,
              tokens_charged: reading.totalTokens,
              tokens_estimated: reading.estimated,
              upstream_failed: failed,
              tokens_used_total: updated?.usage.totalTokens ?? null,
              tokens_budget: grant.budget.maxTotalTokens,
              grant_status_after: updated?.status ?? null,
            },
          });
        });
      },
    );

    const untrack = this.track(grant.id, upstreamRequest);
    upstreamRequest.on("close", untrack);
    upstreamRequest.on("error", (error) => {
      const message = this.options.redactor.redactString(
        error instanceof Error ? error.message : String(error),
      );
      this.options.ledger.endSpan(grant.traceId, spanId, {
        status: "error",
        attributes: { error: message },
      });
      if (!response.headersSent) {
        response.writeHead(502, { "content-type": "application/json" });
      }
      response.end(
        JSON.stringify({
          error: { type: "warden_upstream_error", message },
        }),
      );
    });

    request.pipe(upstreamRequest);
  }

  private async handlePlainForwardProxy(
    request: IncomingMessage,
    response: ServerResponse,
    absoluteUrl: string,
  ): Promise<void> {
    const token = parseCredentials(request.headers["proxy-authorization"] as string | undefined);
    const method = (request.method ?? "GET").toUpperCase();
    let parsed: URL;
    try {
      parsed = new URL(absoluteUrl);
    } catch {
      response.writeHead(400, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: { type: "warden_bad_request", message: "Malformed proxy URL" } }));
      return;
    }
    const port = parsed.port ? Number(parsed.port) : 80;
    const { decision, grant } = this.options.vault.authorize(token, {
      plane: "network",
      host: parsed.hostname,
      port,
      method,
      path: parsed.pathname,
      nowMs: Date.now(),
    });

    if (decision.effect === "deny" || !grant) {
      this.recordDenial(grant, "network", parsed.hostname, port, method, parsed.pathname, decision);
      this.sendDenial(response, grant, decision);
      request.resume();
      return;
    }

    // Same resolve -> screen -> pin treatment as CONNECT. Without it this path
    // would re-resolve the hostname after the policy check.
    let pinned: string;
    try {
      const screened = await resolveAndScreen(parsed.hostname);
      if (!screened) {
        const addressDecision: PolicyDecision = {
          effect: "deny",
          code: "address_not_allowed",
          message:
            "Host " + parsed.hostname + " resolves only to loopback, private or link-local addresses.",
        };
        this.recordDenial(grant, "network", parsed.hostname, port, method, parsed.pathname, addressDecision);
        this.sendDenial(response, grant, addressDecision);
        request.resume();
        return;
      }
      pinned = screened.address;
    } catch {
      response.writeHead(502, { "content-type": "application/json" });
      response.end(JSON.stringify({ error: { type: "warden_dns_failure" } }));
      return;
    }

    const spanId = this.options.ledger.startSpan({
      traceId: grant.traceId,
      runId: grant.runId,
      agentId: grant.agentId,
      kind: "network_call",
      name: method + " " + parsed.hostname + parsed.pathname,
      attributes: {
        plane: "network",
        decision: "allow",
        host: parsed.hostname,
        port,
        grant_id: grant.id,
      },
    });

    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries(request.headers)) {
      const key = name.toLowerCase();
      if (key.startsWith("proxy-") || key === "connection") continue;
      if (value === undefined) continue;
      headers[key] = Array.isArray(value) ? value.join(", ") : value;
    }

    // Connect to the screened address; carry the original Host header so the
    // far end still routes by name.
    headers.host = parsed.host;
    const forwarded = httpRequest(
      {
        hostname: pinned,
        port,
        method,
        path: parsed.pathname + parsed.search,
        headers,
      },
      (upstreamResponse) => {
        response.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers);
        upstreamResponse.pipe(response);
        upstreamResponse.on("end", () => {
          this.options.ledger.endSpan(grant.traceId, spanId, {
            status: "ok",
            attributes: {
              http_status: upstreamResponse.statusCode ?? 0,
              resolved_address: pinned,
            },
          });
        });
      },
    );
    // Registered so revocation tears this down mid-stream, as with CONNECT.
    const untrackForward = this.track(grant.id, forwarded);
    forwarded.on("close", untrackForward);
    forwarded.on("error", (error) => {
      this.options.ledger.endSpan(grant.traceId, spanId, {
        status: "error",
        attributes: { error: this.options.redactor.redactString(String(error)) },
      });
      if (!response.headersSent) response.writeHead(502);
      response.end();
    });
    request.pipe(forwarded);
  }

  // ---------------------------------------------------------------- CONNECT

  private handleConnect(request: IncomingMessage, socket: Duplex, head: Buffer): void {
    void this.handleConnectAsync(request, socket, head);
  }

  private async handleConnectAsync(
    request: IncomingMessage,
    socket: Duplex,
    head: Buffer,
  ): Promise<void> {
    const token = parseCredentials(request.headers["proxy-authorization"] as string | undefined);
    const { host, port } = parseHostPort(request.url ?? "", 443);
    const { decision, grant } = this.options.vault.authorize(token, {
      plane: "network",
      host,
      port,
      method: "CONNECT",
      path: "",
      nowMs: Date.now(),
    });

    if (decision.effect === "deny" || !grant) {
      this.recordDenial(grant, "network", host, port, "CONNECT", "", decision);
      const body = JSON.stringify(this.denyPayload(grant, decision));
      socket.end(
        "HTTP/1.1 403 Forbidden\r\n" +
          "Content-Type: application/json\r\n" +
          "Content-Length: " + Buffer.byteLength(body) + "\r\n" +
          "Connection: close\r\n\r\n" +
          body,
      );
      return;
    }

    // Policy matched the NAME. Now resolve it and screen the ADDRESS, then
    // connect to that exact address. Without this, a hostname on the allowlist
    // (or a rebinding attack) could still land on loopback, a sibling container
    // or the cloud metadata endpoint.
    let pinnedAddress: string;
    try {
      const screened = await resolveAndScreen(host);
      if (!screened) {
        const addressDecision: PolicyDecision = {
          effect: "deny",
          code: "address_not_allowed",
          message:
            "Host " + host + " resolves only to loopback, private or link-local addresses.",
        };
        this.recordDenial(grant, "network", host, port, "CONNECT", "", addressDecision);
        const denial = JSON.stringify(this.denyPayload(grant, addressDecision));
        socket.end(
          "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: " +
            Buffer.byteLength(denial) +
            "\r\nConnection: close\r\n\r\n" +
            denial,
        );
        return;
      }
      pinnedAddress = screened.address;
    } catch {
      socket.end("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n");
      return;
    }

    const spanId = this.options.ledger.startSpan({
      traceId: grant.traceId,
      runId: grant.runId,
      agentId: grant.agentId,
      kind: "network_call",
      name: "CONNECT " + host + ":" + port,
      attributes: {
        plane: "network",
        decision: "allow",
        host,
        port,
        grant_id: grant.id,
      },
    });

    const upstream = netConnect({ host: pinnedAddress, port });
    const untrack = this.track(grant.id, { destroy: () => {
      upstream.destroy();
      socket.destroy();
    } });
    let bytesOut = 0;
    let bytesIn = 0;
    const timeout = setTimeout(() => {
      upstream.destroy();
      socket.destroy();
    }, this.options.tunnelTimeoutMs ?? 120_000);
    timeout.unref();

    const finish = (status: "ok" | "error", error?: unknown) => {
      clearTimeout(timeout);
      untrack();
      this.options.ledger.endSpan(grant.traceId, spanId, {
        status,
        attributes: {
          resolved_address: pinnedAddress,
          bytes_out: bytesOut,
          bytes_in: bytesIn,
          ...(error ? { error: this.options.redactor.redactString(String(error)) } : {}),
        },
      });
    };

    upstream.on("connect", () => {
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length > 0) upstream.write(head);
      socket.on("data", (chunk: Buffer) => {
        bytesOut += chunk.byteLength;
      });
      upstream.on("data", (chunk: Buffer) => {
        bytesIn += chunk.byteLength;
      });
      socket.pipe(upstream);
      upstream.pipe(socket);
    });
    upstream.on("error", (error) => {
      finish("error", error);
      socket.destroy();
    });
    upstream.on("close", () => finish("ok"));
    socket.on("error", () => {
      upstream.destroy();
    });
  }

  // ---------------------------------------------------------------- helpers

  private buildUpstreamPath(incomingPath: string): string {
    const basePath = this.upstream.pathname.replace(/\/+$/, "");
    const suffix = incomingPath.replace(/^\/v1/, "");
    return (basePath + (suffix.startsWith("/") ? suffix : "/" + suffix)) || "/";
  }

  private denyPayload(grant: Grant | null, decision: PolicyDecision): DenyPayload {
    const code = decision.effect === "deny" ? decision.code : "unknown";
    const message = decision.effect === "deny" ? decision.message : "denied";
    return {
      error: {
        type: "warden_policy_denied",
        code,
        message: this.options.redactor.redactString(message),
        grant_id: grant?.id ?? null,
        trace_id: grant?.traceId ?? null,
      },
    };
  }

  private sendDenial(response: ServerResponse, grant: Grant | null, decision: PolicyDecision): void {
    const body = JSON.stringify(this.denyPayload(grant, decision));
    response.writeHead(403, {
      "content-type": "application/json",
      "content-length": Buffer.byteLength(body),
    });
    response.end(body);
  }

  private recordDenial(
    grant: Grant | null,
    plane: EgressPlane,
    host: string,
    port: number,
    method: string,
    path: string,
    decision: PolicyDecision,
  ): void {
    if (!grant) return; // No grant means no trace to attach the evidence to.
    const attributes: Record<string, SpanAttributeValue> = {
      plane,
      decision: "deny",
      deny_code: decision.effect === "deny" ? decision.code : "unknown",
      deny_reason: decision.effect === "deny" ? decision.message : "denied",
      host,
      port,
      method,
      path,
      grant_id: grant.id,
      human_principal: grant.humanPrincipal.id,
      agent_principal: grant.agentPrincipal.id,
    };
    this.options.ledger.recordEvent({
      traceId: grant.traceId,
      runId: grant.runId,
      agentId: grant.agentId,
      kind: plane === "model" ? "model_call" : "network_call",
      name: "DENIED " + method + " " + host + ":" + port,
      status: "denied",
      attributes,
    });
  }
}
