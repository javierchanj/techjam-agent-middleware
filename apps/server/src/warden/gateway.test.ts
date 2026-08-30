import { createServer, type Server } from "node:http";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  DEFAULT_MODEL_PATHS,
  WardenGateway,
  estimateTokens,
  isAllowedModelPath,
  extractUsageTokens,
  parseCredentials,
  parseHostPort,
} from "./gateway.js";
import { GrantVault } from "./grants.js";
import { WardenLedger } from "./ledger.js";
import { Redactor } from "./redact.js";
import type { Budget, EgressScope } from "./types.js";

const REAL_KEY = ["ark", "live", "upstream", "fixture", "123"].join("_");

describe("usage metering", () => {
  it("reads total_tokens from a JSON response", () => {
    expect(extractUsageTokens('{"usage":{"total_tokens":321}}')).toEqual({
      totalTokens: 321,
      estimated: false,
    });
  });

  it("sums input and output tokens when no total is present", () => {
    expect(extractUsageTokens('{"usage":{"input_tokens":10,"output_tokens":7}}')).toEqual({
      totalTokens: 17,
      estimated: false,
    });
  });

  it("takes the last usage block from an SSE stream", () => {
    const stream = [
      'data: {"type":"response.delta"}',
      'data: {"type":"response.in_progress","usage":{"total_tokens":5}}',
      'data: {"type":"response.completed","usage":{"total_tokens":250}}',
      "data: [DONE]",
    ].join("\n\n");
    expect(extractUsageTokens(stream)).toEqual({ totalTokens: 250, estimated: false });
  });

  it("returns null when there is nothing to meter, so the caller can estimate", () => {
    expect(extractUsageTokens("data: [DONE]")).toBeNull();
    expect(extractUsageTokens('{"usage":{not json}}')).toBeNull();
    expect(estimateTokens(400)).toBe(100);
  });
});

describe("credential and authority parsing", () => {
  it("accepts Bearer and Basic proxy credentials", () => {
    expect(parseCredentials("Bearer wgt_abc")).toBe("wgt_abc");
    expect(parseCredentials("Basic " + Buffer.from("grant:wgt_abc").toString("base64"))).toBe(
      "wgt_abc",
    );
    expect(parseCredentials(undefined)).toBeNull();
    expect(parseCredentials("Digest nope")).toBeNull();
  });

  it("parses host:port authorities including IPv6", () => {
    expect(parseHostPort("evil.example.net:443", 443)).toEqual({
      host: "evil.example.net",
      port: 443,
    });
    expect(parseHostPort("example.com", 443)).toEqual({ host: "example.com", port: 443 });
    expect(parseHostPort("[::1]:8080", 443)).toEqual({ host: "::1", port: 8080 });
  });
});

describe("WardenGateway model plane", () => {
  const budget: Budget = { maxModelCalls: 3, maxTotalTokens: 1_000, maxWallClockMs: 60_000 };
  let upstream: Server;
  let upstreamPort = 0;
  let seenAuthorization: string | undefined;
  let gateway: WardenGateway;
  let gatewayPort = 0;
  let vault: GrantVault;
  let ledger: WardenLedger;
  let redactor: Redactor;

  const scopes = (host: string): EgressScope[] => [
    { plane: "model", host, ports: [upstreamPort], methods: ["POST"] },
    // A real network capability, so the exfiltration test exercises host
    // matching rather than the coarser "no network plane at all" denial.
    { plane: "network", host: "allowed.partner.test", ports: [443] },
  ];

  const mint = (allowedHost: string) =>
    vault.mint({
      agentId: "agent_1",
      runId: "run_1",
      traceId: "trace_1",
      humanPrincipal: { kind: "human", id: "user:alice", displayName: "Alice" },
      agentPrincipal: { kind: "agent", id: "agent:agent_1", displayName: "Agent" },
      scopes: scopes(allowedHost),
      budget,
      ttlMs: 60_000,
    });

  beforeEach(async () => {
    seenAuthorization = undefined;
    upstream = createServer((request, response) => {
      seenAuthorization = request.headers.authorization;
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: true, usage: { total_tokens: 120 } }));
    });
    await new Promise<void>((resolve) => upstream.listen(0, "127.0.0.1", resolve));
    const address = upstream.address();
    upstreamPort = typeof address === "object" && address ? address.port : 0;

    redactor = new Redactor();
    redactor.register(REAL_KEY, "ark_api_key");
    ledger = new WardenLedger(redactor);
    vault = new GrantVault(redactor);
    ledger.beginTrace({ traceId: "trace_1", runId: "run_1", agentId: "agent_1" });

    gateway = new WardenGateway({
      vault,
      ledger,
      redactor,
      upstreamBaseUrl: "http://127.0.0.1:" + upstreamPort + "/api/v3",
      upstreamApiKey: REAL_KEY,
      host: "127.0.0.1",
      port: 0,
    });
    gatewayPort = (await gateway.listen()).port;
  });

  afterEach(async () => {
    await gateway.close();
    await new Promise<void>((resolve) => upstream.close(() => resolve()));
  });

  const call = (token: string | null, path = "/v1/responses") =>
    fetch("http://127.0.0.1:" + gatewayPort + path, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(token ? { authorization: "Bearer " + token } : {}),
      },
      body: JSON.stringify({ input: "hello" }),
    });

  it("injects the real credential upstream and never accepts it from the Runtime", async () => {
    const { token } = mint("127.0.0.1");
    const response = await call(token);
    expect(response.status).toBe(200);
    expect(seenAuthorization).toBe("Bearer " + REAL_KEY);
    // The Runtime only ever held the minted grant token.
    expect(token).not.toContain(REAL_KEY);
  });

  it("meters tokens from the upstream response onto the grant", async () => {
    const { token, grant } = mint("127.0.0.1");
    await call(token);
    await new Promise((resolve) => setTimeout(resolve, 50));
    const updated = vault.get(grant.id);
    expect(updated?.usage.totalTokens).toBe(120);
    expect(updated?.usage.estimated).toBe(false);
  });

  it("denies an unauthenticated call with a structured policy error", async () => {
    const response = await call(null);
    expect(response.status).toBe(403);
    const body = (await response.json()) as { error: { type: string; code: string } };
    expect(body.error.type).toBe("warden_policy_denied");
    expect(body.error.code).toBe("no_grant");
  });

  it("denies after operator revocation and writes denial evidence to the trace", async () => {
    const { token, grant } = mint("127.0.0.1");
    vault.revoke(grant.id, "operator kill switch");
    const response = await call(token);
    expect(response.status).toBe(403);
    const denials = ledger.listSpans({ status: "denied" });
    expect(denials).toHaveLength(1);
    expect(denials[0]?.attributes.deny_code).toBe("grant_revoked");
    expect(denials[0]?.attributes.human_principal).toBe("user:alice");
  });

  it("keeps the upstream secret out of every span it records", async () => {
    const { token } = mint("127.0.0.1");
    await call(token);
    await new Promise((resolve) => setTimeout(resolve, 50));
    const serialized = JSON.stringify(ledger.listTraces());
    expect(serialized).not.toContain(REAL_KEY);
    expect(serialized).not.toContain(token);
  });

  it("denies a CONNECT tunnel to a host outside the allowlist", async () => {
    const { token } = mint("127.0.0.1");
    const raw = await new Promise<string>((resolve, reject) => {
      import("node:net").then(({ connect }) => {
        const socket = connect(gatewayPort, "127.0.0.1", () => {
          socket.write(
            "CONNECT attacker.example.net:443 HTTP/1.1\r\n" +
              "Host: attacker.example.net:443\r\n" +
              "Proxy-Authorization: Bearer " + token + "\r\n\r\n",
          );
        });
        let buffer = "";
        socket.on("data", (chunk: Buffer) => {
          buffer += chunk.toString("utf8");
        });
        socket.on("close", () => resolve(buffer));
        socket.on("error", reject);
      }, reject);
    });
    expect(raw).toContain("403 Forbidden");
    expect(raw).toContain("host_not_allowed");
    const denials = ledger.listSpans({ status: "denied" });
    expect(denials.some((span) => span.attributes.host === "attacker.example.net")).toBe(true);
  });
});

describe("model surface restriction", () => {
  it("permits the inference paths Codex actually uses", () => {
    expect(isAllowedModelPath("POST", "/v1/responses", DEFAULT_MODEL_PATHS)).toBe(true);
    expect(isAllowedModelPath("POST", "/v1/chat/completions", DEFAULT_MODEL_PATHS)).toBe(true);
    expect(isAllowedModelPath("GET", "/v1/models", DEFAULT_MODEL_PATHS)).toBe(true);
    expect(isAllowedModelPath("GET", "/v1/models/ep-abc123", DEFAULT_MODEL_PATHS)).toBe(true);
  });

  it("refuses the rest of the provider API even though the key would allow it", () => {
    expect(isAllowedModelPath("POST", "/v1/files", DEFAULT_MODEL_PATHS)).toBe(false);
    expect(isAllowedModelPath("POST", "/v1/fine_tuning/jobs", DEFAULT_MODEL_PATHS)).toBe(false);
    expect(isAllowedModelPath("DELETE", "/v1/responses", DEFAULT_MODEL_PATHS)).toBe(false);
    expect(isAllowedModelPath("GET", "/v1/responses", DEFAULT_MODEL_PATHS)).toBe(false);
  });

  it("is not fooled by a query string or a trailing slash", () => {
    expect(isAllowedModelPath("POST", "/v1/responses?stream=true", DEFAULT_MODEL_PATHS)).toBe(true);
    expect(isAllowedModelPath("POST", "/v1/responses/", DEFAULT_MODEL_PATHS)).toBe(true);
    expect(isAllowedModelPath("POST", "/v1/responses/../files", DEFAULT_MODEL_PATHS)).toBe(false);
  });
});

describe("path matching is exact", () => {
  it("does not permit an extra segment on a POST path", () => {
    // An earlier version allowed one trailing segment on EVERY entry, which
    // silently permitted POST /responses/anything.
    expect(isAllowedModelPath("POST", "/v1/responses/anything", DEFAULT_MODEL_PATHS)).toBe(false);
    expect(isAllowedModelPath("POST", "/v1/chat/completions/x", DEFAULT_MODEL_PATHS)).toBe(false);
  });

  it("permits exactly one id segment on GET /models", () => {
    expect(isAllowedModelPath("GET", "/v1/models/ep-abc", DEFAULT_MODEL_PATHS)).toBe(true);
    expect(isAllowedModelPath("GET", "/v1/models/ep-abc/versions", DEFAULT_MODEL_PATHS)).toBe(false);
  });

  it("rejects dot-segment traversal outright", () => {
    expect(isAllowedModelPath("GET", "/v1/models/../files", DEFAULT_MODEL_PATHS)).toBe(false);
  });
});

describe("usage parsing with nested detail blocks", () => {
  // The shape a reasoning model actually returns. An earlier regex-based
  // parser silently failed on this and estimated every call instead.
  const REAL = '{"usage":{"input_tokens":84,"output_tokens":112,"total_tokens":196,' +
    '"input_tokens_details":{"cached_tokens":0},' +
    '"output_tokens_details":{"reasoning_tokens":96}},"status":"completed"}';

  it("reads total_tokens through nested objects", () => {
    expect(extractUsageTokens(REAL)).toEqual({ totalTokens: 196, estimated: false });
  });

  it("sums input and output when nested details are present and no total is", () => {
    const noTotal = '{"usage":{"input_tokens":10,"output_tokens":7,' +
      '"output_tokens_details":{"reasoning_tokens":5}}}';
    expect(extractUsageTokens(noTotal)).toEqual({ totalTokens: 17, estimated: false });
  });

  it("takes the last usage block from a nested SSE stream", () => {
    const stream = [
      'data: {"usage":{"total_tokens":5,"output_tokens_details":{"reasoning_tokens":1}}}',
      'data: {"usage":{"total_tokens":250,"output_tokens_details":{"reasoning_tokens":96}}}',
      "data: [DONE]",
    ].join("\n\n");
    expect(extractUsageTokens(stream)).toEqual({ totalTokens: 250, estimated: false });
  });

  it("is not confused by braces inside string values", () => {
    const tricky = '{"usage":{"note":"a } brace","total_tokens":42}}';
    expect(extractUsageTokens(tricky)).toEqual({ totalTokens: 42, estimated: false });
  });
});

describe("metering does not charge for failed upstream calls", () => {
  let failing: Server;
  let failingPort = 0;
  let gw: WardenGateway;
  let gwPort = 0;
  let v: GrantVault;
  let led: WardenLedger;

  beforeEach(async () => {
    failing = createServer((_request, response) => {
      // Shape of a real Ark rejection: no usage block, non-trivial body.
      response.writeHead(401, { "content-type": "application/json" });
      response.end(JSON.stringify({
        error: { code: "AuthenticationError", message: "The API key doesn't exist. Request id: 0217880809304" },
      }));
    });
    await new Promise<void>((resolve) => failing.listen(0, "127.0.0.1", resolve));
    const address = failing.address();
    failingPort = typeof address === "object" && address ? address.port : 0;

    const red = new Redactor();
    led = new WardenLedger(red);
    v = new GrantVault(red);
    led.beginTrace({ traceId: "t", runId: "r", agentId: "a" });
    gw = new WardenGateway({
      vault: v, ledger: led, redactor: red,
      upstreamBaseUrl: "http://127.0.0.1:" + failingPort + "/api/v3",
      upstreamApiKey: ["ark", "dead", "beef", "key", "value"].join("-"),
      host: "127.0.0.1", port: 0,
    });
    gwPort = (await gw.listen()).port;
  });

  afterEach(async () => {
    await gw.close();
    await new Promise<void>((resolve) => failing.close(() => resolve()));
  });

  it("charges zero tokens and does not latch the estimated flag on a 401", async () => {
    const { grant, token } = v.mint({
      agentId: "a", runId: "r", traceId: "t",
      humanPrincipal: { kind: "human", id: "user:a", displayName: "A" },
      agentPrincipal: { kind: "agent", id: "agent:a", displayName: "A" },
      scopes: [{ plane: "model", host: "127.0.0.1", ports: [failingPort], methods: ["POST"] }],
      budget: { maxModelCalls: 5, maxTotalTokens: 1_000, maxWallClockMs: 60_000 },
      ttlMs: 60_000,
    });
    const response = await fetch("http://127.0.0.1:" + gwPort + "/v1/responses", {
      method: "POST",
      headers: { authorization: "Bearer " + token, "content-type": "application/json" },
      body: "{}",
    });
    expect(response.status).toBe(401);
    await new Promise((resolve) => setTimeout(resolve, 60));
    const after = v.get(grant.id);
    // The call was attempted, so it counts against the CALL budget...
    expect(after?.usage.modelCalls).toBe(1);
    // ...but it produced no tokens, and accounting stays exact.
    expect(after?.usage.totalTokens).toBe(0);
    expect(after?.usage.estimated).toBe(false);
  });
});
