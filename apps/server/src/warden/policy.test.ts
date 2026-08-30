import { describe, expect, it } from "vitest";
import {
  evaluate,
  isBlockedLiteralAddress,
  isRestrictedAddress,
  matchHost,
  normalizeHost,
  WardenPolicyStore,
} from "./policy.js";
import type { Budget, EgressScope, Grant, PolicyRequest } from "./types.js";

const T0 = Date.parse("2026-01-01T00:00:00.000Z");

const budget: Budget = {
  maxModelCalls: 5,
  maxTotalTokens: 1_000,
  maxWallClockMs: 60_000,
};

const scopes: EgressScope[] = [
  { plane: "model", host: "ark.cn-beijing.volces.com", ports: [443], methods: ["GET", "POST"] },
  { plane: "network", host: "*.internal.test", ports: [443] },
];

function grantFixture(overrides: Partial<Grant> = {}): Grant {
  return {
    id: "grant_1",
    tokenHash: "hash",
    agentId: "agent_1",
    runId: "run_1",
    traceId: "trace_1",
    humanPrincipal: { kind: "human", id: "user:alice", displayName: "Alice" },
    agentPrincipal: { kind: "agent", id: "agent:agent_1", displayName: "Agent" },
    scopes,
    budget,
    usage: { modelCalls: 0, networkCalls: 0, totalTokens: 0, estimated: false },
    status: "active",
    statusReason: null,
    issuedAt: new Date(T0).toISOString(),
    expiresAt: new Date(T0 + 300_000).toISOString(),
    closedAt: null,
    ...overrides,
  };
}

function request(overrides: Partial<PolicyRequest> = {}): PolicyRequest {
  return {
    plane: "model",
    host: "ark.cn-beijing.volces.com",
    port: 443,
    method: "POST",
    path: "/v1/responses",
    nowMs: T0 + 1_000,
    ...overrides,
  };
}

describe("matchHost", () => {
  it("matches exact hosts case-insensitively and ignores a trailing dot", () => {
    expect(matchHost("Example.com", "example.com.")).toBe(true);
  });

  it("matches wildcard subdomains but never the bare parent", () => {
    expect(matchHost("*.internal.test", "svc.internal.test")).toBe(true);
    expect(matchHost("*.internal.test", "a.b.internal.test")).toBe(true);
    expect(matchHost("*.internal.test", "internal.test")).toBe(false);
  });

  it("does not treat a suffix collision as a match", () => {
    expect(matchHost("*.internal.test", "evil-internal.test")).toBe(false);
    expect(matchHost("ark.example.com", "notark.example.com")).toBe(false);
  });

  it("strips ports and IPv6 brackets", () => {
    expect(normalizeHost("[::1]")).toBe("::1");
    expect(normalizeHost("example.com:8443")).toBe("example.com");
  });
});

describe("evaluate", () => {
  it("allows an in-scope model call", () => {
    const decision = evaluate(grantFixture(), request());
    expect(decision.effect).toBe("allow");
  });

  it("denies when no grant is presented", () => {
    const decision = evaluate(null, request());
    expect(decision).toMatchObject({ effect: "deny", code: "no_grant" });
  });

  it("denies an unlisted host — the exfiltration case", () => {
    const decision = evaluate(
      grantFixture(),
      request({ plane: "network", host: "attacker.example.net", port: 443, method: "CONNECT" }),
    );
    expect(decision).toMatchObject({ effect: "deny", code: "host_not_allowed" });
  });

  it("denies an allowed host on an unlisted port", () => {
    const decision = evaluate(
      grantFixture(),
      request({ plane: "network", host: "svc.internal.test", port: 22, method: "CONNECT" }),
    );
    expect(decision).toMatchObject({ effect: "deny", code: "port_not_allowed" });
  });

  it("denies a method outside the scope", () => {
    const decision = evaluate(grantFixture(), request({ method: "DELETE" }));
    expect(decision).toMatchObject({ effect: "deny", code: "method_not_allowed" });
  });

  it("denies after revocation, and the reason is carried through", () => {
    const decision = evaluate(
      grantFixture({ status: "revoked", statusReason: "operator kill switch" }),
      request(),
    );
    expect(decision).toMatchObject({ effect: "deny", code: "grant_revoked" });
    if (decision.effect === "deny") {
      expect(decision.message).toContain("operator kill switch");
    }
  });

  it("denies once the TTL has elapsed", () => {
    const decision = evaluate(grantFixture(), request({ nowMs: T0 + 400_000 }));
    expect(decision).toMatchObject({ effect: "deny", code: "grant_expired" });
  });

  it("denies once the wall-clock budget is spent", () => {
    const decision = evaluate(grantFixture(), request({ nowMs: T0 + 60_001 }));
    expect(decision).toMatchObject({ effect: "deny", code: "budget_time_exhausted" });
  });

  it("denies once the model-call budget is spent", () => {
    const decision = evaluate(
      grantFixture({
        usage: { modelCalls: 5, networkCalls: 0, totalTokens: 0, estimated: false },
      }),
      request(),
    );
    expect(decision).toMatchObject({ effect: "deny", code: "budget_calls_exhausted" });
  });

  it("denies once the token budget is spent", () => {
    const decision = evaluate(
      grantFixture({
        usage: { modelCalls: 1, networkCalls: 0, totalTokens: 1_000, estimated: false },
      }),
      request(),
    );
    expect(decision).toMatchObject({ effect: "deny", code: "budget_tokens_exhausted" });
  });

  it("denies a plane the grant does not hold at all", () => {
    const decision = evaluate(
      grantFixture({ scopes: [scopes[0] as EgressScope] }),
      request({ plane: "network", host: "svc.internal.test", method: "CONNECT" }),
    );
    expect(decision).toMatchObject({ effect: "deny", code: "plane_not_allowed" });
  });
});

describe("WardenPolicyStore", () => {
  it("adds and removes scopes idempotently without mutating callers' arrays", () => {
    const store = new WardenPolicyStore(scopes, budget);
    store.allowHost({ plane: "network", host: "api.partner.test", ports: [443] });
    store.allowHost({ plane: "network", host: "API.partner.test", ports: [443] });
    expect(store.snapshot().scopes.filter((s) => s.host === "api.partner.test")).toHaveLength(1);
    store.denyHost("network", "api.partner.test");
    expect(store.snapshot().scopes.some((s) => s.host === "api.partner.test")).toBe(false);
    expect(scopes).toHaveLength(2);
  });

  it("patches the budget without dropping untouched fields", () => {
    const store = new WardenPolicyStore(scopes, budget);
    expect(store.setBudget({ maxTotalTokens: 42 })).toEqual({ ...budget, maxTotalTokens: 42 });
  });
});

describe("destination hardening", () => {
  it("refuses loopback, private and link-local literals that were not named", () => {
    for (const host of ["127.0.0.1", "10.0.0.5", "172.17.0.2", "192.168.1.9", "::1", "localhost"]) {
      const decision = evaluate(
        grantFixture({
          scopes: [{ plane: "network", host: "*", ports: [443] }],
        }),
        request({ plane: "network", host, port: 443, method: "CONNECT" }),
      );
      expect(decision).toMatchObject({ effect: "deny" });
    }
  });

  it("blocks the cloud metadata address specifically", () => {
    expect(isBlockedLiteralAddress("169.254.169.254")).toBe(true);
  });

  it("still allows a private literal the operator named explicitly", () => {
    const decision = evaluate(
      grantFixture({ scopes: [{ plane: "network", host: "172.20.0.9", ports: [8080] }] }),
      request({ plane: "network", host: "172.20.0.9", port: 8080, method: "CONNECT" }),
    );
    expect(decision.effect).toBe("allow");
  });

  it("rejects a user-info authority such as allowed.com@evil.com", () => {
    const decision = evaluate(
      grantFixture(),
      request({
        plane: "network",
        host: "svc.internal.test@evil.example.net",
        port: 443,
        method: "CONNECT",
      }),
    );
    expect(decision).toMatchObject({ effect: "deny", code: "host_not_allowed" });
  });

  it("leaves public destinations unaffected", () => {
    expect(isBlockedLiteralAddress("93.184.216.34")).toBe(false);
    expect(isBlockedLiteralAddress("ark.cn-beijing.volces.com")).toBe(false);
  });
});

describe("budget denials are actionable", () => {
  it("names the knob an operator would turn", () => {
    // A denial that only states the limit leaves the operator guessing. This
    // was a real demo failure: the run died and the message did not say why
    // the cap was that size or how to change it.
    const decision = evaluate(
      grantFixture({
        usage: { modelCalls: 1, networkCalls: 0, totalTokens: 1_000, estimated: false },
      }),
      request(),
    );
    expect(decision).toMatchObject({ effect: "deny", code: "budget_tokens_exhausted" });
    if (decision.effect === "deny") {
      expect(decision.message).toContain("WARDEN_MAX_TOTAL_TOKENS");
    }
  });

  it("keeps the wall-clock denial distinct from the token denial", () => {
    const decision = evaluate(grantFixture(), request({ nowMs: T0 + 60_001 }));
    expect(decision).toMatchObject({ effect: "deny", code: "budget_time_exhausted" });
  });
});

describe("one canonical address classifier", () => {
  // Two implementations previously disagreed: the policy-time one knew about
  // CGNAT and IPv4-mapped IPv6, the DNS-screening one did not, so an
  // allowlisted host resolving into 100.64/10 slipped past the resolver.
  const mustBlock = [
    "127.0.0.1", "0.0.0.0", "10.1.2.3", "192.168.1.1", "172.20.0.9",
    "169.254.169.254", "100.64.0.1", "100.127.255.254",
    "::1", "::", "fd00::1", "fe80::1", "ff02::1",
    "::ffff:169.254.169.254", "::ffff:10.0.0.1",
    "224.0.0.1", "255.255.255.255", "999.1.1.1",
  ];
  const mustAllow = ["93.184.216.34", "8.8.8.8", "100.63.255.255", "100.128.0.1", "172.15.0.1", "172.32.0.1"];

  it("blocks every private, loopback, link-local, CGNAT and multicast form", () => {
    for (const host of mustBlock) {
      expect(isRestrictedAddress(host), host).toBe(true);
      expect(isBlockedLiteralAddress(host), host).toBe(true);
    }
  });

  it("leaves genuinely public addresses reachable", () => {
    for (const host of mustAllow) {
      expect(isRestrictedAddress(host), host).toBe(false);
      expect(isBlockedLiteralAddress(host), host).toBe(false);
    }
  });

  it("agrees with itself on every case, so policy and DNS screening cannot diverge", () => {
    for (const host of [...mustBlock, ...mustAllow]) {
      // localhost is the only intentional difference: a name, not a literal.
      expect(isBlockedLiteralAddress(host), host).toBe(isRestrictedAddress(host));
    }
    expect(isBlockedLiteralAddress("localhost")).toBe(true);
  });
});
