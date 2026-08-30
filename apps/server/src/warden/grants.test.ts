import { describe, expect, it } from "vitest";
import { GrantVault, GRANT_TOKEN_PREFIX, hashToken } from "./grants.js";
import { Redactor } from "./redact.js";
import type { Budget, EgressScope, PolicyRequest } from "./types.js";

const budget: Budget = { maxModelCalls: 2, maxTotalTokens: 100, maxWallClockMs: 60_000 };
const scopes: EgressScope[] = [
  { plane: "model", host: "ark.test", ports: [443], methods: ["POST"] },
];

function setup(startMs = Date.parse("2026-01-01T00:00:00.000Z")) {
  let now = startMs;
  const redactor = new Redactor();
  const vault = new GrantVault(redactor, () => now);
  const minted = vault.mint({
    agentId: "agent_1",
    runId: "run_1",
    traceId: "trace_1",
    humanPrincipal: { kind: "human", id: "user:alice", displayName: "Alice" },
    agentPrincipal: { kind: "agent", id: "agent:agent_1", displayName: "Agent" },
    scopes,
    budget,
    ttlMs: 30_000,
  });
  const modelRequest = (): PolicyRequest => ({
    plane: "model",
    host: "ark.test",
    port: 443,
    method: "POST",
    path: "/v1/responses",
    nowMs: now,
  });
  return { redactor, vault, minted, modelRequest, advance: (ms: number) => (now += ms) };
}

describe("GrantVault", () => {
  it("mints a prefixed token and never persists it in the clear", () => {
    const { vault, minted } = setup();
    expect(minted.token.startsWith(GRANT_TOKEN_PREFIX)).toBe(true);
    expect(minted.grant.tokenHash).toBe(hashToken(minted.token));
    expect(JSON.stringify(vault.list())).not.toContain(minted.token);
  });

  it("registers the token for redaction at mint time", () => {
    const { redactor, minted } = setup();
    expect(redactor.redactString("proxy=" + minted.token)).not.toContain(minted.token);
  });

  it("resolves a valid token and rejects a forged one", () => {
    const { vault, minted } = setup();
    expect(vault.resolveByToken(minted.token)?.id).toBe(minted.grant.id);
    expect(vault.resolveByToken(GRANT_TOKEN_PREFIX + "forged")).toBeNull();
    expect(vault.resolveByToken(null)).toBeNull();
  });

  it("reserves budget on authorize so concurrent calls cannot overspend", () => {
    const { vault, minted, modelRequest } = setup();
    expect(vault.authorize(minted.token, modelRequest()).decision.effect).toBe("allow");
    expect(vault.authorize(minted.token, modelRequest()).decision.effect).toBe("allow");
    const third = vault.authorize(minted.token, modelRequest());
    expect(third.decision).toMatchObject({ effect: "deny", code: "budget_calls_exhausted" });
  });

  it("marks the grant exhausted once metered tokens cross the budget", () => {
    const { vault, minted } = setup();
    const updated = vault.recordTokenUsage(minted.grant.id, 150, false);
    expect(updated?.status).toBe("exhausted");
    expect(updated?.usage.totalTokens).toBe(150);
  });

  it("flags estimated metering so the trace never overstates precision", () => {
    const { vault, minted } = setup();
    expect(vault.recordTokenUsage(minted.grant.id, 10, true)?.usage.estimated).toBe(true);
  });

  it("denies immediately after revocation", () => {
    const { vault, minted, modelRequest } = setup();
    vault.revoke(minted.grant.id, "operator kill switch");
    expect(vault.authorize(minted.token, modelRequest()).decision).toMatchObject({
      effect: "deny",
      code: "grant_revoked",
    });
  });

  it("expires on TTL without any explicit call", () => {
    const { vault, minted, modelRequest, advance } = setup();
    advance(31_000);
    expect(vault.authorize(minted.token, modelRequest()).decision).toMatchObject({
      effect: "deny",
      code: "grant_expired",
    });
  });

  it("closes the grant and drops the secret from the redactor registry", () => {
    const { vault, redactor, minted, modelRequest } = setup();
    vault.close(minted.grant.id, "run finished");
    expect(redactor.registeredCount).toBe(0);
    expect(vault.authorize(minted.token, modelRequest()).decision).toMatchObject({
      effect: "deny",
      code: "grant_closed",
    });
  });
});

describe("token custody", () => {
  it("keeps the raw token out of the Grant record and the public DTO", () => {
    const { vault, minted } = setup();
    expect(JSON.stringify(minted.grant)).not.toContain(minted.token);
    const publicGrant = GrantVault.toPublic(minted.grant);
    expect("tokenHash" in publicGrant).toBe(false);
    expect(publicGrant.tokenFingerprint).toHaveLength(8);
    expect(JSON.stringify(vault.list().map(GrantVault.toPublic))).not.toContain(minted.token);
  });

  it("drops the raw token from the redactor registry on close", () => {
    const { vault, redactor, minted } = setup();
    expect(redactor.registeredCount).toBe(1);
    vault.close(minted.grant.id, "run finished");
    expect(redactor.registeredCount).toBe(0);
  });
});

describe("grant retention", () => {
  it("evicts old closed grants but never an active one", () => {
    const redactor = new Redactor();
    const vault = new GrantVault(redactor, () => Date.now(), 5);
    const mintOne = (index: number) =>
      vault.mint({
        agentId: "a", runId: "run" + index, traceId: "t" + index,
        humanPrincipal: { kind: "human", id: "user:a", displayName: "A" },
        agentPrincipal: { kind: "agent", id: "agent:a", displayName: "A" },
        scopes, budget, ttlMs: 60_000,
      });

    const keptActive = mintOne(0);
    for (let index = 1; index <= 20; index += 1) {
      const minted = mintOne(index);
      vault.close(minted.grant.id, "run finished");
    }

    const remaining = vault.list();
    expect(remaining.length).toBeLessThanOrEqual(5);
    // The still-enforcing grant must survive eviction.
    expect(remaining.some((grant) => grant.id === keptActive.grant.id)).toBe(true);
    expect(vault.resolveByToken(keptActive.token)?.id).toBe(keptActive.grant.id);
  });

  it("keeps revoked grants, which are the evidence an operator looks at", () => {
    const redactor = new Redactor();
    const vault = new GrantVault(redactor, () => Date.now(), 3);
    const revoked = vault.mint({
      agentId: "a", runId: "r", traceId: "t",
      humanPrincipal: { kind: "human", id: "user:a", displayName: "A" },
      agentPrincipal: { kind: "agent", id: "agent:a", displayName: "A" },
      scopes, budget, ttlMs: 60_000,
    });
    vault.revoke(revoked.grant.id, "operator kill switch");
    for (let index = 0; index < 12; index += 1) {
      const minted = vault.mint({
        agentId: "a", runId: "r" + index, traceId: "t" + index,
        humanPrincipal: { kind: "human", id: "user:a", displayName: "A" },
        agentPrincipal: { kind: "agent", id: "agent:a", displayName: "A" },
        scopes, budget, ttlMs: 60_000,
      });
      vault.close(minted.grant.id, "run finished");
    }
    expect(vault.get(revoked.grant.id)?.status).toBe("revoked");
  });
});
