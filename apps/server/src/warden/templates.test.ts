import { describe, expect, it } from "vitest";
import { InProcessWardenControl } from "./control.js";
import { GrantVault } from "./grants.js";
import { WardenLedger } from "./ledger.js";
import { WardenPolicyStore } from "./policy.js";
import { Redactor } from "./redact.js";
import { GRANT_TEMPLATES, describeTemplates, findTemplate } from "./templates.js";

function control() {
  const redactor = new Redactor();
  const policy = new WardenPolicyStore(
    [{ plane: "model", host: "ark.test", ports: [443], methods: ["POST"] }],
    { maxModelCalls: 5, maxTotalTokens: 1_000, maxWallClockMs: 60_000 },
  );
  return new InProcessWardenControl({
    vault: new GrantVault(redactor),
    ledger: new WardenLedger(redactor),
    policy,
    grantTtlMs: 10_000,
    gatewayPort: 8788,
    internalNetwork: "net",
    upstreamHost: "ark.test",
    upstreamPort: 443,
  });
}

describe("grant templates", () => {
  it("never claims an enforcement it cannot deliver", () => {
    // Method-level control is impossible through a CONNECT tunnel, so no
    // template may be named "read-only".
    for (const template of GRANT_TEMPLATES) {
      expect(template.id).not.toMatch(/read-?only/i);
      expect(template.label).not.toMatch(/read-?only/i);
    }
    const github = findTemplate("model-plus-github");
    expect(github?.guarantees.join(" ")).toMatch(/NOT inspected/);
  });

  it("model-only permits inference and nothing else", () => {
    const scopes = findTemplate("model-only")?.build("ark.test", 443) ?? [];
    expect(scopes).toHaveLength(1);
    expect(scopes[0]?.plane).toBe("model");
  });

  it("fully offline permits nothing at all", () => {
    expect(findTemplate("no-external-network")?.build("ark.test", 443)).toEqual([]);
  });

  it("describes templates without leaking the build function to the API", () => {
    const described = describeTemplates("ark.test", 443);
    expect(described).toHaveLength(GRANT_TEMPLATES.length);
    expect(JSON.stringify(described)).not.toContain("function");
  });

  it("applying a template changes what the next run is delegated", async () => {
    const c = control();
    await c.applyTemplate("model-plus-github");
    const policy = await c.getPolicy();
    expect(policy.templateId).toBe("model-plus-github");
    expect(policy.scopes.some((scope) => scope.host === "api.github.com")).toBe(true);
  });

  it("rejects an unknown template", async () => {
    await expect(control().applyTemplate("root-access")).rejects.toThrow(/Unknown grant template/);
  });
});

describe("dry-run policy check", () => {
  it("reports a denial without minting a grant or spending budget", async () => {
    const c = control();
    const result = await c.checkPolicy({
      plane: "network",
      host: "attacker.example.net",
      port: 443,
      method: "CONNECT",
    });
    expect(result.allowed).toBe(false);
    expect(result.code).toBe("plane_not_allowed");
    expect(await c.listGrants()).toHaveLength(0);
  });

  it("agrees with the enforcement path after a template is applied", async () => {
    const c = control();
    await c.applyTemplate("model-plus-github");
    const allowed = await c.checkPolicy({
      plane: "network",
      host: "api.github.com",
      port: 443,
      method: "CONNECT",
    });
    expect(allowed).toMatchObject({ allowed: true, matchedHost: "api.github.com" });

    const denied = await c.checkPolicy({
      plane: "network",
      host: "api.github.com.evil.net",
      port: 443,
      method: "CONNECT",
    });
    expect(denied).toMatchObject({ allowed: false, code: "host_not_allowed" });
  });

  it("refuses a private literal even under the most permissive template", async () => {
    const c = control();
    await c.applyTemplate("model-plus-github");
    const result = await c.checkPolicy({
      plane: "network",
      host: "169.254.169.254",
      port: 80,
      method: "CONNECT",
    });
    expect(result.allowed).toBe(false);
  });
});

describe('dry-run plane "any"', () => {
  it("reports the model host as ALLOWED, matching what the panel lists", async () => {
    // Checking only the network plane reported the model host as denied while
    // the panel listed it as reachable, which reads as a contradiction.
    const c = control();
    const result = await c.checkPolicy({
      plane: "any",
      host: "ark.test",
      port: 443,
      method: "CONNECT",
    });
    expect(result).toMatchObject({ allowed: true, matchedPlane: "model" });
  });

  it("still denies a host on neither plane, with the specific reason", async () => {
    const result = await control().checkPolicy({
      plane: "any",
      host: "attacker.example.net",
      port: 443,
      method: "CONNECT",
    });
    expect(result.allowed).toBe(false);
    expect(result.matchedPlane).toBeNull();
    // Not the vaguer "plane_not_allowed".
    expect(result.code).toBe("host_not_allowed");
  });

  it("finds a network host once a template grants one", async () => {
    const c = control();
    await c.applyTemplate("model-plus-github");
    const result = await c.checkPolicy({
      plane: "any",
      host: "api.github.com",
      port: 443,
      method: "CONNECT",
    });
    expect(result).toMatchObject({ allowed: true, matchedPlane: "network" });
  });
});

describe("dry run agrees with the panel on a non-default model port", () => {
  it("uses the model scope's own port rather than the UI's assumed 443", async () => {
    const redactor = new Redactor();
    // An ARK_BASE_URL on a custom port, e.g. a proxied or self-hosted endpoint.
    const policy = new WardenPolicyStore(
      [{ plane: "model", host: "ark.internal", ports: [8443], methods: ["POST"] }],
      { maxModelCalls: 5, maxTotalTokens: 1_000, maxWallClockMs: 60_000 },
    );
    const c = new InProcessWardenControl({
      vault: new GrantVault(redactor),
      ledger: new WardenLedger(redactor),
      policy,
      grantTtlMs: 10_000,
      gatewayPort: 8788,
      internalNetwork: "net",
      upstreamHost: "ark.internal",
      upstreamPort: 8443,
    });
    // The panel lists ark.internal:8443 as reachable, so the check must agree
    // even though the UI sends the default 443.
    const result = await c.checkPolicy({
      plane: "any",
      host: "ark.internal",
      port: 443,
      method: "CONNECT",
    });
    expect(result).toMatchObject({ allowed: true, matchedPlane: "model" });
  });
});

describe("granting a capability the Agent actually asked for", () => {
  it("model-plus-dev-tools permits the npm registry that model-only refused", async () => {
    // A real run showed the Agent attempting `npm install` five times and being
    // refused. That is correct under model-only, but an operator must be able
    // to GRANT the capability rather than only observe it being denied.
    const c = control();
    const before = await c.checkPolicy({
      plane: "any", host: "registry.npmjs.org", port: 443, method: "CONNECT",
    });
    expect(before.allowed).toBe(false);

    await c.applyTemplate("model-plus-dev-tools");
    const after = await c.checkPolicy({
      plane: "any", host: "registry.npmjs.org", port: 443, method: "CONNECT",
    });
    expect(after).toMatchObject({ allowed: true, matchedPlane: "network" });
  });

  it("still refuses everything outside the granted set", async () => {
    const c = control();
    await c.applyTemplate("model-plus-dev-tools");
    for (const host of ["ab.chatgpt.com", "attacker.example.net", "registry.npmjs.org.evil.net"]) {
      const result = await c.checkPolicy({ plane: "any", host, port: 443, method: "CONNECT" });
      expect(result.allowed).toBe(false);
    }
  });

  it("does not silently widen the model plane", async () => {
    const c = control();
    await c.applyTemplate("model-plus-dev-tools");
    const scopes = (await c.getPolicy()).scopes.filter((scope) => scope.plane === "model");
    expect(scopes).toHaveLength(1);
  });
});

describe("policy administration is audited", () => {
  it("records who widened the policy, and from what", async () => {
    // Applying a template is the one action that can loosen the whole system.
    // Leaving it unattributed would make it the only decision Warden does not
    // record.
    const c = control();
    await c.applyTemplate("model-only", "user:alice");
    await c.applyTemplate("model-plus-dev-tools", "user:bob");

    const changes = await c.listPolicyChanges();
    expect(changes).toHaveLength(2);
    // Newest first.
    expect(changes[0]).toMatchObject({
      actorId: "user:bob",
      fromTemplate: "model-only",
      toTemplate: "model-plus-dev-tools",
    });
    expect(changes[0]?.scopeSummary).toContain("network:registry.npmjs.org");
    expect(changes[1]).toMatchObject({ actorId: "user:alice", fromTemplate: null });
  });

  it("defaults to the local operator when no actor is supplied", async () => {
    const c = control();
    await c.applyTemplate("model-only");
    expect((await c.listPolicyChanges())[0]?.actorId).toBe("user:local");
  });

  it("records the fully offline profile as granting no egress", async () => {
    const c = control();
    await c.applyTemplate("no-external-network", "user:alice");
    expect((await c.listPolicyChanges())[0]?.scopeSummary).toBe("no egress");
  });

  it("does not record a change when the template is unknown", async () => {
    const c = control();
    await expect(c.applyTemplate("root-access", "user:mallory")).rejects.toThrow();
    expect(await c.listPolicyChanges()).toHaveLength(0);
  });
});
