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