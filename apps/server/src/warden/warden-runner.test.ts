import { describe, expect, it, vi } from "vitest";
import { InProcessWardenControl } from "./control.js";
import { GrantVault } from "./grants.js";
import { WardenLedger } from "./ledger.js";
import { WardenPolicyStore } from "./policy.js";
import { Redactor } from "./redact.js";
import { WardenRunner } from "./warden-runner.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "../types.js";
import type { Budget, EgressScope } from "./types.js";

const REAL_KEY = "ark_live_host_only_secret_value_9";

const scopes: EgressScope[] = [
  { plane: "model", host: "ark.test", ports: [443], methods: ["POST"] },
];
const budget: Budget = { maxModelCalls: 5, maxTotalTokens: 1_000, maxWallClockMs: 5_000 };

function harness(inner: AgentRunner) {
  const redactor = new Redactor();
  redactor.register(REAL_KEY, "ark_api_key");
  const ledger = new WardenLedger(redactor);
  const vault = new GrantVault(redactor);
  const policy = new WardenPolicyStore(scopes, budget);
  const control = new InProcessWardenControl({
    vault,
    ledger,
    policy,
    grantTtlMs: 10_000,
    gatewayPort: 8788,
    internalNetwork: "launchpad-warden-internal",
    upstreamHost: "ark.test",
  });
  const runner = new WardenRunner(inner, {
    control,
    redactor,
    internalNetwork: "launchpad-warden-internal",
    brokerHost: "warden-broker",
    gatewayPort: 8788,
    maxWallClockMs: budget.maxWallClockMs,
  });
  return { runner, vault, ledger, control };
}

const request: RunnerRequest = {
  agentId: "agent_1",
  workspacePath: "/tmp/ws",
  prompt: "build something",
  threadId: null,
  runId: "run_1",
  traceId: "trace_1",
  actor: { kind: "human", id: "user:alice", displayName: "Alice" },
};

const okRunner = (): AgentRunner => ({
  run: async () => ({ output: "done", threadId: null, usage: null }),
  cancel: async () => true,
  isAvailable: async () => true,
});

describe("WardenRunner", () => {
  it("hands the Runtime a minted token and broker routing, never the real key", async () => {
    let seen: RunnerRequest | null = null;
    const inner: AgentRunner = {
      run: async (input) => {
        seen = input;
        return { output: "done", threadId: "t1", usage: null } satisfies RunnerResult;
      },
      cancel: async () => true,
      isAvailable: async () => true,
    };
    const { runner } = harness(inner);
    await runner.run(request);

    const captured = seen as RunnerRequest | null;
    expect(captured?.credentials?.arkApiKey.startsWith("wgt_")).toBe(true);
    expect(captured?.credentials?.arkApiKey).not.toBe(REAL_KEY);
    expect(captured?.credentials?.network).toBe("launchpad-warden-internal");
    expect(captured?.credentials?.extraEnv?.HTTPS_PROXY).toContain("warden-broker:8788");
  });

  it("excludes the broker from proxying, in both env-var cases", async () => {
    let seen: RunnerRequest | null = null;
    const inner: AgentRunner = {
      run: async (input) => {
        seen = input;
        return { output: "done", threadId: null, usage: null };
      },
      cancel: async () => true,
      isAvailable: async () => true,
    };
    const { runner } = harness(inner);
    await runner.run(request);
    const env = (seen as RunnerRequest | null)?.credentials?.extraEnv;
    // The model call addresses the broker directly, so it must not be sent
    // through the broker as a proxy.
    expect(env?.NO_PROXY).toContain("warden-broker");
    expect(env?.no_proxy).toContain("warden-broker");
    expect(env?.http_proxy).toBe(env?.HTTP_PROXY);
    expect(env?.https_proxy).toBe(env?.HTTPS_PROXY);
  });

  it("exposes only a fingerprint to the Runtime, never the raw grant token", async () => {
    let seen: RunnerRequest | null = null;
    const inner: AgentRunner = {
      run: async (input) => {
        seen = input;
        return { output: "done", threadId: null, usage: null };
      },
      cancel: async () => true,
      isAvailable: async () => true,
    };
    const { runner, vault } = harness(inner);
    await runner.run(request);
    const fingerprint = (seen as RunnerRequest | null)?.credentials?.extraEnv
      ?.WARDEN_GRANT_FINGERPRINT;
    expect(fingerprint).toHaveLength(8);
    expect(vault.list()[0]?.tokenFingerprint).toBe(fingerprint);
  });

  it("refuses to run without a pre-assigned runId and traceId", async () => {
    const { runner } = harness(okRunner());
    await expect(
      runner.run({ ...request, runId: undefined, traceId: undefined }),
    ).rejects.toThrow(/assigned before execution/);
  });

  it("closes the grant when the run finishes, so a leaked token is worthless", async () => {
    const { runner, vault } = harness(okRunner());
    await runner.run(request);
    expect(vault.list()[0]?.status).toBe("closed");
  });

  it("emits a correlated trace under the pre-assigned trace id", async () => {
    const { runner, ledger } = harness(okRunner());
    await runner.run(request);
    const trace = ledger.getTrace("trace_1");
    expect(trace?.status).toBe("ok");
    expect(trace?.runId).toBe("run_1");
    expect(trace?.grantId).toBeTruthy();
    expect(trace?.spans.map((span) => span.name)).toEqual(
      expect.arrayContaining(["agent.run", "grant.minted", "grant.closed"]),
    );
    expect(trace?.spans.find((span) => span.name === "agent.run")?.attributes.human_principal).toBe(
      "user:alice",
    );
  });

  it("links a FAILED run to its trace, because the id existed before execution", async () => {
    const inner: AgentRunner = {
      run: async () => {
        throw new Error("upstream rejected credential " + REAL_KEY);
      },
      cancel: async () => true,
      isAvailable: async () => true,
    };
    const { runner, ledger } = harness(inner);
    await expect(runner.run(request)).rejects.toThrow(/redacted:ark_api_key/);
    const trace = ledger.getTrace("trace_1");
    expect(trace?.status).toBe("error");
    expect(JSON.stringify(trace)).not.toContain(REAL_KEY);
  });

  it("fails the run closed when the broker will not mint a grant", async () => {
    const { runner, control } = harness(okRunner());
    vi.spyOn(control, "beginRun").mockRejectedValue(new Error("broker unreachable"));
    await expect(runner.run(request)).rejects.toThrow(/broker unreachable/);
  });

  it("revokes the grant and cancels the container when the wall-clock budget expires", async () => {
    vi.useFakeTimers();
    const cancel = vi.fn(async () => true);
    let release: (() => void) | null = null;
    const inner: AgentRunner = {
      run: async () => {
        await new Promise<void>((resolve) => {
          release = resolve;
        });
        throw new Error("Runtime cancelled by Warden");
      },
      cancel,
      isAvailable: async () => true,
    };
    const { runner, vault } = harness(inner);
    const pending = runner.run(request).catch((error: unknown) => error);
    await vi.advanceTimersByTimeAsync(budget.maxWallClockMs + 10);
    expect(cancel).toHaveBeenCalledWith("agent_1");
    expect(vault.list()[0]?.status).toBe("revoked");
    release?.();
    await pending;
    vi.useRealTimers();
  });
});

describe("run output cannot leak the grant token", () => {
  const leakingRunner = (): AgentRunner => ({
    // Simulates `echo $ARK_API_KEY` -- the Agent can read its own environment.
    run: async (input) => ({
      output:
        "Here is what I found:\nARK_API_KEY=" +
        (input.credentials?.arkApiKey ?? "") +
        "\nproxy=" +
        (input.credentials?.extraEnv?.HTTPS_PROXY ?? ""),
      threadId: null,
      usage: null,
    }),
    cancel: async () => true,
    isAvailable: async () => true,
  });

  it("redacts the token from a SUCCESSFUL run's output", async () => {
    const { runner, vault } = harness(leakingRunner());
    const result = await runner.run(request);
    const token = vault.list()[0];
    expect(result.output).not.toMatch(/wgt_[A-Za-z0-9_-]{20,}/);
    expect(result.output).toContain("[redacted:warden_grant_token]");
    expect(token).toBeDefined();
  });

  it("redacts the proxy URL, which embeds the token as userinfo", async () => {
    const { runner } = harness(leakingRunner());
    const result = await runner.run(request);
    // http://grant:<token>@warden-broker:8788 would otherwise carry it through.
    expect(result.output).not.toMatch(/grant:wgt_/);
  });

  it("leaves ordinary output untouched", async () => {
    const inner: AgentRunner = {
      run: async () => ({ output: "Created src/cli.ts and added a test.", threadId: null, usage: null }),
      cancel: async () => true,
      isAvailable: async () => true,
    };
    const { runner } = harness(inner);
    const result = await runner.run(request);
    expect(result.output).toBe("Created src/cli.ts and added a test.");
  });
});
