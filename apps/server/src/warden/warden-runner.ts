import type { WardenControl } from "./control.js";
import type { Redactor } from "./redact.js";
import { redactedMessage } from "./redact.js";
import type { AgentRunner, RunnerRequest, RunnerResult } from "../types.js";
import type { Principal } from "./types.js";

export interface WardenRunnerOptions {
  control: WardenControl;
  /** Archives finished traces so evidence outlives the broker container. */
  archive?: { append(trace: import("./types.js").WardenTrace): Promise<void> } | undefined;
  redactor: Redactor;
  /** Internal network the Runtime is attached to. It has no route off the host. */
  internalNetwork: string;
  /** DNS name of the broker on that network. Resolved by the container engine. */
  brokerHost: string;
  gatewayPort: number;
  /** Wall-clock ceiling. Enforced here because only here can we also kill the container. */
  maxWallClockMs: number;
}

const agentPrincipalFor = (agentId: string): Principal => ({
  kind: "agent",
  id: "agent:" + agentId,
  displayName: "Agent " + agentId.slice(0, 8),
});

const DEFAULT_HUMAN: Principal = {
  kind: "human",
  id: "user:local",
  displayName: "Local operator",
};

/**
 * Decorator around any AgentRunner. It owns the credential lifecycle for one run:
 *
 *   beginRun (mint) -> inject grant token + proxy config -> run -> endRun (close)
 *
 * Fail-closed: if the broker will not mint a grant, the run does not start.
 * Executing without a grant would mean executing without enforcement, which is
 * exactly the state Warden exists to prevent.
 */
export class WardenRunner implements AgentRunner {
  constructor(
    private readonly inner: AgentRunner,
    private readonly options: WardenRunnerOptions,
  ) {}

  /** Best effort: losing an archive write must never fail a run. */
  private async archive(traceId: string): Promise<void> {
    if (!this.options.archive) return;
    try {
      const trace = await this.options.control.getTrace(traceId);
      if (trace) await this.options.archive.append(trace);
    } catch {
      // Evidence archiving is not on the enforcement path.
    }
  }

  isAvailable(): Promise<boolean> {
    return this.inner.isAvailable();
  }

  cancel(agentId: string): Promise<boolean> {
    return this.inner.cancel(agentId);
  }

  async run(request: RunnerRequest): Promise<RunnerResult> {
    const { control, redactor } = this.options;
    const traceId = request.traceId;
    const runId = request.runId;
    if (!traceId || !runId) {
      throw new Error(
        "Warden requires a runId and a traceId assigned before execution. " +
          "The control plane must create the Run row first.",
      );
    }

    const begun = await control.beginRun({
      agentId: request.agentId,
      runId,
      traceId,
      humanPrincipal: request.actor ?? DEFAULT_HUMAN,
      agentPrincipal: agentPrincipalFor(request.agentId),
      workspacePath: request.workspacePath,
    });

    const proxyUrl =
      "http://grant:" +
      encodeURIComponent(begun.token) +
      "@" +
      this.options.brokerHost +
      ":" +
      this.options.gatewayPort;
    // The model request targets the broker directly (base_url override), so it
    // must NOT be sent through the broker as a proxy. Both cases are set because
    // proxy-variable handling is not standardised across HTTP clients.
    const noProxy = this.options.brokerHost + ",localhost,127.0.0.1";

    const deadline = setTimeout(() => {
      void control
        .revokeGrant(begun.grant.id, "wall-clock budget exhausted")
        .catch(() => undefined);
      void this.inner.cancel(request.agentId);
    }, this.options.maxWallClockMs);
    deadline.unref();

    try {
      const result = await this.inner.run({
        ...request,
        credentials: {
          // Run-scoped, metered, revocable. NOT the real Ark key.
          arkApiKey: begun.token,
          network: this.options.internalNetwork,
          extraEnv: {
            HTTP_PROXY: proxyUrl,
            HTTPS_PROXY: proxyUrl,
            http_proxy: proxyUrl,
            https_proxy: proxyUrl,
            NO_PROXY: noProxy,
            no_proxy: noProxy,
            // Node's fetch/undici ignores proxy environment variables unless
            // this is set (Node >= 22.21 / >= 24). Without it, Agent code
            // written in Node bypasses the proxy and fails at the network layer
            // instead of receiving an explainable Warden denial.
            NODE_USE_ENV_PROXY: "1",
            WARDEN_GRANT_FINGERPRINT: begun.grant.tokenFingerprint,
          },
        },
      });
      await control.endRun({
        traceId,
        grantId: begun.grant.id,
        runSpanId: begun.runSpanId,
        status: "ok",
      });
      await this.archive(traceId);
      return result;
    } catch (error) {
      const message = redactedMessage(redactor, error);
      const finalGrant = await control.getGrant(begun.grant.id).catch(() => null);
      const denied = finalGrant?.status === "revoked" || finalGrant?.status === "exhausted";
      await control
        .endRun({
          traceId,
          grantId: begun.grant.id,
          runSpanId: begun.runSpanId,
          status: denied ? "denied" : "error",
          error: message,
        })
        .catch(() => undefined);
      await this.archive(traceId);
      throw error instanceof Error ? Object.assign(error, { message }) : new Error(message);
    } finally {
      clearTimeout(deadline);
    }
  }
}
