import type { GrantVault } from "./grants.js";
import type { WardenLedger } from "./ledger.js";
import { evaluate, type WardenPolicyStore } from "./policy.js";
import { describeTemplates, findTemplate } from "./templates.js";
import type {
  Budget,
  EgressPlane,
  EgressScope,
  Grant,
  Principal,
  SpanStatus,
  WardenTrace,
} from "./types.js";

/**
 * The control channel between the untrusted-facing broker and the control plane.
 *
 * Warden runs as a dual-homed broker container: it is the ONLY member of both
 * the internal Runtime network and an egress network. That means the vault, the
 * ledger and the policy store live inside the broker process, and the Fastify
 * control plane reaches them over this interface.
 *
 * Two implementations:
 *   InProcessWardenControl — used inside the broker, and in tests.
 *   RemoteWardenControl    — used by the control plane, over loopback HTTP.
 */

export interface BeginRunInput {
  agentId: string;
  runId: string;
  /** Assigned by the control plane BEFORE execution so a failed run still links. */
  traceId: string;
  humanPrincipal: Principal;
  agentPrincipal: Principal;
  workspacePath: string;
}

export interface BeginRunResult {
  grant: Grant;
  /** Returned once, over loopback only. Never persisted, never rendered. */
  token: string;
  runSpanId: string;
}

export interface EndRunInput {
  traceId: string;
  grantId: string;
  runSpanId: string;
  status: SpanStatus;
  error?: string | null | undefined;
}

export interface PolicySnapshot {
  scopes: EgressScope[];
  budget: Budget;
  templateId: string | null;
}

export interface PolicyCheckInput {
  /**
   * "any" asks the question an operator actually means: is this destination
   * reachable AT ALL. Checking only the network plane reports the model host as
   * denied even while the panel lists it as reachable, which reads as a
   * contradiction.
   */
  plane: EgressPlane | "any";
  host: string;
  port: number;
  method: string;
}

/**
 * Result of a dry-run check. Answers "would a fresh grant be allowed to reach
 * this?" without minting anything, spending budget, or opening a socket.
 */
export interface PolicyCheckResult {
  allowed: boolean;
  code: string | null;
  message: string;
  matchedHost: string | null;
  /** Which plane answered. Null when nothing permitted the destination. */
  matchedPlane: EgressPlane | null;
}

/**
 * Applying a template widens or narrows what every subsequent run is delegated.
 * That is an administrative act on the enforcement policy, so it is attributed
 * and retained like any other decision Warden makes -- otherwise the one action
 * that can loosen the whole system is the only one with no record.
 */
export interface PolicyChangeRecord {
  at: string;
  actorId: string;
  fromTemplate: string | null;
  toTemplate: string;
  scopeSummary: string;
}

export interface TemplateDescriptor {
  id: string;
  label: string;
  description: string;
  guarantees: string[];
  scopes: EgressScope[];
}

export interface WardenControlStatus {
  ok: boolean;
  gatewayPort: number;
  upstreamHost: string | null;
  internalNetwork: string;
  activeGrants: number;
  policy: PolicySnapshot;
}

export interface WardenControl {
  beginRun(input: BeginRunInput): Promise<BeginRunResult>;
  endRun(input: EndRunInput): Promise<Grant | null>;
  revokeGrant(grantId: string, reason: string): Promise<Grant | null>;
  getGrant(grantId: string): Promise<Grant | null>;
  listGrants(): Promise<Grant[]>;
  listTraces(agentId?: string | undefined): Promise<WardenTrace[]>;
  getTrace(traceId: string): Promise<WardenTrace | null>;
  getPolicy(): Promise<PolicySnapshot>;
  listTemplates(): Promise<TemplateDescriptor[]>;
  applyTemplate(id: string, actorId?: string | undefined): Promise<PolicySnapshot>;
  listPolicyChanges(): Promise<PolicyChangeRecord[]>;
  checkPolicy(input: PolicyCheckInput): Promise<PolicyCheckResult>;
  status(): Promise<WardenControlStatus>;
}

export interface InProcessControlOptions {
  vault: GrantVault;
  ledger: WardenLedger;
  policy: WardenPolicyStore;
  grantTtlMs: number;
  gatewayPort: number;
  /** Invoked on revocation so live tunnels and streams are torn down. */
  onGrantRevoked?: ((grantId: string) => number) | undefined;
  internalNetwork: string;
  upstreamHost: string | null;
  upstreamPort?: number | undefined;
}

/**
 * Owns the run/grant lifecycle so the caller needs exactly two round trips:
 * beginRun and endRun. Every span the middleware emits is written here or by
 * the gateway — never by the control plane, which is not on the enforcement path.
 */
export class InProcessWardenControl implements WardenControl {
  private templateId: string | null = null;
  private readonly policyChanges: PolicyChangeRecord[] = [];

  constructor(private readonly options: InProcessControlOptions) {}

  async beginRun(input: BeginRunInput): Promise<BeginRunResult> {
    const { ledger, vault, policy } = this.options;
    const baseline = policy.snapshot();

    ledger.beginTrace({
      traceId: input.traceId,
      runId: input.runId,
      agentId: input.agentId,
    });
    const runSpanId = ledger.startSpan({
      traceId: input.traceId,
      runId: input.runId,
      agentId: input.agentId,
      kind: "run",
      name: "agent.run",
      attributes: {
        human_principal: input.humanPrincipal.id,
        agent_principal: input.agentPrincipal.id,
        // Basename only: absolute host paths are operator infrastructure detail
        // and do not belong in evidence that may be exported or screenshotted.
        workspace: input.workspacePath.split(/[\\/]/).filter(Boolean).pop() ?? "workspace",
        scopes: baseline.scopes
          .map((scope) => scope.plane + ":" + scope.host + ":" + scope.ports.join("|"))
          .join(", "),
      },
    });

    const { grant, token } = vault.mint({
      agentId: input.agentId,
      runId: input.runId,
      traceId: input.traceId,
      humanPrincipal: input.humanPrincipal,
      agentPrincipal: input.agentPrincipal,
      scopes: baseline.scopes,
      budget: baseline.budget,
      ttlMs: this.options.grantTtlMs,
    });
    ledger.attachGrant(input.traceId, grant.id);
    ledger.recordEvent({
      traceId: input.traceId,
      runId: input.runId,
      agentId: input.agentId,
      kind: "grant_lifecycle",
      name: "grant.minted",
      status: "ok",
      attributes: {
        grant_id: grant.id,
        grant_fingerprint: grant.tokenFingerprint,
        expires_at: grant.expiresAt,
        max_model_calls: grant.budget.maxModelCalls,
        // Soft budget: metered after each response, enforced on the NEXT call.
        soft_token_budget: grant.budget.maxTotalTokens,
        max_wall_clock_ms: grant.budget.maxWallClockMs,
      },
    });

    return { grant, token, runSpanId };
  }

  async endRun(input: EndRunInput): Promise<Grant | null> {
    const { ledger, vault } = this.options;
    const beforeClose = vault.get(input.grantId);
    ledger.endSpan(input.traceId, input.runSpanId, {
      status: input.status,
      attributes: {
        grant_status: beforeClose?.status ?? "unknown",
        grant_status_reason: beforeClose?.statusReason ?? null,
        model_calls: beforeClose?.usage.modelCalls ?? 0,
        network_calls: beforeClose?.usage.networkCalls ?? 0,
        tokens_used: beforeClose?.usage.totalTokens ?? 0,
        tokens_estimated: beforeClose?.usage.estimated ?? false,
        ...(input.error ? { error: input.error } : {}),
      },
    });
    const closed = vault.close(input.grantId, "run finished");
    ledger.recordEvent({
      traceId: input.traceId,
      runId: beforeClose?.runId ?? input.traceId,
      agentId: beforeClose?.agentId ?? "unknown",
      kind: "grant_lifecycle",
      name: "grant.closed",
      status: "ok",
      attributes: { grant_id: input.grantId, status: closed?.status ?? "closed" },
    });
    ledger.endTrace(input.traceId, input.status);
    return closed;
  }

  async revokeGrant(grantId: string, reason: string): Promise<Grant | null> {
    const grant = this.options.vault.revoke(grantId, reason);
    if (!grant) return null;
    const terminated = this.options.onGrantRevoked?.(grantId) ?? 0;
    this.options.ledger.recordEvent({
      traceId: grant.traceId,
      runId: grant.runId,
      agentId: grant.agentId,
      kind: "grant_lifecycle",
      name: "grant.revoked",
      status: "denied",
      attributes: { grant_id: grant.id, reason, connections_terminated: terminated },
    });
    return grant;
  }

  async getGrant(grantId: string): Promise<Grant | null> {
    return this.options.vault.get(grantId);
  }

  async listGrants(): Promise<Grant[]> {
    return this.options.vault.list();
  }

  async listTraces(agentId?: string | undefined): Promise<WardenTrace[]> {
    return this.options.ledger.listTraces(agentId ? { agentId } : {});
  }

  async getTrace(traceId: string): Promise<WardenTrace | null> {
    return this.options.ledger.getTrace(traceId);
  }

  async getPolicy(): Promise<PolicySnapshot> {
    return { ...this.options.policy.snapshot(), templateId: this.templateId };
  }

  async listPolicyChanges(): Promise<PolicyChangeRecord[]> {
    return [...this.policyChanges].reverse();
  }

  async listTemplates(): Promise<TemplateDescriptor[]> {
    return describeTemplates(this.options.upstreamHost ?? "", this.options.upstreamPort ?? 443);
  }

  async applyTemplate(id: string, actorId?: string | undefined): Promise<PolicySnapshot> {
    const template = findTemplate(id);
    if (!template) throw new Error("Unknown grant template: " + id);
    const previous = this.templateId;
    const scopes = template.build(
      this.options.upstreamHost ?? "",
      this.options.upstreamPort ?? 443,
    );
    this.options.policy.setScopes(scopes);
    this.templateId = id;
    this.policyChanges.push({
      at: new Date().toISOString(),
      actorId: actorId ?? "user:local",
      fromTemplate: previous,
      toTemplate: id,
      scopeSummary:
        scopes.length === 0
          ? "no egress"
          : scopes.map((scope) => scope.plane + ":" + scope.host).join(", "),
    });
    // Bounded: this is an audit tail, not an archive.
    if (this.policyChanges.length > 100) this.policyChanges.shift();
    // Existing grants keep the scopes they were minted with. Templates change
    // what the NEXT run is delegated, which keeps a run's authority stable
    // for its whole lifetime.
    return this.getPolicy();
  }

  /**
   * Dry run. Evaluates against a synthetic grant built from the current policy,
   * so it reports exactly what the enforcement path would decide without
   * minting a grant or reserving any budget.
   */
  async checkPolicy(input: PolicyCheckInput): Promise<PolicyCheckResult> {
    const snapshot = this.options.policy.snapshot();
    const now = Date.now();
    const synthetic: Grant = {
      id: "grant_dry_run",
      tokenHash: "",
      tokenFingerprint: "dryrun",
      agentId: "dry-run",
      runId: "dry-run",
      traceId: "dry-run",
      humanPrincipal: { kind: "human", id: "user:dry-run", displayName: "Dry run" },
      agentPrincipal: { kind: "agent", id: "agent:dry-run", displayName: "Dry run" },
      scopes: snapshot.scopes,
      budget: snapshot.budget,
      usage: { modelCalls: 0, networkCalls: 0, totalTokens: 0, estimated: false },
      status: "active",
      statusReason: null,
      issuedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 60_000).toISOString(),
      closedAt: null,
    };
    const planes: EgressPlane[] =
      input.plane === "any" ? ["model", "network"] : [input.plane];

    let lastDenial: { code: string; message: string } | null = null;
    for (const plane of planes) {
      // The UI cannot know which port the model plane runs on, so it always
      // sends 443. Use the scope's declared port instead, or a custom
      // ARK_BASE_URL port would make the dry run contradict the panel above it.
      const modelPort = snapshot.scopes.find((scope) => scope.plane === "model")?.ports[0];
      const port = plane === "model" && modelPort !== undefined ? modelPort : input.port;
      const decision = evaluate(synthetic, {
        plane,
        host: input.host,
        port,
        method: plane === "model" ? "POST" : input.method,
        path: plane === "model" ? "/v1/responses" : "",
        nowMs: now,
      });
      if (decision.effect === "allow") {
        return {
          allowed: true,
          code: null,
          message:
            "Allowed on the " + plane + " plane by scope " + decision.matchedScope.host,
          matchedHost: decision.matchedScope.host,
          matchedPlane: plane,
        };
      }
      // Prefer the most specific denial. "no capability on this plane at all" is
      // less informative than "this host is not on the list".
      if (!lastDenial || decision.code !== "plane_not_allowed") {
        lastDenial = { code: decision.code, message: decision.message };
      }
    }
    return {
      allowed: false,
      code: lastDenial?.code ?? "host_not_allowed",
      message: lastDenial?.message ?? "Destination is not permitted.",
      matchedHost: null,
      matchedPlane: null,
    };
  }

  async status(): Promise<WardenControlStatus> {
    return {
      ok: true,
      gatewayPort: this.options.gatewayPort,
      upstreamHost: this.options.upstreamHost,
      internalNetwork: this.options.internalNetwork,
      activeGrants: this.options.vault.list().filter((grant) => grant.status === "active").length,
      policy: await this.getPolicy(),
    };
  }
}
