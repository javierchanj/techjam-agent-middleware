import type {
  BeginRunInput,
  BeginRunResult,
  EndRunInput,
  PolicyChangeRecord,
  PolicyCheckInput,
  PolicyCheckResult,
  PolicySnapshot,
  TemplateDescriptor,
  WardenControl,
  WardenControlStatus,
} from "./control.js";
import type { BudgetPatch } from "./policy.js";
import type { Budget, EgressPlane, EgressScope, Grant, WardenTrace } from "./types.js";

/**
 * Control-plane side of the channel. Talks to the broker over loopback.
 *
 * Every method throws on failure rather than degrading. A control plane that
 * silently continues when the broker is unreachable would run Agents with no
 * enforcement, which is the failure mode Warden must never have.
 */
export class RemoteWardenControl implements WardenControl {
  constructor(
    private readonly baseUrl: string,
    private readonly secret: string,
    private readonly timeoutMs = 10_000,
  ) {}

  private async call<T>(path: string, init?: RequestInit): Promise<T> {
    const response = await fetch(this.baseUrl + path, {
      ...init,
      headers: {
        authorization: "Bearer " + this.secret,
        ...(init?.body ? { "content-type": "application/json" } : {}),
        ...init?.headers,
      },
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    const payload = (await response.json().catch(() => ({}))) as T & { error?: string };
    if (!response.ok) {
      throw new Error(payload.error ?? "Warden control call failed: " + path);
    }
    return payload;
  }

  async health(): Promise<boolean> {
    try {
      const response = await fetch(this.baseUrl + "/control/health", {
        signal: AbortSignal.timeout(2_000),
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  beginRun(input: BeginRunInput): Promise<BeginRunResult> {
    return this.call<BeginRunResult>("/control/runs", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  async endRun(input: EndRunInput): Promise<Grant | null> {
    const result = await this.call<{ grant: Grant | null }>("/control/runs/end", {
      method: "POST",
      body: JSON.stringify(input),
    });
    return result.grant;
  }

  async revokeGrant(grantId: string, reason: string): Promise<Grant | null> {
    const result = await this.call<{ grant: Grant | null }>("/control/grants/revoke", {
      method: "POST",
      body: JSON.stringify({ grantId, reason }),
    });
    return result.grant;
  }

  async getGrant(grantId: string): Promise<Grant | null> {
    const result = await this.call<{ grant: Grant | null }>(
      "/control/grants?id=" + encodeURIComponent(grantId),
    );
    return result.grant;
  }

  async listGrants(): Promise<Grant[]> {
    return (await this.call<{ grants: Grant[] }>("/control/grants")).grants;
  }

  async listTraces(agentId?: string | undefined): Promise<WardenTrace[]> {
    const query = agentId ? "?agentId=" + encodeURIComponent(agentId) : "";
    return (await this.call<{ traces: WardenTrace[] }>("/control/traces" + query)).traces;
  }

  async getTrace(traceId: string): Promise<WardenTrace | null> {
    const result = await this.call<{ trace: WardenTrace | null }>(
      "/control/traces?id=" + encodeURIComponent(traceId),
    );
    return result.trace;
  }

  getPolicy(): Promise<PolicySnapshot> {
    return this.call<PolicySnapshot>("/control/policy");
  }

  listTemplates(): Promise<TemplateDescriptor[]> {
    return this.call<TemplateDescriptor[]>("/control/templates");
  }

  applyTemplate(id: string, actorId?: string | undefined): Promise<PolicySnapshot> {
    return this.call<PolicySnapshot>("/control/policy/template", {
      method: "POST",
      body: JSON.stringify({ id, actorId }),
    });
  }

  listPolicyChanges(): Promise<PolicyChangeRecord[]> {
    return this.call<PolicyChangeRecord[]>("/control/policy/history");
  }

  checkPolicy(input: PolicyCheckInput): Promise<PolicyCheckResult> {
    return this.call<PolicyCheckResult>("/control/policy/check", {
      method: "POST",
      body: JSON.stringify(input),
    });
  }

  status(): Promise<WardenControlStatus> {
    return this.call<WardenControlStatus>("/control/status");
  }
}
