export type EgressPlane = "model" | "network";
export type SpanStatus = "running" | "ok" | "denied" | "error";
export type GrantStatus = "active" | "revoked" | "expired" | "exhausted" | "closed";

export interface EgressScope {
  plane: EgressPlane;
  host: string;
  ports: number[];
  description?: string;
}

export interface Budget {
  maxModelCalls: number;
  maxTotalTokens: number;
  maxWallClockMs: number;
}

export interface TemplateDescriptor {
  id: string;
  label: string;
  description: string;
  guarantees: string[];
  scopes: EgressScope[];
}

export interface PolicyCheckResult {
  allowed: boolean;
  code: string | null;
  message: string;
  matchedHost: string | null;
  matchedPlane: EgressPlane | null;
}

export interface WardenStatus {
  enabled: boolean;
  gatewayPort: number;
  containerNetwork: string;
  upstreamHost: string | null;
  policy: { scopes: EgressScope[]; budget: Budget; templateId: string | null };
  activeGrants: number;
}

export interface Grant {
  id: string;
  /** Safe to render. The grant token itself is never sent to the browser. */
  tokenFingerprint: string;
  agentId: string;
  runId: string;
  traceId: string;
  humanPrincipal: { id: string; displayName: string };
  agentPrincipal: { id: string; displayName: string };
  scopes: EgressScope[];
  budget: Budget;
  usage: {
    modelCalls: number;
    networkCalls: number;
    totalTokens: number;
    estimated: boolean;
  };
  status: GrantStatus;
  statusReason: string | null;
  issuedAt: string;
  expiresAt: string;
}

export interface WardenSpan {
  id: string;
  traceId: string;
  runId: string;
  agentId: string;
  kind: "run" | "model_call" | "network_call" | "grant_lifecycle";
  name: string;
  status: SpanStatus;
  startedAt: string;
  durationMs: number | null;
  attributes: Record<string, string | number | boolean | null>;
}

export interface TraceSummary {
  traceId: string;
  runId: string;
  agentId: string;
  grantId: string | null;
  status: SpanStatus;
  startedAt: string;
  spanCount: number;
  deniedCount: number;
}

/**
 * GET /api/warden/traces/:id returns the raw trace. spanCount and deniedCount
 * are computed server-side for the LIST response only, so this must not extend
 * TraceSummary or the type would promise fields the payload does not carry.
 */
export interface WardenTrace {
  traceId: string;
  runId: string;
  agentId: string;
  grantId: string | null;
  status: SpanStatus;
  startedAt: string;
  endedAt: string | null;
  spans: WardenSpan[];
}
