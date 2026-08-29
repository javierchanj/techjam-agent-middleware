/**
 * Warden — capability-scoped egress broker for Agent Runtimes.
 *
 * Every byte an Agent sends outside its container crosses exactly one boundary:
 * the Warden Gateway. These types describe who is asking (principals), what they
 * are allowed to reach (grants + scopes), what the broker decided (decisions),
 * and what evidence it produced (spans).
 */

export type PrincipalKind = "human" | "agent";

export interface Principal {
  kind: PrincipalKind;
  id: string;
  displayName: string;
}

/** Which enforcement plane a request arrived on. */
export type EgressPlane = "model" | "network";

/**
 * A single allowlist entry. `host` is either an exact hostname or a wildcard
 * suffix such as "*.svc.internal". Wildcards never match the bare parent domain.
 */
export interface EgressScope {
  plane: EgressPlane;
  host: string;
  ports: number[];
  /** Absent means "any method". Only meaningful on the model plane. */
  methods?: string[] | undefined;
  description?: string | undefined;
}

export interface Budget {
  maxModelCalls: number;
  maxTotalTokens: number;
  maxWallClockMs: number;
}

export interface BudgetUsage {
  modelCalls: number;
  networkCalls: number;
  totalTokens: number;
  /** True when at least one model call fell back to a byte-based token estimate. */
  estimated: boolean;
}

export type GrantStatus = "active" | "revoked" | "expired" | "exhausted" | "closed";

export interface Grant {
  id: string;
  /**
   * sha256 of the bearer token. The raw token is held in memory by the vault
   * for the grant's lifetime (it must unregister it from the redactor on
   * close) and is dropped there. It is never written to this record, the
   * ledger, the API or disk. Excluded from PublicGrant.
   */
  tokenHash: string;
  /** Short, non-reversible handle safe to show in UI, traces and screenshots. */
  tokenFingerprint: string;
  agentId: string;
  runId: string;
  traceId: string;
  humanPrincipal: Principal;
  agentPrincipal: Principal;
  scopes: EgressScope[];
  budget: Budget;
  usage: BudgetUsage;
  status: GrantStatus;
  statusReason: string | null;
  issuedAt: string;
  expiresAt: string;
  closedAt: string | null;
}

/** What the HTTP API returns. The token hash never leaves the broker. */
export type PublicGrant = Omit<Grant, "tokenHash">;

export type DenyCode =
  | "no_grant"
  | "grant_revoked"
  | "grant_expired"
  | "grant_closed"
  | "host_not_allowed"
  | "address_not_allowed"
  | "port_not_allowed"
  | "method_not_allowed"
  | "path_not_allowed"
  | "plane_not_allowed"
  | "address_not_allowed"
  | "authority_malformed"
  | "budget_calls_exhausted"
  | "budget_tokens_exhausted"
  | "budget_time_exhausted";

export interface PolicyRequest {
  plane: EgressPlane;
  host: string;
  port: number;
  method: string;
  path: string;
  /** Milliseconds since epoch, injected so policy stays a pure function. */
  nowMs: number;
}

export type PolicyDecision =
  | { effect: "allow"; matchedScope: EgressScope }
  | { effect: "deny"; code: DenyCode; message: string };

export type SpanKind =
  | "run"
  | "model_call"
  | "network_call"
  | "grant_lifecycle";

export type SpanStatus = "running" | "ok" | "denied" | "error";

export type SpanAttributeValue = string | number | boolean | null;

export interface WardenSpan {
  id: string;
  traceId: string;
  parentId: string | null;
  runId: string;
  agentId: string;
  kind: SpanKind;
  name: string;
  status: SpanStatus;
  startedAt: string;
  endedAt: string | null;
  durationMs: number | null;
  /** Already redacted before it reaches the ledger. */
  attributes: Record<string, SpanAttributeValue>;
}

export interface WardenTrace {
  traceId: string;
  runId: string;
  agentId: string;
  grantId: string | null;
  startedAt: string;
  endedAt: string | null;
  status: SpanStatus;
  spans: WardenSpan[];
}
