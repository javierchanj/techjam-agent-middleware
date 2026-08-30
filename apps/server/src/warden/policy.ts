import type {
  Budget,
  EgressScope,
  Grant,
  PolicyDecision,
  PolicyRequest,
} from "./types.js";

/**
 * The Policy Decision Point.
 *
 * `evaluate` is deliberately pure: no clock, no I/O, no store. The gateway
 * supplies `nowMs` and the grant snapshot, which makes every allow/deny path
 * unit-testable without a container, a socket, or a model call.
 */

export function normalizeHost(host: string): string {
  const withoutBrackets = host.replace(/^\[|\]$/g, "");
  const withoutPort = withoutBrackets.includes(":") && !withoutBrackets.includes("::")
    ? (withoutBrackets.split(":")[0] ?? withoutBrackets)
    : withoutBrackets;
  return withoutPort.trim().toLowerCase().replace(/\.$/, "");
}

/**
 * Exact match, or wildcard suffix match for patterns beginning "*.".
 * "*.example.com" matches "a.example.com" and "a.b.example.com"
 * but NOT the bare "example.com" — parent domains must be listed explicitly.
 */
export function matchHost(pattern: string, host: string): boolean {
  const normalizedPattern = pattern.trim().toLowerCase().replace(/\.$/, "");
  const normalizedHost = normalizeHost(host);
  if (normalizedPattern === "") return false;
  if (normalizedPattern === normalizedHost) return true;
  if (!normalizedPattern.startsWith("*.")) return false;
  const suffix = normalizedPattern.slice(1); // ".example.com"
  return normalizedHost.endsWith(suffix) && normalizedHost.length > suffix.length;
}

const BLOCKED_V4 = [
  /^127\./,                                   // loopback
  /^0\./,                                     // this-network
  /^10\./,                                    // RFC1918
  /^192\.168\./,                              // RFC1918
  /^172\.(1[6-9]|2\d|3[01])\./,                // RFC1918
  /^169\.254\./,                              // link-local, incl. cloud metadata
  /^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./,  // CGNAT
];

/**
 * True when `host` is an IP literal in a range that should never be reachable
 * from a Runtime unless an operator named it explicitly. This is the SSRF and
 * metadata-endpoint guard: an Agent that resolves its own address, or is handed
 * one by a redirect, must not be able to pivot into the host or cloud metadata.
 */
export function isRestrictedAddress(host: string): boolean {
  const value = normalizeHost(host);
  if (value === "::1" || value === "::" ) return true;
  if (/^f[cd][0-9a-f]{2}:/i.test(value)) return true;   // unique-local v6
  if (/^fe[89ab][0-9a-f]:/i.test(value)) return true;   // link-local v6
  if (/^::ffff:/i.test(value)) {
    return BLOCKED_V4.some((pattern) => pattern.test(value.replace(/^::ffff:/i, "")));
  }
  if (/^ff[0-9a-f]{2}:/i.test(value)) return true;     // multicast v6
  const ipv4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(value);
  if (!ipv4) return false;
  const octets = ipv4.slice(1).map(Number);
  // A malformed literal is refused rather than parsed leniently.
  if (octets.some((octet) => octet > 255)) return true;
  const first = octets[0] ?? 0;
  if (first >= 224) return true;                       // multicast + reserved
  return BLOCKED_V4.some((pattern) => pattern.test(value));
}

/**
 * Single canonical classifier, used BOTH for literal addresses at policy time
 * and for DNS results at connect time.
 *
 * There were previously two implementations with different coverage: the
 * policy-time one knew about CGNAT (100.64.0.0/10) and IPv4-mapped IPv6, the
 * connect-time one did not. An allowlisted hostname resolving into 100.64/10
 * therefore passed the resolver screen even though the same literal would have
 * been refused earlier. Two classifiers means two answers to one question.
 */
export function isBlockedLiteralAddress(host: string): boolean {
  const value = normalizeHost(host);
  if (value === "localhost") return true;
  return isRestrictedAddress(value);
}

export function scopeMatches(scope: EgressScope, request: PolicyRequest): boolean {
  return scope.plane === request.plane && matchHost(scope.host, request.host);
}

export function evaluate(
  grant: Grant | null,
  request: PolicyRequest,
): PolicyDecision {
  if (!grant) {
    return {
      effect: "deny",
      code: "no_grant",
      message:
        "No capability grant was presented. Runtime egress requires a run-scoped Warden grant.",
    };
  }
  if (grant.status === "revoked") {
    return {
      effect: "deny",
      code: "grant_revoked",
      message: "Grant " + grant.id + " was revoked: " + (grant.statusReason ?? "no reason recorded"),
    };
  }
  if (grant.status === "closed") {
    return {
      effect: "deny",
      code: "grant_closed",
      message: "Grant " + grant.id + " closed when its run finished.",
    };
  }
  if (grant.status === "exhausted") {
    return {
      effect: "deny",
      code: "budget_tokens_exhausted",
      message: "Grant " + grant.id + " exhausted its budget: " + (grant.statusReason ?? "budget"),
    };
  }
  if (request.nowMs >= Date.parse(grant.expiresAt)) {
    return {
      effect: "deny",
      code: "grant_expired",
      message: "Grant " + grant.id + " expired at " + grant.expiresAt + ".",
    };
  }
  if (request.nowMs - Date.parse(grant.issuedAt) >= grant.budget.maxWallClockMs) {
    return {
      effect: "deny",
      code: "budget_time_exhausted",
      message:
        "Wall-clock budget of " + grant.budget.maxWallClockMs + " ms exhausted for grant " + grant.id + ".",
    };
  }

  // An IP literal in a private/loopback/metadata range is refused unless a scope
  // names that exact address. Checked before host matching so a wildcard scope
  // can never widen into the host's own network.
  if (isRestrictedAddress(request.host)) {
    const namedExactly = grant.scopes.some(
      (scope) => normalizeHost(scope.host) === normalizeHost(request.host),
    );
    if (!namedExactly) {
      return {
        effect: "deny",
        code: "address_not_allowed",
        message:
          "Address " + normalizeHost(request.host) +
          " is loopback, private or link-local and is not named by any scope.",
      };
    }
  }

  const planeScopes = grant.scopes.filter((scope) => scope.plane === request.plane);
  if (planeScopes.length === 0) {
    return {
      effect: "deny",
      code: "plane_not_allowed",
      message: "Grant " + grant.id + " holds no " + request.plane + "-plane capability.",
    };
  }

  if (request.host.includes("@")) {
    return {
      effect: "deny",
      code: "host_not_allowed",
      message: "Destination authority contains user-info, which is not accepted.",
    };
  }

  const hostMatches = planeScopes.filter((scope) => scopeMatches(scope, request));
  if (hostMatches.length === 0) {
    return {
      effect: "deny",
      code: "host_not_allowed",
      message:
        "Host " + normalizeHost(request.host) + " is not in the delegated allowlist for grant " + grant.id + ".",
    };
  }

  const portMatches = hostMatches.filter((scope) => scope.ports.includes(request.port));
  if (portMatches.length === 0) {
    return {
      effect: "deny",
      code: "port_not_allowed",
      message:
        "Port " + request.port + " is not permitted for host " + normalizeHost(request.host) + ".",
    };
  }

  if (
    request.plane === "network" &&
    isBlockedLiteralAddress(request.host) &&
    !portMatches.some((scope) => normalizeHost(scope.host) === normalizeHost(request.host))
  ) {
    return {
      effect: "deny",
      code: "address_not_allowed",
      message:
        "Destination " +
        normalizeHost(request.host) +
        " is a loopback, private or link-local address and was not named explicitly.",
    };
  }

  const method = request.method.toUpperCase();
  const matched = portMatches.find(
    (scope) => !scope.methods || scope.methods.map((item) => item.toUpperCase()).includes(method),
  );
  if (!matched) {
    return {
      effect: "deny",
      code: "method_not_allowed",
      message: "Method " + method + " is not permitted for host " + normalizeHost(request.host) + ".",
    };
  }

  if (request.plane === "model") {
    if (grant.usage.modelCalls >= grant.budget.maxModelCalls) {
      return {
        effect: "deny",
        code: "budget_calls_exhausted",
        message:
          "Model call budget of " + grant.budget.maxModelCalls + " reached for grant " + grant.id + ".",
      };
    }
    if (grant.usage.totalTokens >= grant.budget.maxTotalTokens) {
      return {
        effect: "deny",
        code: "budget_tokens_exhausted",
        message:
          "Token budget of " +
          grant.budget.maxTotalTokens +
          " reached for grant " +
          grant.id +
          ". Raise WARDEN_MAX_TOTAL_TOKENS if the task legitimately needs more.",
      };
    }
  }

  return { effect: "allow", matchedScope: matched };
}

/**
 * Mutable baseline policy. This is what a new grant is minted from, and what the
 * operator edits from the UI to demonstrate live tightening or widening.
 */
export type BudgetPatch = {
  [K in keyof Budget]?: Budget[K] | undefined;
};

export class WardenPolicyStore {
  private scopes: EgressScope[];
  private budget: Budget;

  constructor(scopes: EgressScope[], budget: Budget) {
    this.scopes = scopes.map((scope) => ({ ...scope, ports: [...scope.ports] }));
    this.budget = { ...budget };
  }

  snapshot(): { scopes: EgressScope[]; budget: Budget } {
    return {
      scopes: this.scopes.map((scope) => ({ ...scope, ports: [...scope.ports] })),
      budget: { ...this.budget },
    };
  }

  setBudget(patch: BudgetPatch): Budget {
    const next: Budget = { ...this.budget };
    if (patch.maxModelCalls !== undefined) next.maxModelCalls = patch.maxModelCalls;
    if (patch.maxTotalTokens !== undefined) next.maxTotalTokens = patch.maxTotalTokens;
    if (patch.maxWallClockMs !== undefined) next.maxWallClockMs = patch.maxWallClockMs;
    this.budget = next;
    return { ...this.budget };
  }

  /** Replaces the entire scope set. Used when an operator applies a template. */
  setScopes(scopes: EgressScope[]): EgressScope[] {
    this.scopes = scopes.map((scope) => ({ ...scope, ports: [...scope.ports] }));
    return this.snapshot().scopes;
  }

  allowHost(scope: EgressScope): EgressScope[] {
    const exists = this.scopes.some(
      (item) => item.plane === scope.plane && item.host.toLowerCase() === scope.host.toLowerCase(),
    );
    if (!exists) this.scopes.push({ ...scope, ports: [...scope.ports] });
    return this.snapshot().scopes;
  }

  denyHost(plane: EgressScope["plane"], host: string): EgressScope[] {
    this.scopes = this.scopes.filter(
      (item) => !(item.plane === plane && item.host.toLowerCase() === host.toLowerCase()),
    );
    return this.snapshot().scopes;
  }
}
