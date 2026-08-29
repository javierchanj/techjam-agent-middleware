import { createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { evaluate } from "./policy.js";
import type { Redactor } from "./redact.js";
import type {
  PublicGrant,
  Budget,
  EgressScope,
  Grant,
  PolicyDecision,
  PolicyRequest,
  Principal,
} from "./types.js";

export interface MintGrantInput {
  agentId: string;
  runId: string;
  traceId: string;
  humanPrincipal: Principal;
  agentPrincipal: Principal;
  scopes: EgressScope[];
  budget: Budget;
  ttlMs: number;
}

export interface MintedGrant {
  grant: Grant;
  /** Returned exactly once. Only the sha256 hash is retained. */
  token: string;
}

export const GRANT_TOKEN_PREFIX = "wgt_";

export function hashToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

/**
 * Issues, resolves, meters and revokes short-lived per-run capability tokens.
 *
 * Design notes:
 *  - The raw token exists in memory only long enough to be injected into the
 *    Runtime container's environment. Only the hash is kept.
 *  - Lookup is by hash, then confirmed with a constant-time comparison so a
 *    token cannot be recovered by timing the resolver.
 *  - Every mutation is synchronous and in-process; the ledger owns durability.
 */
export class GrantVault {
  private readonly grants = new Map<string, Grant>();
  private readonly byTokenHash = new Map<string, string>();
  /**
   * Raw tokens for ACTIVE grants only. The vault must be able to unregister a
   * token from the redactor when the grant closes, so it holds the value for
   * the grant's lifetime and drops it on close. What is never written to a
   * Grant record, the ledger, the API or disk is the raw value: those carry
   * the sha256 hash and an 8-character fingerprint.
   */
  private readonly liveTokens = new Map<string, string>();

  constructor(
    private readonly redactor: Redactor,
    private readonly clock: () => number = () => Date.now(),
  ) {}

  mint(input: MintGrantInput): MintedGrant {
    const token = GRANT_TOKEN_PREFIX + randomBytes(32).toString("base64url");
    const issuedAtMs = this.clock();
    const grant: Grant = {
      id: "grant_" + randomUUID(),
      tokenHash: hashToken(token),
      tokenFingerprint: hashToken(token).slice(0, 8),
      agentId: input.agentId,
      runId: input.runId,
      traceId: input.traceId,
      humanPrincipal: input.humanPrincipal,
      agentPrincipal: input.agentPrincipal,
      scopes: input.scopes.map((scope) => ({ ...scope, ports: [...scope.ports] })),
      budget: { ...input.budget },
      usage: { modelCalls: 0, networkCalls: 0, totalTokens: 0, estimated: false },
      status: "active",
      statusReason: null,
      issuedAt: new Date(issuedAtMs).toISOString(),
      expiresAt: new Date(issuedAtMs + input.ttlMs).toISOString(),
      closedAt: null,
    };
    this.grants.set(grant.id, grant);
    this.byTokenHash.set(grant.tokenHash, grant.id);
    this.liveTokens.set(grant.id, token);
    this.redactor.register(token, "warden_grant_token");
    return { grant: structuredClone(grant), token };
  }

  resolveByToken(token: string | null): Grant | null {
    if (!token) return null;
    const candidateHash = hashToken(token);
    const grantId = this.byTokenHash.get(candidateHash);
    if (!grantId) return null;
    const grant = this.grants.get(grantId);
    if (!grant) return null;
    const left = Buffer.from(candidateHash, "hex");
    const right = Buffer.from(grant.tokenHash, "hex");
    if (left.length !== right.length || !timingSafeEqual(left, right)) return null;
    this.expireIfDue(grant);
    return structuredClone(grant);
  }

  get(grantId: string): Grant | null {
    const grant = this.grants.get(grantId);
    if (!grant) return null;
    this.expireIfDue(grant);
    return structuredClone(grant);
  }

  list(): Grant[] {
    for (const grant of this.grants.values()) this.expireIfDue(grant);
    return [...this.grants.values()]
      .map((grant) => structuredClone(grant))
      .sort((left, right) => right.issuedAt.localeCompare(left.issuedAt));
  }

  /**
   * Atomically evaluates policy and, on allow, reserves one call against the
   * budget. Reserving before the upstream call is what stops N concurrent calls
   * from all passing the same budget check.
   */
  authorize(token: string | null, request: PolicyRequest): {
    decision: PolicyDecision;
    grant: Grant | null;
  } {
    const snapshot = this.resolveByToken(token);
    const decision = evaluate(snapshot, request);
    if (decision.effect === "allow" && snapshot) {
      const live = this.grants.get(snapshot.id);
      if (live) {
        if (request.plane === "model") live.usage.modelCalls += 1;
        else live.usage.networkCalls += 1;
      }
    }
    return { decision, grant: snapshot };
  }

  recordTokenUsage(grantId: string, tokens: number, estimated: boolean): Grant | null {
    const grant = this.grants.get(grantId);
    if (!grant) return null;
    grant.usage.totalTokens += Math.max(0, Math.round(tokens));
    if (estimated) grant.usage.estimated = true;
    if (grant.status === "active" && grant.usage.totalTokens >= grant.budget.maxTotalTokens) {
      grant.status = "exhausted";
      grant.statusReason =
        "token budget " + grant.budget.maxTotalTokens + " exceeded (" + grant.usage.totalTokens + ")";
      grant.closedAt = new Date(this.clock()).toISOString();
    }
    return structuredClone(grant);
  }

  revoke(grantId: string, reason: string): Grant | null {
    const grant = this.grants.get(grantId);
    if (!grant) return null;
    if (grant.status === "active" || grant.status === "exhausted") {
      grant.status = "revoked";
      grant.statusReason = reason;
      grant.closedAt = new Date(this.clock()).toISOString();
    }
    return structuredClone(grant);
  }

  /** Called when a run finishes. Closes the grant and drops the raw token. */
  close(grantId: string, reason: string): Grant | null {
    const grant = this.grants.get(grantId);
    if (!grant) return null;
    if (grant.status === "active") {
      grant.status = "closed";
      grant.statusReason = reason;
      grant.closedAt = new Date(this.clock()).toISOString();
    }
    const token = this.liveTokens.get(grantId);
    if (token) {
      this.redactor.unregister(token);
      this.liveTokens.delete(grantId);
    }
    return structuredClone(grant);
  }

  /** API-safe projection. Excludes the token hash. */
  static toPublic(grant: Grant): PublicGrant {
    const { tokenHash: _tokenHash, ...rest } = grant;
    return rest;
  }

  private expireIfDue(grant: Grant): void {
    if (grant.status !== "active") return;
    if (this.clock() < Date.parse(grant.expiresAt)) return;
    grant.status = "expired";
    grant.statusReason = "ttl elapsed";
    grant.closedAt = new Date(this.clock()).toISOString();
  }
}
