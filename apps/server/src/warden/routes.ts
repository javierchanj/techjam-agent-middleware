import type { FastifyInstance } from "fastify";
import { z } from "zod";
import type { WardenControl } from "./control.js";
import { GrantVault } from "./grants.js";

const traceIdParams = z.object({ id: z.string().min(1).max(120) });
const grantIdParams = z.object({ id: z.string().min(1).max(120) });
const revokeBody = z.object({ reason: z.string().trim().min(1).max(200) });
const traceQuery = z.object({ agentId: z.string().uuid().optional() });
const templateBody = z.object({ id: z.string().trim().min(1).max(64) });
const checkBody = z.object({
  plane: z.enum(["model", "network", "any"]).default("any"),
  host: z.string().trim().min(1).max(253),
  port: z.coerce.number().int().min(1).max(65535).default(443),
  method: z.string().trim().min(1).max(16).default("CONNECT"),
});

export interface WardenRouteDeps {
  control: WardenControl;
  /** Fallback lookup for traces whose broker has since restarted. */
  archive?:
    | {
        find(traceId: string): Promise<import("./types.js").WardenTrace | null>;
        list(agentId?: string | undefined): Promise<import("./types.js").WardenTrace[]>;
      }
    | undefined;
  containerNetwork: string;
  /**
   * Revoke-and-cancel: revoking authority must also stop the work that
   * authority was for, otherwise the operator is left with a container that is
   * still running but can no longer do anything.
   */
  cancelRun(agentId: string, expectedRunId: string): Promise<boolean>;
}

export async function registerWardenRoutes(
  app: FastifyInstance,
  deps: WardenRouteDeps,
): Promise<void> {
  app.get("/api/warden/status", async () => {
    const status = await deps.control.status();
    return {
      enabled: true,
      gatewayPort: status.gatewayPort,
      containerNetwork: deps.containerNetwork,
      upstreamHost: status.upstreamHost,
      policy: status.policy,
      activeGrants: status.activeGrants,
    };
  });

  app.get("/api/warden/policy", async () => deps.control.getPolicy());

  app.get("/api/warden/templates", async () => ({
    templates: await deps.control.listTemplates(),
  }));

  app.get("/api/warden/policy/history", async () => ({
    changes: await deps.control.listPolicyChanges(),
  }));

  app.post("/api/warden/policy/template", async (request, reply) => {
    const { id } = templateBody.parse(request.body);
    // Same mock principal the Playground uses, so a policy change is
    // attributable to the operator who made it.
    const rawActor = request.headers["x-launchpad-actor"];
    const actorHeader = Array.isArray(rawActor) ? rawActor[0] : rawActor;
    const actorId = /^[A-Za-z0-9:._-]{1,64}$/.test(actorHeader ?? "")
      ? (actorHeader as string)
      : "user:local";
    try {
      return { policy: await deps.control.applyTemplate(id, actorId) };
    } catch (error) {
      return reply
        .code(400)
        .send({ error: error instanceof Error ? error.message : "Unknown template" });
    }
  });

  /** Dry run: answers "would this be allowed?" without minting or connecting. */
  app.post("/api/warden/policy/check", async (request) => {
    const body = checkBody.parse(request.body);
    return deps.control.checkPolicy({
      plane: body.plane,
      host: body.host,
      port: body.port,
      method: body.method,
    });
  });

  app.get("/api/warden/grants", async () => ({
    // Public projection: the token hash never leaves the broker boundary.
    grants: (await deps.control.listGrants()).map(GrantVault.toPublic),
  }));

  app.post("/api/warden/grants/:id/revoke", async (request, reply) => {
    const { id } = grantIdParams.parse(request.params);
    const { reason } = revokeBody.parse(request.body);
    const grant = await deps.control.revokeGrant(id, reason);
    if (!grant) return reply.code(404).send({ error: "Grant not found" });
    // Authority and execution are revoked together, but only for the run this
    // grant was issued for. Revoking a stale grant must not kill a newer run.
    const cancelled = await deps.cancelRun(grant.agentId, grant.runId);
    return { grant, cancelledRunId: cancelled ? grant.runId : null };
  });

  app.get("/api/warden/traces", async (request) => {
    const query = traceQuery.parse(request.query);
    const live = await deps.control.listTraces(query.agentId);
    // Merge archived history so the rail is not empty after a broker restart.
    // Live traces win: the broker's copy is the one still being written to.
    const merged = new Map<string, (typeof live)[number]>();
    for (const trace of (await deps.archive?.list(query.agentId)) ?? []) {
      merged.set(trace.traceId, trace);
    }
    for (const trace of live) merged.set(trace.traceId, trace);
    const traces = [...merged.values()].sort((left, right) =>
      right.startedAt.localeCompare(left.startedAt),
    );
    return {
      traces: traces.map((trace) => ({
        traceId: trace.traceId,
        runId: trace.runId,
        agentId: trace.agentId,
        grantId: trace.grantId,
        status: trace.status,
        startedAt: trace.startedAt,
        endedAt: trace.endedAt,
        spanCount: trace.spans.length,
        deniedCount: trace.spans.filter((span) => span.status === "denied").length,
      })),
    };
  });

  app.get("/api/warden/traces/:id", async (request, reply) => {
    const { id } = traceIdParams.parse(request.params);
    const trace = (await deps.control.getTrace(id)) ?? (await deps.archive?.find(id)) ?? null;
    if (!trace) return reply.code(404).send({ error: "Trace not found" });
    return { trace };
  });
}
