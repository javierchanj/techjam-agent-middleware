import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "./api";
import type {
  Grant,
  PolicyCheckResult,
  TemplateDescriptor,
  TraceSummary,
  WardenSpan,
  WardenStatus,
  WardenTrace,
} from "./warden-types";

const POLL_MS = 1_500;

function clock(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(new Date(value));
}

function Meter({ label, used, limit }: { label: string; used: number; limit: number }) {
  const ratio = limit > 0 ? Math.min(1, used / limit) : 0;
  const level = ratio >= 1 ? "over" : ratio >= 0.8 ? "warn" : "ok";
  return (
    <div className="warden-meter">
      <div className="warden-meter-head">
        <span>{label}</span>
        <span>
          {used} / {limit}
        </span>
      </div>
      <div className="warden-meter-track">
        <div className={"warden-meter-fill warden-meter-" + level} style={{ width: ratio * 100 + "%" }} />
      </div>
    </div>
  );
}

function SpanRow({ span }: { span: WardenSpan }) {
  const denied = span.status === "denied";
  const code = span.attributes.deny_code;
  const reason = span.attributes.deny_reason;
  return (
    <li className={"warden-span warden-span-" + span.status}>
      <div className="warden-span-head">
        <span className={"warden-tag warden-tag-" + span.kind}>{span.kind.replace("_", " ")}</span>
        <span className="warden-span-name">{span.name}</span>
        <span className="warden-span-time">
          {span.durationMs === null ? "…" : span.durationMs + " ms"}
        </span>
      </div>
      {denied && (
        <p className="warden-deny">
          <strong>{String(code ?? "denied")}</strong> {String(reason ?? "")}
        </p>
      )}
      {!denied && span.attributes.tokens_charged !== undefined && (
        <p className="warden-span-meta">
          {String(span.attributes.tokens_charged)} tokens charged
          {span.attributes.tokens_estimated === true ? " (estimated)" : ""} · total{" "}
          {String(span.attributes.tokens_used_total ?? "0")}
        </p>
      )}
    </li>
  );
}

export default function WardenPanel({ agentId }: { agentId: string | null }) {
  const [status, setStatus] = useState<WardenStatus | null>(null);
  const [grants, setGrants] = useState<Grant[]>([]);
  const [traces, setTraces] = useState<TraceSummary[]>([]);
  const [openTraceId, setOpenTraceId] = useState<string | null>(null);
  const [openTrace, setOpenTrace] = useState<WardenTrace | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [templates, setTemplates] = useState<TemplateDescriptor[]>([]);
  const [probeHost, setProbeHost] = useState("");
  const [probe, setProbe] = useState<PolicyCheckResult | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [statusResult, grantResult, traceResult] = await Promise.all([
        api.wardenStatus(),
        api.wardenGrants(),
        agentId ? api.wardenTraces(agentId) : Promise.resolve({ traces: [] }),
      ]);
      setStatus(statusResult);
      setGrants(grantResult.grants);
      setTraces(traceResult.traces);
    } catch {
      setStatus(null);
    }
  }, [agentId]);

  useEffect(() => {
    void refresh();
    const timer = setInterval(() => void refresh(), POLL_MS);
    return () => clearInterval(timer);
  }, [refresh]);

  useEffect(() => {
    void api
      .wardenTemplates()
      .then((result) => setTemplates(result.templates))
      .catch(() => setTemplates([]));
  }, []);

  const applyTemplate = async (id: string) => {
    try {
      await api.wardenApplyTemplate(id);
      setNotice("Template applied. It takes effect on the next run; grants already issued keep their scopes.");
      setProbe(null);
      await refresh();
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Could not apply that template.");
    }
  };

  const checkDestination = async () => {
    const host = probeHost.trim();
    if (!host) return;
    try {
      setProbe(await api.wardenCheck(host));
    } catch (error) {
      setProbe({
        allowed: false,
        code: "check_failed",
        message: error instanceof Error ? error.message : "Check failed",
        matchedHost: null,
      });
    }
  };

  useEffect(() => {
    if (!openTraceId) {
      setOpenTrace(null);
      return;
    }
    let cancelled = false;
    const load = async () => {
      try {
        const result = await api.wardenTrace(openTraceId);
        if (!cancelled) setOpenTrace(result.trace);
      } catch {
        if (!cancelled) setOpenTrace(null);
      }
    };
    void load();
    const timer = setInterval(() => void load(), POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [openTraceId]);

  const liveGrant = useMemo(
    () => grants.find((grant) => grant.agentId === agentId && grant.status === "active") ?? null,
    [grants, agentId],
  );
  const lastGrant = useMemo(
    () => grants.find((grant) => grant.agentId === agentId) ?? null,
    [grants, agentId],
  );
  const shown = liveGrant ?? lastGrant;

  const revoke = async () => {
    if (!shown) return;
    try {
      await api.wardenRevoke(shown.id, "Revoked from the operator console");
      setNotice("Access revoked and the run cancelled. The Agent is idle again.");
      await refresh();
    } catch (error) {
      setNotice(error instanceof Error ? error.message : "Could not revoke this grant.");
    }
  };

  if (!status?.enabled) {
    return (
      <section className="warden-panel">
        <h3>Warden</h3>
        <p className="warden-empty">
          The egress broker is off. Start the server with WARDEN_ENABLED=true to route Runtime
          traffic through it.
        </p>
      </section>
    );
  }

  // Both planes are read from the live policy. Asserting the model host from
  // status.upstreamHost would keep claiming model access under the fully
  // offline template, which grants no model scope at all.
  const modelHosts = status.policy.scopes.filter((scope) => scope.plane === "model");
  const networkHosts = status.policy.scopes.filter((scope) => scope.plane === "network");

  return (
    <section className="warden-panel">
      <header className="warden-head">
        <h3>Warden</h3>
        <span className="warden-sub">
          gateway :{status.gatewayPort} · network {status.containerNetwork}
        </span>
      </header>

      {templates.length > 0 && (
        <div className="warden-card">
          <h4>Delegation profile</h4>
          <div className="warden-templates">
            {templates.map((template) => (
              <button
                key={template.id}
                type="button"
                title={template.description}
                className={
                  "warden-template" +
                  (status.policy.templateId === template.id ? " warden-template-active" : "")
                }
                onClick={() => void applyTemplate(template.id)}
              >
                {template.label}
              </button>
            ))}
          </div>
          {status.policy.templateId && (
            <ul className="warden-guarantees">
              {templates
                .find((template) => template.id === status.policy.templateId)
                ?.guarantees.map((line) => <li key={line}>{line}</li>)}
            </ul>
          )}
        </div>
      )}

      <div className="warden-card">
        <h4>Would this be allowed?</h4>
        <div className="warden-probe">
          <input
            value={probeHost}
            onChange={(event) => setProbeHost(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") void checkDestination();
            }}
            placeholder="host to test, e.g. api.github.com"
            aria-label="Destination to test against the policy"
          />
          <button type="button" onClick={() => void checkDestination()}>
            Check
          </button>
        </div>
        {probe && (
          <p className={probe.allowed ? "warden-probe-allow" : "warden-deny"}>
            <strong>{probe.allowed ? "allowed" : (probe.code ?? "denied")}</strong> {probe.message}
          </p>
        )}
        <p className="warden-span-meta">
          Dry run against the live policy. Nothing is minted and no connection is made.
        </p>
      </div>

      <div className="warden-card">
        <h4>What this Agent may reach</h4>
        <ul className="warden-scopes">
          {modelHosts.length === 0 ? (
            <li className="warden-scope-empty">
              <span className="warden-tag warden-tag-model_call">model</span>
              nothing — the Agent cannot reach the model provider
            </li>
          ) : (
            modelHosts.map((scope) => (
              <li key={"model:" + scope.host}>
                <span className="warden-tag warden-tag-model_call">model</span>
                {scope.host}:{scope.ports.join(",")}
              </li>
            ))
          )}
          {networkHosts.length === 0 ? (
            <li className="warden-scope-empty">
              <span className="warden-tag warden-tag-network_call">network</span>
              nothing — every other destination is refused
            </li>
          ) : (
            networkHosts.map((scope) => (
              <li key={scope.host}>
                <span className="warden-tag warden-tag-network_call">network</span>
                {scope.host}:{scope.ports.join(",")}
              </li>
            ))
          )}
        </ul>
      </div>

      {shown && (
        <div className="warden-card">
          <h4>
            Access for this run
            <span className={"warden-status warden-status-" + shown.status}>{shown.status}</span>
          </h4>
          <p className="warden-chain">
            {shown.humanPrincipal.id} → {shown.agentPrincipal.id}
          </p>
          <dl className="warden-facts">
            <dt>Credential type</dt>
            <dd>run grant</dd>
            <dt>Grant fingerprint</dt>
            <dd className="warden-mono">{shown.tokenFingerprint}</dd>
            <dt>Provider key in Runtime</dt>
            <dd>no</dd>
          </dl>
          <Meter label="Model calls" used={shown.usage.modelCalls} limit={shown.budget.maxModelCalls} />
          <Meter
            label="Tokens (soft cap)"
            used={shown.usage.totalTokens}
            limit={shown.budget.maxTotalTokens}
          />
          <p className="warden-span-meta">
            {shown.usage.networkCalls} allowed outbound network calls · expires{" "}
            {clock(shown.expiresAt)}
            {shown.usage.estimated ? " · token count partly estimated" : ""}
          </p>
          {shown.statusReason && <p className="warden-deny">{shown.statusReason}</p>}
          <button
            type="button"
            className="warden-revoke"
            onClick={() => void revoke()}
            disabled={shown.status !== "active"}
          >
            Revoke access
          </button>
        </div>
      )}

      {notice && <p className="warden-notice">{notice}</p>}

      <div className="warden-card">
        <h4>Runs</h4>
        {traces.length === 0 ? (
          <p className="warden-empty">Send a message to record the first brokered run.</p>
        ) : (
          <ul className="warden-traces">
            {traces.map((trace) => (
              <li key={trace.traceId}>
                <button
                  type="button"
                  className={
                    "warden-trace" +
                    (trace.deniedCount > 0 ? " warden-trace-denied" : "") +
                    (openTraceId === trace.traceId ? " warden-trace-open" : "")
                  }
                  onClick={() =>
                    setOpenTraceId(openTraceId === trace.traceId ? null : trace.traceId)
                  }
                >
                  <span>{clock(trace.startedAt)}</span>
                  <span>{trace.spanCount} steps</span>
                  {trace.deniedCount > 0 && (
                    <span className="warden-badge">{trace.deniedCount} blocked</span>
                  )}
                </button>
                {openTraceId === trace.traceId && openTrace && (
                  <ul className="warden-spans">
                    {openTrace.spans.map((span) => (
                      <SpanRow key={span.id} span={span} />
                    ))}
                  </ul>
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}