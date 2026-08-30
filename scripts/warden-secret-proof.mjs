#!/usr/bin/env node
/**
 * Deterministic, screen-safe proof of Warden's credential boundary.
 *
 * Run this from a SECOND terminal while an Agent turn is active. The script is
 * trusted host-side evidence: it reads Docker/Podman inspection data into memory
 * but prints only booleans and fingerprints already exposed by Warden. Neither
 * the provider key nor the raw run grant is ever written to stdout/stderr.
 */
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const engine = process.env.CONTAINER_ENGINE?.trim() || "docker";
const apiBase = (process.env.WARDEN_API_BASE_URL || "http://127.0.0.1:3000").replace(/\/+$/, "");
const authToken = process.env.APP_AUTH_TOKEN?.trim() || "";
const checks = [];

class SafeProofError extends Error {}

function record(ok, message) {
  checks.push({ ok, message });
  process.stdout.write((ok ? "PASS" : "FAIL") + "  " + message + "\n");
}

async function engineOutput(args) {
  const { stdout } = await execFileAsync(engine, args, {
    timeout: 15_000,
    maxBuffer: 2 * 1024 * 1024,
  });
  return stdout.trim();
}

async function containerIds(label) {
  const output = await engineOutput([
    "ps",
    "--filter",
    "label=io.codejam.launchpad=" + label,
    "--format",
    "{{.ID}}",
  ]);
  return output.split(/\r?\n/).map((value) => value.trim()).filter(Boolean);
}

async function inspect(containerId) {
  const output = await engineOutput(["inspect", containerId]);
  const parsed = JSON.parse(output);
  if (!Array.isArray(parsed) || !parsed[0]) throw new Error("inspection returned no container");
  return parsed[0];
}

function environmentOf(inspection) {
  const result = new Map();
  const entries = inspection?.Config?.Env;
  if (!Array.isArray(entries)) return result;
  for (const entry of entries) {
    if (typeof entry !== "string") continue;
    const separator = entry.indexOf("=");
    if (separator < 0) continue;
    result.set(entry.slice(0, separator), entry.slice(separator + 1));
  }
  return result;
}

async function api(path) {
  const response = await fetch(apiBase + path, {
    headers: authToken ? { authorization: "Bearer " + authToken } : {},
    signal: AbortSignal.timeout(8_000),
  });
  if (!response.ok) throw new Error("API request failed with status " + response.status);
  return response.json();
}

function contains(payload, secret) {
  return Boolean(secret) && JSON.stringify(payload).includes(secret);
}

try {
  const brokerIds = await containerIds("warden-broker");
  const runtimeIds = await containerIds("agent-runtime");
  if (brokerIds.length !== 1) {
    throw new SafeProofError("expected one active Warden broker; start npm run poc first");
  }
  if (runtimeIds.length !== 1) {
    throw new SafeProofError(
      "expected one active Agent Runtime; start the long-running secret-proof Playground task first",
    );
  }

  const [broker, runtime] = await Promise.all([
    inspect(brokerIds[0]),
    inspect(runtimeIds[0]),
  ]);
  const brokerEnvironment = environmentOf(broker);
  const runtimeEnvironment = environmentOf(runtime);
  const providerKey = brokerEnvironment.get("ARK_API_KEY") || "";
  const runGrant = runtimeEnvironment.get("ARK_API_KEY") || "";
  const grantFingerprint = runGrant
    ? createHash("sha256").update(runGrant, "utf8").digest("hex").slice(0, 8)
    : "";

  record(providerKey.length > 0, "broker holds the provider credential (value not displayed)");
  record(runGrant.startsWith("wgt_"), "Runtime holds a run-scoped wgt_ grant");
  record(
    providerKey.length > 0 && runGrant !== providerKey && !JSON.stringify(runtime).includes(providerKey),
    "provider credential is absent from the Runtime inspection record",
  );

  const runtimeCommand = JSON.stringify(runtime?.Config?.Cmd ?? []);
  record(
    !runtimeCommand.includes(providerKey) && !runtimeCommand.includes(runGrant),
    "Runtime command arguments contain neither credential",
  );

  const [grantPayload, traceSummaries, agentPayload, systemPayload] = await Promise.all([
    api("/api/warden/grants"),
    api("/api/warden/traces"),
    api("/api/agents"),
    api("/api/system"),
  ]);
  const grants = Array.isArray(grantPayload?.grants) ? grantPayload.grants : [];
  const matchingGrant = grants.find(
    (grant) => grant?.tokenFingerprint === grantFingerprint && grant?.status === "active",
  );
  record(
    Boolean(matchingGrant),
    "public grant fingerprint matches the active Runtime grant: " +
      (grantFingerprint || "unavailable"),
  );
  record(
    !JSON.stringify(grantPayload).includes("tokenHash") &&
      !contains(grantPayload, providerKey) &&
      !contains(grantPayload, runGrant),
    "grant API exposes no raw token, token hash, or provider credential",
  );

  const traces = Array.isArray(traceSummaries?.traces) ? traceSummaries.traces : [];
  const traceDetails = await Promise.all(
    traces.map((trace) => api("/api/warden/traces/" + encodeURIComponent(trace.traceId))),
  );
  const agents = Array.isArray(agentPayload?.agents) ? agentPayload.agents : [];
  const agentEvidence = await Promise.all(
    agents.flatMap((agent) => [
      api("/api/agents/" + encodeURIComponent(agent.id) + "/messages"),
      api("/api/agents/" + encodeURIComponent(agent.id) + "/runs"),
    ]),
  );
  const publicEvidence = { grantPayload, traceSummaries, traceDetails, agentEvidence, systemPayload };
  record(
    !contains(publicEvidence, providerKey) && !contains(publicEvidence, runGrant),
    "traces, Runs, messages and public system data contain neither raw credential",
  );

  const failed = checks.filter((check) => !check.ok).length;
  process.stdout.write(
    "\n" + (failed === 0
      ? "Secret boundary verified without displaying a secret.\n"
      : failed + " secret-boundary check(s) failed.\n"),
  );
  process.exitCode = failed === 0 ? 0 : 1;
} catch (error) {
  // Never stringify child-process errors: they may carry captured inspection
  // output. Only errors we constructed from fixed text are safe to show.
  const message = error instanceof SafeProofError
    ? error.message
    : error instanceof SyntaxError
      ? "invalid inspection response"
      : "a container-engine or API command failed; confirm the POC is running and APP_AUTH_TOKEN is set if required";
  process.stderr.write(
    "Secret proof could not run: " + message + "\n",
  );
  process.exitCode = 1;
}
