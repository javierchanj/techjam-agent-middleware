import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import { fileURLToPath } from "node:url";
import type { AppConfig } from "../config.js";

const execFileAsync = promisify(execFile);

export interface BrokerHandle {
  containerName: string;
  controlBaseUrl: string;
  stop(): Promise<void>;
}

export class WardenStartupError extends Error {
  constructor(message: string, cause?: unknown) {
    const detail = cause instanceof Error ? ": " + cause.message.split("\n")[0] : "";
    super(message + detail);
    this.name = "WardenStartupError";
  }
}

async function run(
  engine: string,
  args: string[],
  timeout = 30_000,
  env?: NodeJS.ProcessEnv | undefined,
): Promise<string> {
  // `--env NAME` is the passthrough form: it keeps values out of argv, but the
  // value must then exist in the environment of the container-engine child.
  // The control secret is generated at boot and is not in process.env.
  const { stdout } = await execFileAsync(engine, args, {
    timeout,
    ...(env ? { env } : {}),
  });
  return stdout.trim();
}

async function quiet(engine: string, args: string[]): Promise<void> {
  try {
    await run(engine, args, 15_000);
  } catch {
    // Best effort: used only for teardown of resources that may not exist.
  }
}

/**
 * Creates the two-network topology Warden depends on.
 *
 *   <name>-internal : --internal, no route off the host. Runtimes live here.
 *   <name>-egress   : ordinary bridge. Only the broker is attached.
 *
 * FAIL CLOSED. If the engine will not create a genuinely internal network there
 * is no containment, and falling back to a routable bridge would leave the
 * platform advertising a guarantee it is not providing. We abort instead.
 */
export async function ensureWardenNetworks(config: AppConfig): Promise<void> {
  const engine = config.containerEngine;
  const { internalNetwork, egressNetwork } = config.warden;

  for (const [name, internal] of [
    [internalNetwork, true],
    [egressNetwork, false],
  ] as const) {
    try {
      await run(engine, ["network", "inspect", name], 10_000);
      continue;
    } catch {
      // Not present yet.
    }
    try {
      await run(engine, [
        "network",
        "create",
        "--driver",
        "bridge",
        ...(internal ? ["--internal"] : []),
        name,
      ]);
    } catch (error) {
      throw new WardenStartupError(
        "Could not create the " + (internal ? "internal" : "egress") + " network " + name,
        error,
      );
    }
  }

  // Verify the internal network really is internal. A network that merely
  // exists under the right name proves nothing.
  try {
    const internalFlag = await run(engine, [
      "network",
      "inspect",
      internalNetwork,
      "--format",
      "{{.Internal}}",
    ]);
    if (!/true/i.test(internalFlag)) {
      throw new Error("network reports Internal=" + internalFlag);
    }
  } catch (error) {
    throw new WardenStartupError(
      "Network " + internalNetwork + " is not isolated, so Runtime egress cannot be contained",
      error,
    );
  }
}

function brokerDistDirectory(): string {
  // dist/warden/broker-container.js -> dist
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
}

/**
 * Starts the broker as a dual-homed container.
 *
 * No new image is built: the compiled `dist` tree is copied into the existing
 * Runtime image, which already carries Node 22. The broker subtree imports only
 * Node built-ins, so nothing has to be installed inside the container.
 */
export async function startWardenBroker(
  config: AppConfig,
  controlSecret: string,
): Promise<BrokerHandle> {
  const engine = config.containerEngine;
  const containerName =
    "launchpad-warden-" + config.runtimeInstanceId.replace(/[^a-zA-Z0-9_.-]/g, "-").slice(0, 32);

  await quiet(engine, ["rm", "--force", containerName]);

  const environment: Record<string, string> = {
    ARK_API_KEY: config.arkApiKey,
    WARDEN_UPSTREAM_BASE_URL: config.arkBaseUrl,
    WARDEN_CONTROL_SECRET: controlSecret,
    WARDEN_PORT: String(config.warden.port),
    WARDEN_CONTROL_PORT: String(config.warden.controlPort),
    WARDEN_INTERNAL_NETWORK: config.warden.internalNetwork,
    // The broker resolves this alias to keep the control API off the Runtime
    // interface; a non-default value must reach it or startup fails closed.
    WARDEN_BROKER_HOST: config.warden.brokerHost,
    WARDEN_MODEL_PATHS: config.warden.modelPaths.join(","),
    WARDEN_GRANT_TTL_MS: String(config.warden.grantTtlMs),
    WARDEN_MAX_MODEL_CALLS: String(config.warden.maxModelCalls),
    WARDEN_MAX_TOTAL_TOKENS: String(config.warden.maxTotalTokens),
    WARDEN_MAX_WALL_CLOCK_MS: String(config.warden.maxWallClockMs),
    WARDEN_ALLOWED_NETWORK_HOSTS: config.warden.allowedNetworkHosts.join(","),
  };

  try {
    await run(engine, [
      "create",
      "--name",
      containerName,
      "--label",
      "io.codejam.launchpad=warden-broker",
      "--label",
      "io.codejam.instance-id=" + config.runtimeInstanceId,
      "--network",
      config.warden.egressNetwork,
      // Control API is published to loopback only. The internal network has no
      // route to host-published ports, so Runtimes cannot reach it.
      "--publish",
      "127.0.0.1:" + config.warden.controlPort + ":" + config.warden.controlPort,
      "--security-opt",
      "no-new-privileges",
      "--cap-drop",
      "ALL",
      "--memory",
      "512m",
      "--pids-limit",
      "128",
      ...Object.keys(environment).flatMap((name) => ["--env", name]),
      "--workdir",
      "/warden",
      config.containerRuntimeImage,
      "node",
      "/warden/warden/broker-main.js",
    ], 30_000, { ...process.env, ...environment });
  } catch (error) {
    throw new WardenStartupError("Could not create the Warden broker container", error);
  }

  try {
    // Ship the compiled broker in rather than bind-mounting it: bind mounts of
    // the repository are unreliable across Docker Desktop, Colima and Podman.
    await run(engine, ["cp", brokerDistDirectory() + "/.", containerName + ":/warden/"], 60_000);
    await run(engine, [
      "network",
      "connect",
      "--alias",
      config.warden.brokerHost,
      config.warden.internalNetwork,
      containerName,
    ]);
    await run(engine, ["start", containerName]);
  } catch (error) {
    await quiet(engine, ["rm", "--force", containerName]);
    throw new WardenStartupError("Could not start the Warden broker container", error);
  }

  const controlBaseUrl = "http://127.0.0.1:" + config.warden.controlPort;
  const deadline = Date.now() + 30_000;
  let lastError = "no response";
  while (Date.now() < deadline) {
    try {
      const response = await fetch(controlBaseUrl + "/control/health", {
        signal: AbortSignal.timeout(1_500),
      });
      if (response.ok) {
        return {
          containerName,
          controlBaseUrl,
          stop: async () => {
            await quiet(engine, ["rm", "--force", containerName]);
          },
        };
      }
      lastError = "status " + response.status;
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }

  const logs = await run(engine, ["logs", "--tail", "20", containerName]).catch(() => "");
  await quiet(engine, ["rm", "--force", containerName]);
  throw new WardenStartupError(
    "Warden broker did not become healthy (" + lastError + "). Container logs:\n" + logs,
  );
}
