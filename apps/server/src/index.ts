import path from "node:path";
import { AgentService } from "./agent-service.js";
import { createApp } from "./app.js";
import { loadConfig, modelPlaneBaseUrl, writeCodexConfig } from "./config.js";
import { createRunner } from "./runner-factory.js";
import { listenWithCleanup } from "./startup.js";
import { JsonStore } from "./store.js";
import { startWarden, type Warden } from "./warden/index.js";
import { WorkspaceManager } from "./workspace.js";

const config = loadConfig();
await writeCodexConfig(config);

const store = new JsonStore(path.join(config.dataDirectory, "launchpad.json"));
const workspaces = new WorkspaceManager(config.workspaceRoot);
const baseRunner = createRunner(config);

/**
 * Warden is fail-closed. If the broker or its isolated network cannot be
 * brought up, the server refuses to start rather than silently running Agents
 * with a production credential and open internet access.
 */
let warden: Warden | null = null;
if (config.warden.enabled) {
  warden = await startWarden(config);
}

const runner = warden ? warden.wrapRunner(baseRunner) : baseRunner;
const service = new AgentService(config, store, workspaces, runner);
await service.initialize();

const app = await createApp(
  config,
  service,
  warden
    ? {
        control: warden.control,
        archive: warden.archive,
        containerNetwork: config.warden.internalNetwork,
        cancelRun: (agentId: string, expectedRunId: string) =>
          service.cancelRun(agentId, expectedRunId),
      }
    : undefined,
);

if (warden) {
  app.log.info(
    {
      broker: warden.broker.containerName,
      internalNetwork: config.warden.internalNetwork,
      egressNetwork: config.warden.egressNetwork,
      modelPlaneBaseUrl: modelPlaneBaseUrl(config),
    },
    "Warden egress broker active",
  );
} else {
  app.log.warn("Warden is disabled: Runtimes hold the provider key and have open egress");
}

const shutdown = async (signal: string) => {
  app.log.info({ signal }, "Shutting down");
  await app.close();
  if (warden) await warden.stop();
  process.exit(0);
};

process.on("SIGTERM", () => void shutdown("SIGTERM"));
process.on("SIGINT", () => void shutdown("SIGINT"));

await listenWithCleanup(app, warden, { host: config.host, port: config.port });
