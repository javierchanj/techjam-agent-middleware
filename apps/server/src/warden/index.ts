import { randomBytes } from "node:crypto";
import { join as pathJoin } from "node:path";
import type { AppConfig } from "../config.js";
import type { AgentRunner } from "../types.js";
import { RemoteWardenControl } from "./control-client.js";
import {
  ensureWardenNetworks,
  startWardenBroker,
  WardenStartupError,
  type BrokerHandle,
} from "./broker-container.js";
import { Redactor } from "./redact.js";
import { WardenTraceArchive } from "./trace-archive.js";
import { WardenRunner } from "./warden-runner.js";
import type { WardenControl } from "./control.js";

export * from "./types.js";
export type { WardenControl } from "./control.js";
export { InProcessWardenControl } from "./control.js";
export { RemoteWardenControl } from "./control-client.js";
export { WardenControlServer } from "./control-server.js";
export { WardenGateway, extractUsageTokens, parseCredentials, parseHostPort } from "./gateway.js";
export { GrantVault, hashToken } from "./grants.js";
export { WardenLedger } from "./ledger.js";
export {
  WardenPolicyStore,
  evaluate,
  isBlockedLiteralAddress,
  matchHost,
  normalizeHost,
} from "./policy.js";
export { Redactor, redactedMessage } from "./redact.js";
export { WardenRunner } from "./warden-runner.js";
export { registerWardenRoutes } from "./routes.js";
export { WardenTraceArchive } from "./trace-archive.js";
export { GRANT_TEMPLATES, describeTemplates, findTemplate } from "./templates.js";
export { ensureWardenNetworks, startWardenBroker, WardenStartupError };

export interface Warden {
  control: WardenControl;
  archive: WardenTraceArchive;
  redactor: Redactor;
  broker: BrokerHandle;
  wrapRunner(runner: AgentRunner): AgentRunner;
  stop(): Promise<void>;
}

/**
 * Brings up the Warden broker and returns the control-plane handle.
 *
 * Fail-closed by construction: every step throws. There is no degraded mode,
 * because a degraded Warden is a platform that claims containment it does not
 * have. If this function throws, the server must not start.
 */
export async function startWarden(config: AppConfig): Promise<Warden> {
  if (config.runtimeProvider !== "container") {
    throw new WardenStartupError("Warden requires the container Runtime provider");
  }
  const redactor = new Redactor();
  redactor.register(config.arkApiKey, "ark_api_key");
  redactor.register(config.authToken, "app_auth_token");

  const controlSecret = randomBytes(32).toString("base64url");
  redactor.register(controlSecret, "warden_control_secret");

  await ensureWardenNetworks(config);
  const broker = await startWardenBroker(config, controlSecret);
  const control = new RemoteWardenControl(broker.controlBaseUrl, controlSecret);

  const archive = new WardenTraceArchive(
    pathJoin(config.dataDirectory, "warden-traces.jsonl"),
  );

  return {
    control,
    archive,
    redactor,
    broker,
    wrapRunner(runner: AgentRunner): AgentRunner {
      return new WardenRunner(runner, {
        control,
        archive,
        redactor,
        internalNetwork: config.warden.internalNetwork,
        brokerHost: config.warden.brokerHost,
        gatewayPort: config.warden.port,
        maxWallClockMs: config.warden.maxWallClockMs,
      });
    },
    stop: () => broker.stop(),
  };
}
