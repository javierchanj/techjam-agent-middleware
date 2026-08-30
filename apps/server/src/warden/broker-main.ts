/**
 * Warden broker entrypoint. Runs INSIDE the dual-homed broker container.
 *
 *   launchpad-warden-internal  (--internal)  <- shared with Agent Runtimes
 *   launchpad-warden-egress    (bridge)      <- the only route to the internet
 *
 * The Runtime is attached to the internal network only, so this process is the
 * sole reachable destination and the sole holder of the real provider key.
 *
 * Deliberately depends on Node built-ins only: it is shipped by copying the
 * compiled `dist/warden` directory into the existing Runtime image, with no
 * package installation and no extra image build.
 */
import { lookup } from "node:dns/promises";
import { networkInterfaces } from "node:os";
import { WardenControlServer } from "./control-server.js";
import { InProcessWardenControl } from "./control.js";
import { WardenGateway } from "./gateway.js";
import { GrantVault } from "./grants.js";
import { WardenLedger } from "./ledger.js";
import { WardenPolicyStore } from "./policy.js";
import { Redactor } from "./redact.js";
import type { EgressScope } from "./types.js";

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error("Warden broker requires " + name);
  }
  return value;
}

function integer(name: string, fallback: number): number {
  const raw = process.env[name]?.trim();
  if (!raw) return fallback;
  const parsed = Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(name + " must be a positive integer");
  }
  return parsed;
}

const upstreamBaseUrl = required("WARDEN_UPSTREAM_BASE_URL");
const upstreamApiKey = required("ARK_API_KEY");
const controlSecret = required("WARDEN_CONTROL_SECRET");
const gatewayPort = integer("WARDEN_PORT", 8788);
const controlPort = integer("WARDEN_CONTROL_PORT", 8789);
const internalNetwork = process.env.WARDEN_INTERNAL_NETWORK ?? "launchpad-warden-internal";

const upstream = new URL(upstreamBaseUrl);
const upstreamPort = upstream.port
  ? Number(upstream.port)
  : upstream.protocol === "http:"
    ? 80
    : 443;

const redactor = new Redactor();
redactor.register(upstreamApiKey, "ark_api_key");
redactor.register(controlSecret, "warden_control_secret");

const scopes: EgressScope[] = [
  {
    plane: "model",
    host: upstream.hostname,
    ports: [upstreamPort],
    methods: ["GET", "POST"],
    description: "Configured Ark Responses endpoint",
  },
  ...(process.env.WARDEN_ALLOWED_NETWORK_HOSTS ?? "")
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0)
    .map<EgressScope>((entry) => {
      // Exact host:port entries. Wildcards are supported by the policy engine
      // but are not used by default: an explicit list is easier to audit.
      const separator = entry.lastIndexOf(":");
      const hasPort = separator > 0 && /^\d+$/.test(entry.slice(separator + 1));
      return {
        plane: "network",
        host: hasPort ? entry.slice(0, separator) : entry,
        ports: hasPort ? [Number(entry.slice(separator + 1))] : [443],
        description: "Operator-allowlisted destination",
      };
    }),
];

const policy = new WardenPolicyStore(scopes, {
  maxModelCalls: integer("WARDEN_MAX_MODEL_CALLS", 40),
  maxTotalTokens: integer("WARDEN_MAX_TOTAL_TOKENS", 500_000),
  maxWallClockMs: integer("WARDEN_MAX_WALL_CLOCK_MS", 600_000),
});
const ledger = new WardenLedger(redactor, { maxTraces: 200 });
const vault = new GrantVault(redactor);

const modelPaths = (process.env.WARDEN_MODEL_PATHS ?? "")
  .split(",")
  .map((entry) => entry.trim())
  .filter((entry) => entry.length > 0);

const gateway = new WardenGateway({
  vault,
  ledger,
  redactor,
  upstreamBaseUrl,
  upstreamApiKey,
  host: "0.0.0.0",
  port: gatewayPort,
  ...(modelPaths.length > 0 ? { modelPaths } : {}),
});
const control = new InProcessWardenControl({
  vault,
  ledger,
  policy,
  grantTtlMs: integer("WARDEN_GRANT_TTL_MS", 900_000),
  gatewayPort,
  internalNetwork,
  upstreamHost: upstream.hostname,
  upstreamPort,
  // Revoking authority also tears down whatever that authority was being used for.
  onGrantRevoked: (grantId) => gateway.closeForGrant(grantId),
});

/**
 * Discover this container's address on the INTERNAL network by resolving its own
 * alias, then refuse to serve the control API on that interface. The gateway is
 * the only thing a Runtime may talk to.
 */
const brokerAlias = process.env.WARDEN_BROKER_HOST ?? "warden-broker";
const internalAddresses: string[] = [];
try {
  const resolved = await lookup(brokerAlias, { all: true });
  internalAddresses.push(...resolved.map((entry) => entry.address));
} catch (error) {
  // Fail closed. If we cannot identify the internal interface we cannot keep
  // the control API off it, and binding anyway would silently expose control
  // to the Runtime with only the shared secret in front of it.
  if (process.env.WARDEN_UNSAFE_SKIP_INTERFACE_GUARD !== "1") {
    throw new Error(
      "Could not resolve the broker alias '" + brokerAlias + "', so the control API " +
        "cannot be kept off the Runtime network. Refusing to start. " +
        (error instanceof Error ? error.message : ""),
    );
  }
  process.stdout.write(
    "[warden] WARNING: interface guard disabled (development only); " +
      "control API is protected by its secret alone\n",
  );
}

/**
 * Bind the control API to the EGRESS interface only.
 *
 * A request-layer guard is not enough: binding 0.0.0.0 still completes the TCP
 * handshake on the internal interface, so a Runtime can confirm the port is
 * open even though it can never get a response. Not listening there at all is
 * the property we actually want, and the one the integration test asserts.
 *
 * The request-layer guard below stays as defence in depth, for the case where
 * the address set changes under us at runtime.
 */
const localAddresses = Object.values(networkInterfaces())
  .flat()
  .filter((entry) => entry && entry.family === "IPv4" && !entry.internal)
  .map((entry) => entry?.address ?? "")
  .filter((address) => address.length > 0);
const egressAddresses = localAddresses.filter(
  (address) => !internalAddresses.includes(address),
);

let controlBindAddress: string;
if (process.env.WARDEN_UNSAFE_SKIP_INTERFACE_GUARD === "1") {
  // Development only: the broker is running as a host process, where there is
  // no internal network to keep the control API off.
  controlBindAddress = "0.0.0.0";
  process.stdout.write(
    "[warden] WARNING: binding control to 0.0.0.0 (development only)\n",
  );
} else if (egressAddresses.length === 1) {
  controlBindAddress = egressAddresses[0] as string;
} else {
  // Fail closed: if we cannot single out the egress interface we cannot keep
  // the control API off the Runtime network.
  throw new Error(
    "Could not identify a single egress interface for the control API. " +
      "Found [" + localAddresses.join(", ") + "], internal [" +
      internalAddresses.join(", ") + "]. Refusing to start.",
  );
}

const controlServer = new WardenControlServer(
  control,
  controlSecret,
  controlBindAddress,
  controlPort,
  internalAddresses,
);

const gatewayAddress = await gateway.listen();
const controlAddress = await controlServer.listen();
process.stdout.write(
  "[warden] broker ready gateway=" +
    gatewayAddress.port +
    " control=" +
    controlAddress +
    " upstream=" +
    upstream.hostname +
    " control-bound-to=" +
    controlBindAddress +
    " control-blocked-on=" +
    (internalAddresses.join(",") || "none") +
    "\n",
);

const shutdown = async () => {
  await gateway.close();
  await controlServer.close();
  process.exit(0);
};
process.on("SIGTERM", () => void shutdown());
process.on("SIGINT", () => void shutdown());
