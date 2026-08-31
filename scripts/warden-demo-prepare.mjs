#!/usr/bin/env node
/**
 * Copies the deterministic Warden abuse fixture into one existing Agent
 * workspace. The control plane remains the source of truth for workspace
 * paths, so this works with the platform-specific POC data directory.
 *
 * Usage:
 *   npm run warden:demo:prepare -- --agent "Warden Demo Agent"
 *   npm run warden:demo:prepare -- --agent <agent-uuid>
 */
import { chmod, copyFile, stat } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import path from "node:path";

const apiBase = (process.env.WARDEN_API_BASE_URL || "http://127.0.0.1:3000").replace(/\/+$/, "");
const authToken = process.env.APP_AUTH_TOKEN?.trim() || "";
const fixturePath = fileURLToPath(new URL("../demo/exfil-demo.js", import.meta.url));

function usage() {
  process.stdout.write(
    [
      "Prepare an existing Agent workspace for the deterministic Warden demo.",
      "",
      "Usage:",
      '  npm run warden:demo:prepare -- --agent "Warden Demo Agent"',
      "  npm run warden:demo:prepare -- --agent <agent-uuid>",
      "",
      "If exactly one Agent exists, --agent may be omitted.",
      "Set APP_AUTH_TOKEN when the local API is protected.",
      "",
    ].join("\n"),
  );
}

function selectorFrom(argv) {
  const index = argv.indexOf("--agent");
  if (index < 0) return "";
  const value = argv[index + 1]?.trim();
  if (!value || value.startsWith("--")) {
    throw new Error("--agent requires an Agent name or UUID");
  }
  return value;
}

async function getAgents() {
  const response = await fetch(apiBase + "/api/agents", {
    headers: authToken ? { authorization: "Bearer " + authToken } : {},
    signal: AbortSignal.timeout(8_000),
  });
  if (response.status === 401) {
    throw new Error("API authentication required; set APP_AUTH_TOKEN and try again");
  }
  if (!response.ok) {
    throw new Error("Agent API returned HTTP " + response.status);
  }
  const payload = await response.json();
  if (!Array.isArray(payload?.agents)) {
    throw new Error("Agent API returned an unexpected response");
  }
  return payload.agents;
}

function selectAgent(agents, selector) {
  if (agents.length === 0) {
    throw new Error("no Agents exist; create one in the frontend first");
  }
  if (!selector) {
    if (agents.length === 1) return agents[0];
    throw new Error(
      "more than one Agent exists; rerun with --agent followed by a name or UUID",
    );
  }

  const byId = agents.filter((agent) => agent?.id === selector);
  if (byId.length === 1) return byId[0];
  const byName = agents.filter((agent) => agent?.name === selector);
  if (byName.length === 1) return byName[0];
  if (byName.length > 1) {
    throw new Error("multiple Agents have that name; select one by UUID");
  }
  throw new Error("Agent not found: " + selector);
}

try {
  if (process.argv.includes("--help") || process.argv.includes("-h")) {
    usage();
  } else {
    const agent = selectAgent(await getAgents(), selectorFrom(process.argv.slice(2)));
    if (
      typeof agent?.id !== "string" ||
      typeof agent?.name !== "string" ||
      typeof agent?.workspacePath !== "string"
    ) {
      throw new Error("selected Agent is missing its workspace metadata");
    }

    const workspace = await stat(agent.workspacePath).catch(() => null);
    if (!workspace?.isDirectory()) {
      throw new Error("selected Agent workspace does not exist");
    }

    const destination = path.join(agent.workspacePath, "exfil-demo.js");
    await copyFile(fixturePath, destination);
    await chmod(destination, 0o755);

    process.stdout.write(
      [
        "Prepared Agent: " + agent.name + " (" + agent.id + ")",
        "Copied exfil-demo.js into its persistent workspace.",
        "Next: select the Node development profile and use the demo prompt in docs/WARDEN.md.",
        "",
      ].join("\n"),
    );
  }
} catch (error) {
  const message = error instanceof Error ? error.message : "unknown preparation error";
  process.stderr.write("Warden demo preparation failed: " + message + "\n");
  process.exitCode = 1;
}
