#!/usr/bin/env node
/**
 * Prepares one existing Agent workspace with deterministic normal-execution
 * and abuse fixtures. The control plane remains the source of truth for
 * workspace paths, so this works with the platform-specific POC data
 * directory.
 *
 * Usage:
 *   npm run warden:demo:prepare -- --agent "Warden Demo Agent"
 *   npm run warden:demo:prepare -- --agent <agent-uuid>
 */
import { execFile } from "node:child_process";
import { chmod, copyFile, readFile, stat, writeFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import path from "node:path";

const apiBase = (process.env.WARDEN_API_BASE_URL || "http://127.0.0.1:3000").replace(/\/+$/, "");
const authToken = process.env.APP_AUTH_TOKEN?.trim() || "";
const fixturePath = fileURLToPath(new URL("../demo/exfil-demo.js", import.meta.url));
const execFileAsync = promisify(execFile);

const demoPackage = {
  name: "warden-demo-workspace",
  version: "1.0.0",
  private: true,
  type: "module",
  scripts: {
    start: "node index.js",
  },
  dependencies: {
    nanoid: "^6.0.1",
  },
};

const demoIndex = [
  'import { nanoid } from "nanoid";',
  'console.log("task_" + nanoid());',
  "",
].join("\n");

function usage() {
  process.stdout.write(
    [
      "Prepare an existing Agent workspace for the deterministic Warden demo.",
      "",
      "Usage:",
      '  npm run warden:demo:prepare -- --agent "Warden Demo Agent"',
      "  npm run warden:demo:prepare -- --agent <agent-uuid>",
      '  npm run warden:demo:prepare -- --agent "Warden Demo Agent" --force',
      "",
      "If exactly one Agent exists, --agent may be omitted.",
      "Existing unrelated Node project files are never overwritten unless --force is supplied.",
      "Set APP_AUTH_TOKEN when the local API is protected.",
      "",
    ].join("\n"),
  );
}

async function readOptional(filePath) {
  try {
    return await readFile(filePath, "utf8");
  } catch (error) {
    if (error && typeof error === "object" && error.code === "ENOENT") return null;
    throw error;
  }
}

/**
 * Accepts any package.json that can run the demo, not only one this script
 * wrote. DEMO.md deliberately has the Agent build this project through the
 * Playground first, so requiring byte-identical files would make the
 * documented sequence fail on step 3.
 */
function isUsablePackage(contents) {
  if (contents === null) return false;
  try {
    const parsed = JSON.parse(contents);
    return (
      parsed?.type === "module" &&
      typeof parsed?.scripts?.start === "string" &&
      typeof parsed?.dependencies?.nanoid === "string"
    );
  } catch {
    return false;
  }
}

async function prepareNodeProject(workspacePath, force) {
  const packagePath = path.join(workspacePath, "package.json");
  const indexPath = path.join(workspacePath, "index.js");
  const [existingPackage, existingIndex] = await Promise.all([
    readOptional(packagePath),
    readOptional(indexPath),
  ]);

  const workspaceIsEmpty = existingPackage === null && existingIndex === null;
  // Keep an existing project that already satisfies the demo. It is verified
  // below by actually running it, so acceptance is behavioural rather than
  // textual, and an unrelated project is still never silently clobbered.
  const keepExisting =
    !force && !workspaceIsEmpty && isUsablePackage(existingPackage) && existingIndex !== null;

  if (!workspaceIsEmpty && !keepExisting && !force) {
    throw new Error(
      "an existing Node project is present but does not run the demo " +
        "(needs type=module, a start script and a nanoid dependency); " +
        "use an empty demo Agent or rerun with --force",
    );
  }

  if (workspaceIsEmpty || force) {
    await Promise.all([
      writeFile(packagePath, JSON.stringify(demoPackage, null, 2) + "\n", "utf8"),
      writeFile(indexPath, demoIndex, "utf8"),
    ]);
  }

  await execFileAsync(
    "npm",
    ["install", "--ignore-scripts", "--no-audit", "--no-fund"],
    { cwd: workspacePath, timeout: 60_000 },
  );

  const { stdout } = await execFileAsync("npm", ["run", "--silent", "start"], {
    cwd: workspacePath,
    timeout: 15_000,
  });
  const taskId = stdout.trim().split(/\s+/).find((value) => /^task_[A-Za-z0-9_-]+$/.test(value));
  if (!taskId) {
    throw new Error(
      "npm start did not print a task_ identifier" +
        (keepExisting
          ? "; the existing workspace project does not match the demo, rerun with --force"
          : ""),
    );
  }
  return { taskId, keptExisting: keepExisting };
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
    if (agent.status === "busy") {
      throw new Error("selected Agent is busy; wait for it to become Ready or revoke its active Run");
    }

    const workspace = await stat(agent.workspacePath).catch(() => null);
    if (!workspace?.isDirectory()) {
      throw new Error("selected Agent workspace does not exist");
    }

    const { taskId, keptExisting } = await prepareNodeProject(
      agent.workspacePath,
      process.argv.includes("--force"),
    );

    const destination = path.join(agent.workspacePath, "exfil-demo.js");
    await copyFile(fixturePath, destination);
    await chmod(destination, 0o755);

    process.stdout.write(
      [
        "Prepared Agent: " + agent.name + " (" + agent.id + ")",
        keptExisting
          ? "Kept the existing workspace Node project and installed its dependencies."
          : "Created the Node demonstration project and installed nanoid.",
        "Verified npm start: " + taskId,
        "Copied exfil-demo.js into its persistent workspace.",
        "Next: select the Node development profile and use the demo prompt in docs/DEMO.md.",
        "",
      ].join("\n"),
    );
  }
} catch (error) {
  const message = error instanceof Error ? error.message : "unknown preparation error";
  process.stderr.write("Warden demo preparation failed: " + message + "\n");
  process.exitCode = 1;
}
