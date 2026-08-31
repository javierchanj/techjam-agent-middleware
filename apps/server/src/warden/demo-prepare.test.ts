import { execFile } from "node:child_process";
import { createServer } from "node:http";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { afterEach, describe, expect, it } from "vitest";

const execFileAsync = promisify(execFile);
const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../../..",
);
const scriptPath = path.join(repositoryRoot, "scripts/warden-demo-prepare.mjs");
const fixturePath = path.join(repositoryRoot, "demo/exfil-demo.js");
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map((directory) =>
      rm(directory, { recursive: true, force: true }),
    ),
  );
});

describe("Warden demo preparation", () => {
  it("copies the controlled fixture into the selected Agent workspace", async () => {
    const workspace = await mkdtemp(path.join(tmpdir(), "warden-demo-workspace-"));
    temporaryDirectories.push(workspace);

    const server = createServer((request, response) => {
      expect(request.url).toBe("/api/agents");
      response.writeHead(200, { "content-type": "application/json" });
      response.end(
        JSON.stringify({
          agents: [
            {
              id: "11111111-1111-4111-8111-111111111111",
              name: "Warden Demo Agent",
              workspacePath: workspace,
            },
          ],
        }),
      );
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("test server did not bind");

    try {
      const result = await execFileAsync(
        process.execPath,
        [scriptPath, "--agent", "Warden Demo Agent"],
        {
          env: {
            ...process.env,
            WARDEN_API_BASE_URL: "http://127.0.0.1:" + address.port,
          },
        },
      );
      expect(result.stdout).toContain("Prepared Agent: Warden Demo Agent");
      expect(await readFile(path.join(workspace, "exfil-demo.js"), "utf8")).toBe(
        await readFile(fixturePath, "utf8"),
      );
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
