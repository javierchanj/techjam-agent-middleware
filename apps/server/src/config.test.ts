import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { loadConfig, writeCodexConfig } from "./config.js";

describe("Codex configuration", () => {
  it("disables optional metrics instead of widening Warden for telemetry", async () => {
    const codexHome = await mkdtemp(path.join(tmpdir(), "warden-codex-config-"));
    // Assemble credentials at runtime so test fixtures cannot be mistaken for
    // live secrets by repository scanners.
    const providerKey = ["ark", "live", "config", "fixture", "123456"].join("_");
    try {
      const config = loadConfig({
        CODEX_HOME: codexHome,
        ARK_API_KEY: providerKey,
        ARK_MODEL: "ep-config-test",
        ARK_BASE_URL: "https://ark.example.test/api/v3",
        RUNTIME_PROVIDER: "container",
        WARDEN_ENABLED: "true",
      });

      await writeCodexConfig(config);
      const contents = await readFile(path.join(codexHome, "config.toml"), "utf8");

      expect(contents).toContain("[otel]\nmetrics_exporter = \"none\"");
      expect(contents).not.toContain("ab.chatgpt.com");
      expect(contents).not.toContain(providerKey);
    } finally {
      await rm(codexHome, { recursive: true, force: true });
    }
  });
});
