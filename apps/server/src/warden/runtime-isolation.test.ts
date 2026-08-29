import { describe, expect, it } from "vitest";
import { buildContainerRunArgs } from "../container-codex-runner.js";
import { loadConfig } from "../config.js";
import type { RunnerRequest } from "../types.js";

const REAL_KEY = "ark_live_never_leaves_the_host_1234";

const config = loadConfig({
  ARK_API_KEY: REAL_KEY,
  ARK_MODEL: "ep-test",
  RUNTIME_PROVIDER: "container",
  NODE_ENV: "test",
});

const baseRequest: RunnerRequest = {
  agentId: "11111111-2222-3333-4444-555555555555",
  workspacePath: "/tmp/workspace",
  prompt: "hello",
  threadId: null,
};

describe("Runtime isolation", () => {
  it("keeps the original bridge behaviour when no grant is supplied", () => {
    const args = buildContainerRunArgs(baseRequest, config);
    expect(args).toContain("bridge");
    expect(args).not.toContain("--add-host");
  });

  it("attaches the Runtime to the internal network and nothing else", () => {
    const args = buildContainerRunArgs(
      {
        ...baseRequest,
        credentials: {
          arkApiKey: "wgt_minted",
          network: "launchpad-warden-internal",
          extraEnv: { HTTPS_PROXY: "http://grant:wgt_minted@warden-broker:8788" },
        },
      },
      config,
    );
    expect(args.filter((arg) => arg === "--network")).toHaveLength(1);
    expect(args[args.indexOf("--network") + 1]).toBe("launchpad-warden-internal");
    // The broker is resolved by container DNS on the internal network, so no
    // host alias is needed and the host is never named as a destination.
    expect(args).not.toContain("--add-host");
    expect(args.join(" ")).not.toContain("host-gateway");
  });

  it("never places any credential in the container argv", () => {
    const token = "wgt_" + "s".repeat(43);
    const proxy = "http://grant:" + token + "@warden.internal:8788";
    const args = buildContainerRunArgs(
      {
        ...baseRequest,
        credentials: {
          arkApiKey: token,
          network: "launchpad-warden-internal",
          extraEnv: { HTTPS_PROXY: proxy, HTTP_PROXY: proxy },
        },
      },
      config,
    );
    const flattened = args.join(" ");
    // Passthrough form: names in argv, values in the spawn environment. This
    // keeps credentials out of `ps` output. It does NOT hide them from
    // `docker inspect`, which resolves and stores the environment -- the grant
    // token is expected to be visible there, and is safe to be: it is
    // run-scoped, metered and revocable. The real key is what must never appear.
    expect(flattened).not.toContain(token);
    expect(flattened).not.toContain(REAL_KEY);
    expect(args).toContain("ARK_API_KEY");
    expect(args).toContain("HTTPS_PROXY");
    expect(args).toContain("HTTP_PROXY");
  });

  it("preserves the baseline hardening flags", () => {
    const args = buildContainerRunArgs(baseRequest, config);
    expect(args).toContain("no-new-privileges");
    expect(args).toContain("--cap-drop");
    expect(args).toContain("--pids-limit");
  });
});
