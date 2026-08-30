import { mkdtemp, readFile, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { WardenTraceArchive } from "./trace-archive.js";
import type { WardenTrace } from "./types.js";

function traceFixture(id: string, agentId = "agent_1", spans = 1): WardenTrace {
  return {
    traceId: id,
    runId: "run_" + id,
    agentId,
    grantId: "grant_" + id,
    status: "ok",
    startedAt: new Date(Date.parse("2026-01-01T00:00:00Z") + Number(id.slice(1)) * 1000).toISOString(),
    endedAt: null,
    spans: Array.from({ length: spans }, (_unused, index) => ({
      id: "span_" + index,
      traceId: id,
      parentId: null,
      runId: "run_" + id,
      agentId,
      kind: "model_call" as const,
      name: "POST /v1/responses",
      status: "ok" as const,
      startedAt: "2026-01-01T00:00:00.000Z",
      endedAt: "2026-01-01T00:00:01.000Z",
      durationMs: 1000,
      attributes: { filler: "x".repeat(400) },
    })),
  };
}

async function archiveIn(maxBytes: number) {
  const directory = await mkdtemp(path.join(tmpdir(), "warden-archive-"));
  const file = path.join(directory, "traces.jsonl");
  return { file, archive: new WardenTraceArchive(file, maxBytes) };
}

describe("WardenTraceArchive", () => {
  it("finds a trace after the broker that produced it has gone", async () => {
    const { archive } = await archiveIn(1024 * 1024);
    await archive.append(traceFixture("t1"));
    expect((await archive.find("t1"))?.runId).toBe("run_t1");
    expect(await archive.find("t404")).toBeNull();
  });

  it("bounds the WHOLE file, not just one line", async () => {
    // The earlier implementation compared maxBytes against a single record, so
    // the archive itself grew without limit.
    const { file, archive } = await archiveIn(8_000);
    for (let index = 1; index <= 40; index += 1) {
      await archive.append(traceFixture("t" + index, "agent_1", 3));
    }
    const size = (await stat(file)).size;
    expect(size).toBeLessThanOrEqual(8_000 + 4_000);
  });

  it("keeps one previous generation, so a rotation does not lose recent evidence", async () => {
    const { file, archive } = await archiveIn(6_000);
    // Append until exactly one rotation has happened.
    let written = 0;
    let rotated = "";
    while (written < 60 && rotated.length === 0) {
      written += 1;
      await archive.append(traceFixture("t" + written, "agent_1", 3));
      rotated = await readFile(file + ".1", "utf8").catch(() => "");
    }
    expect(rotated.length).toBeGreaterThan(0);
    // Traces written just before the rotation are still retrievable from .1 --
    // that is the point of keeping a generation rather than truncating.
    const justBefore = await archive.find("t" + (written - 1));
    expect(justBefore?.traceId).toBe("t" + (written - 1));
    // And the newest one is in the live file.
    expect((await archive.find("t" + written))?.traceId).toBe("t" + written);
  });

  it("is genuinely bounded: the oldest evidence ages out after repeated rotation", async () => {
    // A bounded archive trades old evidence for a size guarantee. Stating that
    // explicitly stops anyone reading "archive" as "keeps everything forever".
    const { archive } = await archiveIn(6_000);
    for (let index = 1; index <= 40; index += 1) {
      await archive.append(traceFixture("t" + index, "agent_1", 3));
    }
    expect(await archive.find("t1")).toBeNull();
    expect((await archive.find("t40"))?.traceId).toBe("t40");
  });

  it("lists history for the rail, filtered by agent", async () => {
    const { archive } = await archiveIn(1024 * 1024);
    await archive.append(traceFixture("t1", "agent_a"));
    await archive.append(traceFixture("t2", "agent_b"));
    await archive.append(traceFixture("t3", "agent_a"));
    const forA = await archive.list("agent_a");
    expect(forA.map((trace) => trace.traceId).sort()).toEqual(["t1", "t3"]);
    expect((await archive.list()).length).toBe(3);
  });

  it("survives a corrupt line rather than losing the whole archive", async () => {
    const { file, archive } = await archiveIn(1024 * 1024);
    await archive.append(traceFixture("t1"));
    await writeFile(file, (await readFile(file, "utf8")) + "{not json}\n", "utf8");
    await archive.append(traceFixture("t2"));
    expect((await archive.list()).map((trace) => trace.traceId).sort()).toEqual(["t1", "t2"]);
  });
});
