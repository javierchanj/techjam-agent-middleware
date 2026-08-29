import { appendFile, mkdir, readFile } from "node:fs/promises";
import path from "node:path";
import type { WardenTrace } from "./types.js";

/**
 * Bounded JSONL archive of completed traces, written by the control plane.
 *
 * The broker's ledger is in-memory and dies with the container, which would
 * leave persisted Runs pointing at trace ids that no longer resolve. After each
 * run ends, the control plane pulls the finished trace and appends it here, so
 * evidence outlives the broker.
 *
 * Traces are already redacted at ledger-write time inside the broker, so
 * nothing sensitive reaches this file.
 */
export class WardenTraceArchive {
  constructor(
    private readonly filePath: string,
    private readonly maxBytes = 8 * 1024 * 1024,
  ) {}

  async append(trace: WardenTrace): Promise<void> {
    const line = JSON.stringify(trace) + "\n";
    if (Buffer.byteLength(line) > this.maxBytes) return;
    await mkdir(path.dirname(this.filePath), { recursive: true });
    await appendFile(this.filePath, line, { encoding: "utf8", mode: 0o600 });
  }

  /** Reads a trace back after the broker that produced it has gone. */
  async find(traceId: string): Promise<WardenTrace | null> {
    let contents: string;
    try {
      contents = await readFile(this.filePath, "utf8");
    } catch {
      return null;
    }
    // Reverse order: the newest record for a trace id wins.
    const lines = contents.split("\n").filter((line) => line.trim().length > 0);
    for (let index = lines.length - 1; index >= 0; index -= 1) {
      try {
        const parsed = JSON.parse(lines[index] as string) as WardenTrace;
        if (parsed.traceId === traceId) return parsed;
      } catch {
        continue;
      }
    }
    return null;
  }
}
