import { appendFile, mkdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import type { WardenTrace } from "./types.js";

/**
 * Bounded JSONL archive of completed traces, written by the control plane.
 *
 * The broker's ledger is in-memory and dies with the container, which would
 * leave persisted Runs pointing at trace ids that no longer resolve. After each
 * run ends the control plane pulls the finished trace and appends it here, so
 * evidence outlives the broker.
 *
 * Traces are already redacted at ledger-write time inside the broker, so
 * nothing sensitive reaches this file.
 */
export class WardenTraceArchive {
  constructor(
    private readonly filePath: string,
    /** Cap on the WHOLE archive, not one line. Rotated once exceeded. */
    private readonly maxBytes = 8 * 1024 * 1024,
    /** Single records larger than this are dropped rather than rotating the file. */
    private readonly maxRecordBytes = 512 * 1024,
  ) {}

  async append(trace: WardenTrace): Promise<void> {
    const line = JSON.stringify(trace) + "\n";
    if (Buffer.byteLength(line) > this.maxRecordBytes) return;
    await mkdir(path.dirname(this.filePath), { recursive: true });
    await this.rotateIfNeeded(Buffer.byteLength(line));
    await appendFile(this.filePath, line, { encoding: "utf8", mode: 0o600 });
  }

  /**
   * Keeps one previous generation. An unbounded append-only file was the
   * earlier behaviour: `maxBytes` guarded a single line, so the archive itself
   * could grow without limit and `find()` read all of it on every lookup.
   */
  private async rotateIfNeeded(incoming: number): Promise<void> {
    let size = 0;
    try {
      size = (await stat(this.filePath)).size;
    } catch {
      return; // No file yet.
    }
    if (size + incoming <= this.maxBytes) return;
    try {
      await rename(this.filePath, this.filePath + ".1");
      await writeFile(this.filePath, "", { encoding: "utf8", mode: 0o600 });
    } catch {
      // If rotation fails the append still proceeds; losing evidence is worse
      // than exceeding the cap.
    }
  }

  /** Reads a trace back after the broker that produced it has gone. */
  async find(traceId: string): Promise<WardenTrace | null> {
    for (const candidate of [this.filePath, this.filePath + ".1"]) {
      const found = await this.scan(candidate, (trace) => trace.traceId === traceId);
      if (found.length > 0) return found[found.length - 1] ?? null;
    }
    return null;
  }

  /** Summaries for the rail, so history survives a broker restart. */
  async list(agentId?: string | undefined): Promise<WardenTrace[]> {
    const seen = new Map<string, WardenTrace>();
    for (const candidate of [this.filePath + ".1", this.filePath]) {
      const traces = await this.scan(
        candidate,
        (trace) => !agentId || trace.agentId === agentId,
      );
      // Later generations win, so a re-archived trace supersedes its older copy.
      for (const trace of traces) seen.set(trace.traceId, trace);
    }
    return [...seen.values()];
  }

  private async scan(
    filePath: string,
    predicate: (trace: WardenTrace) => boolean,
  ): Promise<WardenTrace[]> {
    let contents: string;
    try {
      contents = await readFile(filePath, "utf8");
    } catch {
      return [];
    }
    const matches: WardenTrace[] = [];
    for (const line of contents.split("\n")) {
      if (line.trim().length === 0) continue;
      try {
        const parsed = JSON.parse(line) as WardenTrace;
        if (predicate(parsed)) matches.push(parsed);
      } catch {
        continue;
      }
    }
    return matches;
  }
}
