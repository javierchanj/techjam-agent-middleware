import { randomUUID } from "node:crypto";
import { mkdir, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import type { Redactor } from "./redact.js";
import type {
  SpanAttributeValue,
  SpanKind,
  SpanStatus,
  WardenSpan,
  WardenTrace,
} from "./types.js";

export interface StartSpanInput {
  traceId: string;
  parentId?: string | null | undefined;
  runId: string;
  agentId: string;
  kind: SpanKind;
  name: string;
  attributes?: Record<string, SpanAttributeValue> | undefined;
}

export interface EndSpanInput {
  status: SpanStatus;
  attributes?: Record<string, SpanAttributeValue> | undefined;
}

export interface LedgerOptions {
  /** Bounded so a long-lived POC cannot grow without limit. */
  maxTraces?: number | undefined;
  /** Absolute path for the durable copy. Omit to keep the ledger in memory. */
  filePath?: string | undefined;
}

/**
 * Append-only, redaction-at-write trace store.
 *
 * Redaction happens here rather than at read time, so a secret never lands in
 * memory in an unredacted span in the first place — the ledger cannot leak what
 * it never accepted.
 */
export class WardenLedger {
  private readonly traces = new Map<string, WardenTrace>();
  private readonly order: string[] = [];
  private readonly maxTraces: number;
  private readonly filePath: string | null;
  private persistQueue: Promise<void> = Promise.resolve();

  constructor(
    private readonly redactor: Redactor,
    options: LedgerOptions = {},
  ) {
    this.maxTraces = options.maxTraces ?? 200;
    this.filePath = options.filePath ?? null;
  }

  newTraceId(): string {
    return "trace_" + randomUUID();
  }

  beginTrace(input: { traceId: string; runId: string; agentId: string }): WardenTrace {
    const trace: WardenTrace = {
      traceId: input.traceId,
      runId: input.runId,
      agentId: input.agentId,
      grantId: null,
      startedAt: new Date().toISOString(),
      endedAt: null,
      status: "running",
      spans: [],
    };
    this.traces.set(trace.traceId, trace);
    this.order.push(trace.traceId);
    this.evict();
    this.schedulePersist();
    return structuredClone(trace);
  }

  attachGrant(traceId: string, grantId: string): void {
    const trace = this.traces.get(traceId);
    if (!trace) return;
    trace.grantId = grantId;
    this.schedulePersist();
  }

  startSpan(input: StartSpanInput): string {
    const trace = this.traces.get(input.traceId);
    const span: WardenSpan = {
      id: "span_" + randomUUID(),
      traceId: input.traceId,
      parentId: input.parentId ?? null,
      runId: input.runId,
      agentId: input.agentId,
      kind: input.kind,
      name: input.name,
      status: "running",
      startedAt: new Date().toISOString(),
      endedAt: null,
      durationMs: null,
      attributes: this.redactAttributes(input.attributes ?? {}),
    };
    if (trace) {
      trace.spans.push(span);
      this.schedulePersist();
    }
    return span.id;
  }

  endSpan(traceId: string, spanId: string, input: EndSpanInput): void {
    const trace = this.traces.get(traceId);
    if (!trace) return;
    const span = trace.spans.find((item) => item.id === spanId);
    if (!span) return;
    const endedAt = new Date();
    span.status = input.status;
    span.endedAt = endedAt.toISOString();
    span.durationMs = endedAt.getTime() - Date.parse(span.startedAt);
    span.attributes = {
      ...span.attributes,
      ...this.redactAttributes(input.attributes ?? {}),
    };
    this.schedulePersist();
  }

  /** Convenience for point-in-time events that have no duration. */
  recordEvent(input: StartSpanInput & { status: SpanStatus }): string {
    const spanId = this.startSpan(input);
    this.endSpan(input.traceId, spanId, { status: input.status });
    return spanId;
  }

  endTrace(traceId: string, status: SpanStatus): void {
    const trace = this.traces.get(traceId);
    if (!trace) return;
    trace.status = status;
    trace.endedAt = new Date().toISOString();
    this.schedulePersist();
  }

  getTrace(traceId: string): WardenTrace | null {
    const trace = this.traces.get(traceId);
    return trace ? structuredClone(trace) : null;
  }

  listTraces(filter: { agentId?: string | undefined } = {}): WardenTrace[] {
    return [...this.traces.values()]
      .filter((trace) => !filter.agentId || trace.agentId === filter.agentId)
      .sort((left, right) => right.startedAt.localeCompare(left.startedAt))
      .map((trace) => structuredClone(trace));
  }

  /** Flat, newest-first view used by the denial feed in the UI. */
  listSpans(filter: { kind?: SpanKind | undefined; status?: SpanStatus | undefined; limit?: number | undefined } = {}): WardenSpan[] {
    const spans: WardenSpan[] = [];
    for (const trace of this.traces.values()) {
      for (const span of trace.spans) {
        if (filter.kind && span.kind !== filter.kind) continue;
        if (filter.status && span.status !== filter.status) continue;
        spans.push(structuredClone(span));
      }
    }
    spans.sort((left, right) => right.startedAt.localeCompare(left.startedAt));
    return spans.slice(0, filter.limit ?? 100);
  }

  async flush(): Promise<void> {
    await this.persistQueue;
  }

  private redactAttributes(
    attributes: Record<string, SpanAttributeValue>,
  ): Record<string, SpanAttributeValue> {
    const output: Record<string, SpanAttributeValue> = {};
    for (const [key, value] of Object.entries(attributes)) {
      output[key] = typeof value === "string" ? this.redactor.redactString(value) : value;
    }
    return output;
  }

  private evict(): void {
    while (this.order.length > this.maxTraces) {
      const oldest = this.order.shift();
      if (oldest) this.traces.delete(oldest);
    }
  }

  private schedulePersist(): void {
    if (!this.filePath) return;
    const target = this.filePath;
    this.persistQueue = this.persistQueue
      .then(async () => {
        const payload = JSON.stringify(
          { version: 1, traces: [...this.traces.values()] },
          null,
          2,
        );
        await mkdir(path.dirname(target), { recursive: true });
        const temporary = target + ".tmp";
        await writeFile(temporary, payload + "\n", { encoding: "utf8", mode: 0o600 });
        await rename(temporary, target);
      })
      .catch(() => undefined);
  }
}
