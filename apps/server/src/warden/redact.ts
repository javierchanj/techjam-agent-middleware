/**
 * Dynamic secret redaction.
 *
 * Two layers:
 *  1. A live registry of exact secret values (the real Ark key, the app bearer
 *     token, every minted grant token). Registered at startup / mint time and
 *     unregistered when a grant closes.
 *  2. Shape-based patterns for credentials we never held ourselves, e.g. a key
 *     the Agent invented and tried to send outbound.
 *
 * Everything that crosses into the ledger, the HTTP API, or a run error message
 * goes through `redact()` first.
 */

const MIN_SECRET_LENGTH = 8;

interface PatternRule {
  label: string;
  pattern: RegExp;
}

const PATTERN_RULES: PatternRule[] = [
  { label: "authorization_header", pattern: /\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}/gi },
  { label: "ark_api_key", pattern: /\bark[_-][A-Za-z0-9]{12,}\b/gi },
  { label: "aws_access_key_id", pattern: /\bAKIA[0-9A-Z]{16}\b/g },
  { label: "openai_style_key", pattern: /\bsk-[A-Za-z0-9]{16,}\b/g },
  { label: "warden_grant_token", pattern: /\bwgt_[A-Za-z0-9_-]{16,}\b/g },
  { label: "private_key_block", pattern: /-----BEGIN[^-]{0,40}PRIVATE KEY-----[\s\S]*?-----END[^-]{0,40}PRIVATE KEY-----/g },
];

function marker(label: string): string {
  return "[redacted:" + label + "]";
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export class Redactor {
  private readonly exact = new Map<string, string>();

  /** Register a live secret. Values shorter than 8 characters are ignored so a
   *  stray empty-string config cannot blank out every log line. */
  register(value: string | null | undefined, label: string): void {
    if (!value) return;
    const trimmed = value.trim();
    if (trimmed.length < MIN_SECRET_LENGTH) return;
    this.exact.set(trimmed, label);
  }

  unregister(value: string | null | undefined): void {
    if (!value) return;
    this.exact.delete(value.trim());
  }

  get registeredCount(): number {
    return this.exact.size;
  }

  redactString(input: string): string {
    let output = input;
    for (const [secret, label] of this.exact) {
      if (!output.includes(secret)) continue;
      output = output.replace(new RegExp(escapeRegExp(secret), "g"), marker(label));
    }
    for (const rule of PATTERN_RULES) {
      rule.pattern.lastIndex = 0;
      output = output.replace(rule.pattern, marker(rule.label));
    }
    return output;
  }

  /** Deep-redacts strings inside plain objects, arrays, Maps and Errors. */
  redact<T>(input: T): T {
    return this.walk(input, 0) as T;
  }

  redactHeaders(
    headers: Record<string, string | string[] | undefined>,
  ): Record<string, string> {
    const output: Record<string, string> = {};
    for (const [name, raw] of Object.entries(headers)) {
      if (raw === undefined) continue;
      const key = name.toLowerCase();
      const value = Array.isArray(raw) ? raw.join(", ") : raw;
      output[key] =
        key === "authorization" || key === "proxy-authorization" || key === "cookie"
          ? marker("authorization_header")
          : this.redactString(value);
    }
    return output;
  }

  private walk(input: unknown, depth: number): unknown {
    if (depth > 8) return "[redacted:depth_limit]";
    if (typeof input === "string") return this.redactString(input);
    if (input === null || typeof input !== "object") return input;
    if (Array.isArray(input)) return input.map((item) => this.walk(item, depth + 1));
    if (input instanceof Error) {
      const clone = new Error(this.redactString(input.message));
      clone.name = input.name;
      return clone;
    }
    const output: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(input as Record<string, unknown>)) {
      output[key] = this.walk(value, depth + 1);
    }
    return output;
  }
}

/** Convenience for error paths where we do not want to thread a Redactor. */
export function redactedMessage(redactor: Redactor, error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return redactor.redactString(message);
}
