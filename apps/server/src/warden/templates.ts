import type { EgressScope } from "./types.js";

/**
 * Grant templates: named, auditable delegation profiles.
 *
 * The point is that an operator should be able to say what an Agent may reach
 * in one word, and that the word should mean something enforceable. Each
 * template is a scope set the broker mints new grants from.
 *
 * Note on naming honesty: there is no "GitHub read-only" template. Method-level
 * restriction is impossible on the network plane, because an HTTPS request
 * through a CONNECT tunnel is opaque to the broker — it can enforce WHERE the
 * Agent connects, not WHAT it sends. Naming a template "read-only" would claim
 * a control that does not exist.
 */
export interface GrantTemplate {
  id: string;
  label: string;
  description: string;
  /** Enforcement the template genuinely provides, in the operator's words. */
  guarantees: string[];
  build(upstreamHost: string, upstreamPort: number): EgressScope[];
}

const modelScope = (host: string, port: number): EgressScope => ({
  plane: "model",
  host,
  ports: [port],
  methods: ["GET", "POST"],
  description: "Configured Ark inference endpoint",
});

export const GRANT_TEMPLATES: readonly GrantTemplate[] = [
  {
    id: "model-only",
    label: "Model only",
    description: "The Agent may reach the inference endpoint and nothing else.",
    guarantees: [
      "No outbound network destination other than the model provider",
      "Provider surface limited to the inference paths",
      "No package installs, no git remotes, no webhooks",
    ],
    build: (host, port) => [modelScope(host, port)],
  },
  {
    id: "model-plus-github",
    label: "Model + GitHub",
    description:
      "Inference plus github.com and api.github.com, for Agents that clone or read repositories.",
    guarantees: [
      "Outbound network limited to GitHub hosts on port 443",
      "Connections are pinned to the resolved address",
      "Request contents are NOT inspected: TLS is opaque to the broker",
    ],
    build: (host, port) => [
      modelScope(host, port),
      { plane: "network", host: "github.com", ports: [443], description: "GitHub" },
      { plane: "network", host: "api.github.com", ports: [443], description: "GitHub API" },
      { plane: "network", host: "codeload.github.com", ports: [443], description: "GitHub archives" },
    ],
  },
  {
    id: "no-external-network",
    label: "Fully offline",
    description:
      "No egress at all, including inference. For Agents that only operate on files already in the workspace.",
    guarantees: [
      "Every outbound request is denied, including model calls",
      "Useful for reproducing a run with zero external dependencies",
    ],
    build: () => [],
  },
];

export function findTemplate(id: string): GrantTemplate | null {
  return GRANT_TEMPLATES.find((template) => template.id === id) ?? null;
}

/** Serializable form for the API: the build function is not sent to the browser. */
export function describeTemplates(
  upstreamHost: string,
  upstreamPort: number,
): Array<{
  id: string;
  label: string;
  description: string;
  guarantees: string[];
  scopes: EgressScope[];
}> {
  return GRANT_TEMPLATES.map((template) => ({
    id: template.id,
    label: template.label,
    description: template.description,
    guarantees: [...template.guarantees],
    scopes: template.build(upstreamHost, upstreamPort),
  }));
}
