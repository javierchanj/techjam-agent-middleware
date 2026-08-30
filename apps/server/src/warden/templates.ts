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
    id: "model-plus-dev-tools",
    label: "Node development",
    description:
      "Inference plus the npm registry and GitHub, for Node.js Agents that install dependencies or work with repositories.",
    guarantees: [
      "Outbound network limited to the npm registry and GitHub hosts on port 443",
      "Connections are pinned to the screened resolved address",
      "Request contents are NOT inspected: TLS is opaque to the broker, so an allowed host can receive anything",
    ],
    build: (host, port) => [
      modelScope(host, port),
      { plane: "network", host: "registry.npmjs.org", ports: [443], description: "npm registry" },
      { plane: "network", host: "github.com", ports: [443], description: "GitHub" },
      { plane: "network", host: "api.github.com", ports: [443], description: "GitHub API" },
      { plane: "network", host: "codeload.github.com", ports: [443], description: "GitHub archives" },
    ],
  },
  {
    id: "no-external-network",
    label: "Deny all",
    description:
      "Emergency and demo kill switch: a new Playground turn is denied before inference because no egress is delegated.",
    guarantees: [
      "Every outbound request is denied, including model calls",
      "A new Codex turn cannot execute while this profile is active",
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
