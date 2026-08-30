import type { Agent, AgentRun, Message, SystemInfo } from "./types";
import type {
  Grant,
  PolicyCheckResult,
  TemplateDescriptor,
  TraceSummary,
  WardenStatus,
  WardenTrace,
} from "./warden-types";

export class ApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
  ) {
    super(message);
  }
}

let authToken = "";

export function setAuthToken(token: string): void {
  authToken = token.trim();
}

async function request<T>(url: string, options?: RequestInit): Promise<T> {
  const headers = {
    ...(options?.body ? { "Content-Type": "application/json" } : {}),
    ...(authToken ? { Authorization: "Bearer " + authToken } : {}),
    ...options?.headers,
  };
  const response = await fetch(url, {
    ...options,
    headers,
  });
  const data = (await response.json().catch(() => ({}))) as T & { error?: string };
  if (!response.ok) {
    throw new ApiError(data.error ?? "Request failed", response.status);
  }
  return data;
}

export const api = {
  auth: () => request<{ required: boolean }>("/api/auth"),
  system: () => request<SystemInfo>("/api/system"),
  listAgents: () => request<{ agents: Agent[] }>("/api/agents"),
  createAgent: (body: {
    name: string;
    description: string;
    instructions: string;
  }) =>
    request<{ agent: Agent }>("/api/agents", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  updateAgent: (
    id: string,
    body: { name: string; description: string; instructions: string },
  ) =>
    request<{ agent: Agent }>("/api/agents/" + id, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  deleteAgent: (id: string) =>
    request<{ archivedWorkspace: string }>("/api/agents/" + id, {
      method: "DELETE",
    }),
  startAgent: (id: string) =>
    request<{ agent: Agent }>("/api/agents/" + id + "/start", {
      method: "POST",
    }),
  stopAgent: (id: string) =>
    request<{ agent: Agent }>("/api/agents/" + id + "/stop", {
      method: "POST",
    }),
  messages: (id: string) =>
    request<{ messages: Message[] }>("/api/agents/" + id + "/messages"),
  runs: (id: string) =>
    request<{ runs: AgentRun[] }>("/api/agents/" + id + "/runs"),
  sendMessage: (id: string, content: string) =>
    request<{ run: AgentRun; message: Message }>(
      "/api/agents/" + id + "/messages",
      {
        method: "POST",
        body: JSON.stringify({ content }),
      },
    ),
  run: (id: string) => request<{ run: AgentRun }>("/api/runs/" + id),

  wardenStatus: () => request<WardenStatus>("/api/warden/status"),
  wardenGrants: () => request<{ grants: Grant[] }>("/api/warden/grants"),
  wardenTraces: (agentId?: string) =>
    request<{ traces: TraceSummary[] }>(
      "/api/warden/traces" + (agentId ? "?agentId=" + agentId : ""),
    ),
  wardenTrace: (traceId: string) =>
    request<{ trace: WardenTrace }>("/api/warden/traces/" + traceId),
  wardenRevoke: (grantId: string, reason: string) =>
    request<{ grant: Grant }>("/api/warden/grants/" + grantId + "/revoke", {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),
  wardenTemplates: () =>
    request<{ templates: TemplateDescriptor[] }>("/api/warden/templates"),
  wardenApplyTemplate: (id: string) =>
    request<{ policy: WardenStatus["policy"] }>("/api/warden/policy/template", {
      method: "POST",
      body: JSON.stringify({ id }),
    }),
  wardenCheck: (host: string) =>
    request<PolicyCheckResult>("/api/warden/policy/check", {
      method: "POST",
      body: JSON.stringify({ plane: "network", host, port: 443, method: "CONNECT" }),
    }),
};
