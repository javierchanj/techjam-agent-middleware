import type { Principal } from "./warden/types.js";

export type { Principal };

export type AgentStatus = "ready" | "busy" | "stopped" | "error";
export type RunStatus = "queued" | "running" | "completed" | "failed" | "cancelled";
export type MessageRole = "user" | "assistant";

export interface Agent {
  id: string;
  name: string;
  description: string;
  instructions: string;
  status: AgentStatus;
  workspacePath: string;
  codexThreadId: string | null;
  lastError: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface Message {
  id: string;
  agentId: string;
  runId: string;
  role: MessageRole;
  content: string;
  createdAt: string;
}

export interface RunUsage {
  inputTokens?: number;
  cachedInputTokens?: number;
  outputTokens?: number;
}

export interface AgentRun {
  id: string;
  agentId: string;
  status: RunStatus;
  prompt: string;
  output: string | null;
  error: string | null;
  usage: RunUsage | null;
  startedAt: string | null;
  completedAt: string | null;
  createdAt: string;
  /** Human principal that initiated the run. */
  actorId?: string | undefined;
  /** Warden trace correlating every brokered egress decision for this run. */
  traceId?: string | undefined;
}

export interface Database {
  version: 1;
  agents: Agent[];
  messages: Message[];
  runs: AgentRun[];
}

export interface CreateAgentInput {
  name: string;
  description?: string | undefined;
  instructions?: string | undefined;
}

export interface UpdateAgentInput {
  name?: string | undefined;
  description?: string | undefined;
  instructions?: string | undefined;
}

export interface RunnerResult {
  output: string;
  threadId: string | null;
  usage: RunUsage | null;
}

/**
 * Credentials and network placement handed to the Runtime for exactly one run.
 * Supplied by Warden middleware; absent means "legacy unbrokered execution".
 */
export interface RuntimeCredentials {
  /** Run-scoped capability token injected as ARK_API_KEY. Never the real Ark key. */
  arkApiKey: string;
  /**
   * Container network to attach. Internal (no route off the host), so the
   * dual-homed Warden broker is the only reachable destination.
   */
  network?: string | undefined;
  extraEnv?: Readonly<Record<string, string>> | undefined;
}

export interface RunnerRequest {
  agentId: string;
  workspacePath: string;
  prompt: string;
  threadId: string | null;
  /** Correlates the Runtime execution with the control-plane Run and its trace. */
  runId?: string | undefined;
  /**
   * Assigned when the Run row is created, BEFORE execution, so a Run that fails
   * or is denied still points at the trace holding its denial evidence.
   */
  traceId?: string | undefined;
  /** The human principal who initiated this run, for action attribution. */
  actor?: Principal | undefined;
  credentials?: RuntimeCredentials | undefined;
}

export interface AgentRunner {
  run(request: RunnerRequest): Promise<RunnerResult>;
  cancel(agentId: string): Promise<boolean>;
  isAvailable(): Promise<boolean>;
}
