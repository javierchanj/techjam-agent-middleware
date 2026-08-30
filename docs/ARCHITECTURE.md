# Architecture

> **This document describes the starter-kit baseline.** With Warden enabled —
> which is the default under `npm run poc` — the Runtime no longer holds the
> provider credential and no longer has direct egress. See
> [WARDEN.md](WARDEN.md) for the brokered architecture, and the diagram below
> for how the two relate.

Volc Agent Launchpad is a single-node control plane for hackathon use.

## Baseline vs Warden-enabled

```mermaid
flowchart LR
    subgraph baseline["Baseline (WARDEN_ENABLED=false)"]
        C1["Runtime container<br/>holds real ARK_API_KEY<br/>--network bridge"] --> A1["Ark / ModelArk"]
        C1 -.->|"unrestricted"| Net1["anywhere on the internet"]
    end
    subgraph warden["Warden enabled (npm run poc)"]
        C2["Runtime container<br/>holds wgt_ grant only<br/>--network internal"] --> B["Warden broker<br/>policy · metering · trace"]
        B --> A2["Ark / ModelArk<br/>(real key injected here)"]
        B -.->|"allowlisted only"| Net2["named destinations"]
    end
```

The control plane, `AgentService`, workspaces and the JSON store are identical
in both. Warden is a decorator around `AgentRunner`, so nothing below changes
shape — only what the Runtime is permitted to reach.


```mermaid
flowchart LR
    UI["React Web UI"] --> API["Fastify API"]
    API --> Service["AgentService"]
    Service --> Store["JSON store"]
    Service --> Workspace["Agent workspace"]
    Service --> Runner{"AgentRunner"}
    Runner -->|Local POC| Container["Disposable Runtime container"]
    Runner -->|ECS| Process["Codex child process"]
    Container --> Ark["Volcengine Ark"]
    Process --> Ark
```

## Components

### Web UI

Lists Agents, manages lifecycle actions, submits prompts, and polls asynchronous
Runs. It never receives the Ark API key.

### Fastify API

Validates requests, protects remote demos with a shared bearer token, and
serves the compiled Web UI. The token is not user identity or authorization.

### AgentService

Coordinates lifecycle state, persistence, workspaces, and Runs. One Agent can
have only one active Run.

```text
ready -> busy -> ready
  |       |
  v       v
stopped  error
```

Interrupted Runs become `cancelled` after a restart.

### Storage

```text
data/launchpad.json       Agent, message, and Run metadata
workspaces/AgentID/       Agent-created files
workspaces/.deleted/      Archived deleted workspaces
codex-home/               Codex configuration and sessions
```

`JsonStore` serializes writes and atomically replaces one JSON file. It supports
one process only.

### Runtime providers

- `CodexRunner` runs Codex inside the application container for ECS.
- `ContainerCodexRunner` starts one disposable Docker, Colima, or Podman
  container for every local turn.

Both providers use argv-only process execution, bound output and time, resume
the stored Codex thread, and escalate termination after a grace period.

## Deployment profiles

| Profile | Control plane | Agent execution |
| --- | --- | --- |
| Local POC | Host Node.js | Disposable local container |
| ECS | Application container | Codex process in the same container |
| Local development | Host Node.js | Host Codex process |

## Extension seams

| Track | Primary seam | Expected change |
| --- | --- | --- |
| Glass Box | `AgentRunner`, `AgentRun` | Emit and display correlated execution events. |
| Bouncer | API routes, Agent ownership | Add identity and server-side authorization. |
| Kill Switch | `AgentRunner` | Add threat-specific policy or a stronger sandbox. |

The current container or ECS instance is the POC trust boundary. Ordinary
containers are not hardened multi-tenant isolation.
