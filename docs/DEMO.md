# Warden live demonstration

This is the reproducible operator guide and three-minute presentation script for
Warden. For implementation details, threat model and limitations, see
[WARDEN.md](WARDEN.md).
For the trust-boundary view, see
[WARDEN_ARCHITECTURE.md](WARDEN_ARCHITECTURE.md).

## What this demonstration proves

The demonstration uses two real Playground Runs. The first completes normally
and contains a controlled egress attempt. The second stays active long enough to
prove the credential boundary and then demonstrates revocation and recovery.

| Acceptance evidence | Live proof |
| --- | --- |
| Frontend-to-Agent path | Select a `Ready` Agent and submit both tasks through the Playground. |
| Real model, file and Runtime actions | Codex invokes `npm start` and `node exfil-demo.js` inside the disposable Runtime. |
| Middleware outside the UI | The broker mints the run grant, authorizes model/network traffic and records correlated spans. |
| Useful behavior preserved | The existing Node project runs and prints a new `task_` identifier. |
| Appropriate abuse and denial | Direct TCP receives `ENETUNREACH`; brokered CONNECT receives HTTP 403 `host_not_allowed`. |
| Secret handling | The live proof shows that the broker holds the provider key while the Runtime holds only a `wgt_` grant. |
| Scoped, revocable delegation | Each Run has a different fingerprint; revocation cancels only the active Run. |
| Recovery and control | The Agent returns to `Ready` and the denial/revocation trace remains available. |

## Before the presentation

### 1. Start the supported topology

Use Docker and the official POC path from the repository root:

```bash
ARK_API_KEY=<your-own-modelark-key> \
ARK_MODEL=ep-<your-endpoint-id> \
ARK_BASE_URL=https://ark.ap-southeast.bytepluses.com/api/v3 \
npm run poc
```

Use the base URL that matches the account which issued the key. Never commit the
key, paste it into the Playground, or show the startup terminal during the demo.

Open <http://localhost:3000>. The Warden rail should show a broker address rather
than “The egress broker is off.”

### 2. Create one clean demo Agent

From the frontend, create an Agent named `Warden Demo Agent` and wait for it to
show `Ready`. Use this Agent for preparation and the live demo; each Agent has a
different persistent workspace.

Select **Node development** and submit this one-time preparation task:

```text
Respond in English only.

In /workspace, create a minimal Node.js project that imports nanoid and prints
task_ followed by a random ID. Initialize package.json, install nanoid, set
type to module, add start as node index.js, create index.js, and run npm start.
Report the files created and the final output.
```

This deliberately happens before the timed demo. It proves that an allowed npm
destination works and leaves a small persisted project for the live Run.

### 3. Install the deterministic abuse fixture

In a second terminal at the repository root, run:

```bash
npm run warden:demo:prepare -- --agent "Warden Demo Agent"
```

If exactly one Agent exists, the `--agent` argument may be omitted. Set
`APP_AUTH_TOKEN` in this terminal when local API authentication is enabled.

The command copies the repository-controlled `demo/exfil-demo.js` fixture into
that Agent's persistent workspace. It does not copy the repository or expose a
credential. The fixture attempts both direct TCP and brokered CONNECT to the
undelegated test destination `1.1.1.1:443`.

It also verifies the Node project from step 2 by installing its dependencies and
running `npm start`, and accepts the project the Agent wrote as long as it
prints a `task_` identifier. If the workspace is empty it writes an equivalent
project instead. An unrelated existing project is refused rather than
overwritten; rerun with `--force` only if you intend to replace it.

### 4. Preflight without changing the workspace

Start a new Playground Run with:

```text
Respond in English only.

Without installing packages or modifying files, confirm that package.json,
package-lock.json, index.js and exfil-demo.js exist, then run npm start.
Report only whether the files exist and whether npm start prints a task_ ID.
```

Do not continue until this succeeds. Then make sure the Agent is `Ready`, keep
the Node development profile selected, and have the architecture diagram and a
green GitHub Actions page open in separate tabs.

## Timed demonstration

### 0:00–0:20 — Explain the boundary change

Show the selected Agent and Warden rail.

> The starter kit already provides React, Fastify, persistent workspaces,
> Codex execution and disposable Runtime containers. However, the original
> Runtime received the real ModelArk key and a routable Docker bridge. Warden
> changes that boundary without replacing the platform: the provider key stays
> in a trusted broker, while every Run receives only a short-lived, scoped and
> revocable grant.

### 0:20–0:40 — Show least-privilege policy

Select **Model only**, enter `registry.npmjs.org` in **Would this be allowed?**,
and click **Check**.

> Under Model only, npm is denied because the grant has no network-plane
> capability.

Select **Node development**, check the same hostname again, and leave that
profile selected.

> Node development adds npm and GitHub because this task needs them. The dry-run
> uses the same policy decision function as enforcement, but it does not mint a
> grant or open a connection. The selected profile applies to the next Run.

### 0:40–0:50 — Start Run 1

Paste this exact task into the Playground:

```text
Respond in English only.

Without modifying files or installing packages, execute exactly these commands
in order:

1. Run npm start.
2. Run node exfil-demo.js unchanged.

Report using exactly these headings:

NORMAL EXECUTION
- State whether npm start succeeded and include the generated task ID.

CONTAINMENT RESULTS
- State the direct TCP result.
- State the brokered CONNECT result and exact Warden policy code.
- If CONNECT returns HTTP 403, explicitly state that Warden denied it.

Do not inspect unrelated files. Do not claim Warden denied nothing if CONNECT
received HTTP 403.
```

### 0:50–1:20 — Explain the active Run

Point to the grant card and trace while the task is executing.

> This request travelled through the real frontend, Fastify API, AgentService,
> disposable Codex Runtime and Warden broker. Warden minted authority for this
> Run only. The rail exposes its fingerprint, expiry, model-call budget and
> token usage. “Provider key in Runtime: no” is the key boundary: the Runtime
> contains a temporary `wgt_` grant, and the trusted broker substitutes the real
> key only for approved model calls.

### 1:20–1:45 — Show success and containment

Show the final Agent response and expand the denied network span.

> First, `npm start` succeeds and produces a new `task_` identifier. Agent
> execution and persistent dependencies still work; Warden is not securing the
> system by disabling functionality.

> Next is the controlled abuse case. The fixture represents compromised or
> misdirected Agent code attempting to reach `1.1.1.1:443`, which was never
> delegated. Direct TCP receives `ENETUNREACH` because the Runtime has no direct
> Internet route. The attempted broker tunnel receives HTTP 403 with
> `host_not_allowed`. The dangerous action fails at two layers, and Warden
> preserves an explainable, correlated policy decision.

Run 1 should finish normally. A red child span means enforcement succeeded; it
does not mean the platform failed.

### 1:45–1:55 — Start Run 2

Paste this exact task:

```text
Respond in English only.

Run this command and wait for it to finish:

node -e "setTimeout(() => console.log('revocation-window-complete'), 120000)"

Do not inspect or print environment variables. Do not modify files.
```

When the new grant becomes active, point out its different fingerprint.

> This is a separate Run, so it receives a separate grant. Authority belongs to
> a Run, not permanently to the Agent.

### 1:55–2:15 — Prove secret handling

While Run 2 is active, switch to the second terminal and run:

```bash
npm run warden:secret-proof
```

Show the PASS results without scrolling to or revealing the startup command.

> Blocking a host alone does not prove that the credential is safe. This script
> checks the live container boundary. It confirms that the broker holds the
> provider credential, the Runtime holds only its run-scoped `wgt_` grant, and
> neither raw value appears in Runtime arguments, public grants, messages, Runs
> or traces. It deliberately prints only PASS or FAIL evidence.

### 2:15–2:35 — Revoke and recover

Return to the browser and click **Revoke access** while Run 2 is still active.
Point to `grant.revoked`, `grant.closed` and the Agent returning to `Ready`.

> Warden invalidates this exact grant, closes active broker access and cancels
> the matching Runtime. This is the recovery case: the Run cannot continue, the
> Agent becomes usable again, and the evidence remains available afterward.

### 2:35–2:50 — Show the architecture

Open [WARDEN_ARCHITECTURE.md](WARDEN_ARCHITECTURE.md).

> The disposable Runtime is treated as untrusted: it has no provider key and no
> direct Internet route. Approved model and network access crosses the broker,
> where Warden enforces grant validity, exact destinations, model paths,
> budgets, expiry and revocation. Redacted decisions return to the Warden rail
> as correlated evidence.

### 2:50–3:00 — Close with independent verification

Show the green GitHub Actions workflow.

> The repository verifies type checking, builds, unit tests, real Docker
> isolation and complete-history secret scanning. Before Warden, the Runtime had
> ambient credential and network authority. With Warden, each Run receives
> access that is scoped, brokered, observable and revocable.

## Expected evidence checklist

Before presenting, rehearse until all of these are visible:

- Agent starts at `Ready` and returns to `Ready` after revocation.
- Model only denies `registry.npmjs.org`; Node development allows it.
- Run 1 has a grant fingerprint and `Provider key in Runtime: no`.
- `npm start` prints a fresh `task_` identifier.
- Direct TCP to `1.1.1.1:443` fails with `ENETUNREACH`.
- Brokered CONNECT is HTTP 403 with `host_not_allowed`.
- The matching trace contains model, network, denial and grant lifecycle spans.
- `npm run warden:secret-proof` prints every PASS line without a raw secret.
- Run 2 has a different fingerprint from Run 1.
- Revocation produces `grant.revoked` and `grant.closed`, cancels the Run and
  returns the Agent to `Ready`.
- GitHub Actions is green.

## Troubleshooting

### “The egress broker is off”

The server was started through a baseline path. Stop it and use `npm run poc`
with Docker. Do not use `npm run dev` or `docker compose up` for the Warden demo.
If port 3000 is occupied, identify the old listener with
`lsof -nP -iTCP:3000 -sTCP:LISTEN`, stop that exact process, and start again.

### `package.json` or `exfil-demo.js` is missing

The task is running in a different Agent workspace, or preparation was skipped.
Select the intended Agent, run the one-time Node project task, then execute
`npm run warden:demo:prepare -- --agent "Warden Demo Agent"` again.

### npm is denied with `plane_not_allowed`

The Run was minted from Model only. Select Node development and start a new Run.
Changing a profile never widens an already-issued grant.

### The Agent replies in another language

Start a new session and retain `Respond in English only.` as the first line of
each prompt. This is a model-output issue, not a Warden policy result.

### The run shows denied steps

That is expected for `exfil-demo.js`. Read the child span: `host_not_allowed`
means the broker rejected an undelegated destination before opening a tunnel.
The deliberate revocation Run is expected to end as denied/cancelled.

### Secret proof cannot find an active Runtime

Run the proof only after Run 2 has minted its grant and before clicking Revoke.
The 120-second wait provides the inspection window.

## Deliberately not demonstrated live

The three-minute scenario does not edit budgets or attempt token exhaustion.
Call and wall-clock budgets are hard controls; the token limit is a documented
soft cap enforced on the next call. Their deterministic tests remain part of
`npm run check` and the Docker suite, while the live demo focuses on the clearest
end-to-end security boundary: scoped access, containment, secret isolation,
correlated evidence, revocation and recovery.
