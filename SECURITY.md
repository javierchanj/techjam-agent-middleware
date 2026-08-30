# Security policy

Volc Agent Launchpad with Warden is a single-user hackathon proof of concept.
Only the latest revision on the default branch is supported. The official
Warden path is `npm run poc` with the disposable container Runtime; development,
Docker Compose and ECS paths run the unbrokered starter baseline unless stated
otherwise.

## Report a vulnerability

Send the repository owner or event organiser the affected revision,
reproduction steps, impact and suggested mitigation. Do not publish credentials,
personal data, raw grants or exploit details in an issue.

## Warden credential boundary

- The real ModelArk provider key is held by the control plane and Warden broker.
- An Agent Runtime receives a short-lived `wgt_` run grant instead of that key.
- Only a token hash is retained internally; public APIs expose an eight-character
  fingerprint, not the raw grant or hash.
- Model and network authority is scoped, metered, revocable and closed when the
  Run finishes.
- Run output, errors and trace attributes are redacted before persistence or UI
  rendering.

Run `npm run warden:secret-proof` during an active Agent turn for screen-safe,
deterministic evidence of this boundary. The proof never displays either
credential.

## Known limitations

- The shared application bearer token is not user identity, RBAC or tenant
  isolation. `x-launchpad-actor` is a mock principal and is spoofable.
- There is no CSRF protection. Keep the local POC on loopback.
- A host administrator with Docker/Podman access can inspect the broker and read
  its provider key. Warden reduces credential exposure; it is not a secrets
  manager.
- A run grant is visible inside its Runtime and through container inspection.
  It is intentionally short-lived, scoped, metered and revocable.
- HTTPS contents on the network plane are opaque. Warden controls destination
  host and port, not the encrypted request contents.
- Runtime containers share an internal bridge. Concurrent sibling Runtimes and
  unrelated host services bound to the bridge gateway remain a residual lateral
  movement risk. Per-run networks or host firewall isolation are future work.
- The model-plane hop inside the private internal bridge is plaintext HTTP.
- Policy-change history is an in-memory bounded audit tail and does not survive
  a broker restart. Completed run traces are archived separately.
- Docker is the supported Warden topology. Colima and Podman remain unverified;
  ECS uses the baseline with Warden disabled.
- Ordinary containers are not hardened multi-tenant sandboxes. Codex may execute
  prompt-triggered commands and edit every file mounted in its Agent workspace.
- The Ark key may be stored in Terraform POC state on the optional baseline ECS
  path.

## Safe use

- Use a dedicated development machine and a scoped, revocable ModelArk key.
- Use a unique `APP_AUTH_TOKEN` for any non-loopback demo and add HTTPS before
  sending it across an untrusted network.
- Never mount unrelated credentials, production data or Volcengine account
  AK/SK into an Agent Runtime.
- Run the default, broker smoke and real-Docker verification suites before a
  demo.
- Stop the POC, remove test resources and revoke temporary keys after the event.
