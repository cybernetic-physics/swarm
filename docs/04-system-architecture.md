# System architecture

Status: draft
Date: 2026-02-28

## Plane model

`swarm` follows the same layered model in Notes:

1. Trust plane
- commit pin + attestation + proof/public input verification.
- certificate hash binding.

2. Control plane
- run lifecycle (launch, resume, fork, cancel, collect).
- backend dispatch and timeout governance.

3. Data plane
- encrypted bundles and manifests.
- certificate and proof artifacts.

4. State plane
- serialized SQLite checkpoint engine.
- state capability ratchet.

5. Network plane
- `net_cap` policy resolution and route establishment.
- reconnect semantics per execution episode.

6. Execution plane
- local backend.
- GitHub Actions backend (Phase 0/1).
- GitLab backend (Phase 2+).

## Module map (Rust)

- `swarm-core`: DAG/node lifecycle and orchestration.
- `swarm-crypto`: capability ratchets and envelope crypto.
- `swarm-state`: SQLite snapshot execute/fork engine.
- `swarm-store`: storage backends (artifact/s3/local).
- `swarm-exec`: local + GitHub backend adapters.
- `swarm-net`: `net_cap` policy/session handling.
- `swarm-verify`: certificate/proof/commit checks.
- `swarm-cli`: command surface and UX.

## Primary run flow (Phase 0/1)

1. Resolve run spec + pinned workflow commit.
2. Load node and decrypt input state bundle via `state_cap`.
3. Restore state/workspace/checkpoint (if compatible).
4. Re-establish route policy from `net_cap` when required.
5. Execute agent step.
6. Produce deterministic `certificate.json` and result artifacts.
7. Re-checkpoint and emit encrypted outgoing bundle.
8. Rotate `state_cap` and `net_cap`.
9. Verify and return structured output.

## Fallback semantics

If checkpoint restore fails compatibility checks:
- switch to cold-start path.
- emit `restore_mode = cold_start` in outputs.
- continue only if policy allows this fallback.

## Security boundaries

- Commit pin is mandatory boundary.
- `repoHash` is informational, not primary trust gate.
- Capability tokens are bearer secrets and must not appear in logs.
- Orchestrator/backends are control components, not semantic trust anchors.
