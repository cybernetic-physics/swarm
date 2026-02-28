# Roadmap (M0-M5)

Status: active (M0-M3 implemented; M4 Phase 1 implemented; M4 strict/on-chain + M5 pending)
Date: 2026-02-28

## M0: contract freeze

Deliverables:
- Freeze branch node schema v1.
- Freeze certificate schema v1.
- Freeze capability envelope v1 (`state_cap`, `net_cap`).
- Freeze verifier minimum checks.

Done-when:
- schemas versioned in repo docs.
- validation tests pass for all schema fixtures.

## M1: local engine baseline

Deliverables:
- implement `swarm-state` execute/fork loop using serialized SQLite snapshots.
- deterministic bundle build/extract pipeline.
- local command path: `run launch/resume/fork` with local backend.

Done-when:
- replay from any retained node succeeds locally.
- deterministic outputs remain byte-stable across repeated runs.

## M2: GitHub attested backend

Deliverables:
- GitHub dispatch/collect adapter.
- pinned workflow commit enforcement.
- certificate production and collection.
- restore compatibility checks + cold-start fallback path.

Done-when:
- one full end-to-end attested run verifies with CLI verifier.
- fallback behavior is tested and classified in outputs.

## M2b: operations hardening

Deliverables:
- retries, timeout policies, cancellation behavior.
- artifact and error taxonomy.
- improved diagnostics and `doctor` checks.

Done-when:
- integration tests cover timeout/cancel/retry scenarios.

## M3: network capability MVP

Deliverables:
- proxy-first `client_exit` mode.
- route verification evidence in output/certificate fields.
- fail-closed policy path.

Done-when:
- proxy mode works for required routes and blocks on policy mismatch.

## M4: policy capsule hook

Deliverables:
- Phase 1 (implemented): optional `policy.json` hash integration in certificate and verifier optional branch.
- Phase 1 (implemented): strict verifier mode to require policy metadata.
- Phase 2+ (pending): on-chain policy hash enforcement in settlement path.
- Phase 2+ (pending): deterministic runtime policy enforcement hooks.

Done-when:
- Phase 1 done-when:
  - local/GitHub outputs include policy metadata in certificate.
  - verifier validates policy hash when policy metadata is present.
  - strict mode rejects missing policy metadata.
- Full M4 done-when:
  - settlement path enforces policy hash on-chain.

## M5 (Phase 2+): GitLab parity + marketplace scaffolding

Deliverables:
- GitLab backend contract parity.
- marketplace-oriented command placeholders and ledger structures.

Done-when:
- same test fixtures pass for GitHub and GitLab output contracts.

## Immediate next implementation order

1. Add settlement-layer policy hash enforcement path (M4 Phase 2).
2. Continue security hardening with signed capability envelopes + stronger replay resistance beyond fixture-level checks.
3. (Postponed) Add GitLab backend parity scaffolding (M5).
4. (Postponed) Add storage adapter abstraction and S3 manifest-integrity path.

Storage decision note (2026-02-28):
- Continue using GitHub Artifacts as primary state storage for current live workflow chaining.
- Defer S3 adapter work until artifact lifecycle limits or portability requirements become active blockers.

Substrate scope note (2026-02-28):
- Keep active execution scope GitHub-only for current phase.
- Defer GitLab backend activation to explicit Phase 2+ expansion.
