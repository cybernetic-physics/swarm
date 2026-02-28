# Notes synthesis

Status: draft
Date: 2026-02-28

## Observed facts from Notes

- `agent_swarm` defines a phase split: Phase 0/1 launcher first, Phase 2+ marketplace later.
- Current decision snapshot locks GitHub Actions as the only worker substrate for Phase 0/1.
- `net_cap` direction is proxy mode first, then Tailscale exit-node after MVP.
- `github-zktls` is treated as the ready trust anchor for commit/artifact binding.
- `loom-paid-run.yml` is a strong skeleton but still conditional and needs hardening.
- oauth3 repos are currently reference/conditional and have blocking findings before tight coupling.
- No dedicated Rust Loom client module currently exists in `/Users/cuboniks/Projects/agent_swarm`.
- `Main TODO` marks verifier freeze + schema freeze + local backend + GitHub backend as P0/P1 core path.

Primary source pages:
- `/Users/cuboniks/Notes/pages/agent_swarm.md`
- `/Users/cuboniks/Notes/pages/agent_swarm what to build now.md`
- `/Users/cuboniks/Notes/pages/agent_swarm implementation readiness matrix.md`
- `/Users/cuboniks/Notes/pages/agent_swarm implementation evidence.md`
- `/Users/cuboniks/Notes/pages/Main TODO.md`

## Requirement set for `swarm`

### RQ-001: CLI-first execution
Implement launch/resume/fork/verify as first-class commands with no marketplace dependency.

### RQ-002: Deterministic attestation artifact
Generate deterministic `certificate.json` and bind it to attested artifact hash.

### RQ-003: Commit pin enforcement
Require pinned workflow commit in run spec and verifier path.

### RQ-004: Substrate-aware restore
Support checkpoint restore when compatible; require cold-start fallback semantics.

### RQ-005: Encrypted state continuity
Adopt serialized SQLite snapshot engine with capability ratchets (`state_cap`).

### RQ-006: Explicit egress policy
Treat `net_cap` as separate capability with fail-closed policy for required client-egress runs.

### RQ-007: GitHub-first backend
Implement GitHub execution backend first; keep backend abstraction ready for GitLab parity later.

### RQ-008: Off-chain verifier first
Implement proof/public-input + certificate-hash + schema checks before any on-chain settlement work.

### RQ-009: Strict output contracts
Emit stable machine-readable artifacts (`result.json`, `next_tokens.json`, cert references).

### RQ-010: Security hygiene
Never log raw capability tokens; keep secrets in non-log channels only.

## Non-goals for first ship

- Multi-backend parity (GitHub + GitLab simultaneously).
- Direct dependency on oauth3 runtime components.
- Long-lived hosted runner networking sessions.
- Full dispute/escrow policy implementation.

## Open decisions to carry into M0

- Mode B transfer semantics: lease vs ownership transfer.
- Proof policy: mandatory per run vs challenge window.
- Production substrate posture after GitHub-only phase.
- Exact capability token envelope format and merge semantics.
