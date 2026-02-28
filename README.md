# swarm

Status: M0 schema/verifier freeze + M1 local backend + M2 GitHub adapter + M2b hardening + M3 fail-closed net_cap
Last updated: 2026-02-28

`swarm` is the new CLI-first project under `/Users/cuboniks/Projects/agent_swarm/swarm`.

Goal: implement the Phase 0/1 `agent_swarm` launcher as a production-grade CLI that supports attested branching runs, encrypted state continuity, deterministic certificates, and GitHub-first execution. Phase 2+ extends the same contracts to marketplace and GitLab parity.

This planning set was built from:
- Logseq notes in `/Users/cuboniks/Notes/pages` (especially `agent_swarm*`, `popcorn-cli`, `Main TODO`, `Loom client`).
- Local `popcorn-cli` repository patterns (`/Users/cuboniks/Projects/kernel_projects/popcorn-cli`).
- Web research from official docs (GitHub, GitLab, clap, Docker, SQLite).

## Current implementation status

Implemented now:
- Rust workspace with `swarm-cli`, `swarm-core`, `swarm-state`, `swarm-verify`, `swarm-proxy`.
- Functional local M1 path:
  - launch/resume/fork with SQLite snapshot transitions,
  - deterministic local tar bundle generation,
  - deterministic conformance tests for repeated local artifact outputs,
  - run status + state inspect,
  - certificate schema/hash/commit semantics verification command,
  - proof/public-input hash-binding verification command.
- M2 GitHub adapter scaffold:
  - strict pinned workflow ref enforcement (`@<40-hex-commit>`),
  - workflow dispatch path via `gh api`,
  - collection path via `gh run download`,
  - `.swarm/github` run ledger,
  - restore fallback compatibility check on collected result artifacts.
- M2b operations hardening:
  - retry + timeout policy controls for dispatch/collect/cancel,
  - `run cancel` and `backend github cancel` command paths,
  - artifact schema guards for `result.json` and `next_tokens.json`,
  - machine-readable GitHub backend error taxonomy + stable exit code mapping,
  - expanded `doctor` diagnostics for GitHub CLI/auth/workflow pin validity.
- M3 proxy-first fail-closed `net_cap` path:
  - standalone broker/provider/ticket module in `swarm-proxy`,
  - CLI-integrated route-policy preflight with fail-closed enforcement,
  - GitHub Actions end-to-end smoke workflow proving proxy handshake and payload forwarding.
- Capability envelope parser/serializer:
  - shared `state_cap`/`net_cap` envelope encode/decode and validation in `swarm-core`,
  - redacted capability summaries for log-safe CLI output paths.

Not implemented yet:
- run-id to GH run correlation automation after dispatch.
- M5 GitLab parity backend.

## Doc map

- `docs/01-notes-synthesis.md`: extracted requirements and constraints from Notes.
- `docs/02-popcorn-cli-baseline.md`: what to copy, what to change from `popcorn-cli`.
- `docs/03-cli-spec.md`: command tree, config, UX and machine-output contracts.
- `docs/04-system-architecture.md`: core modules and control/data/trust/state/network planes.
- `docs/05-data-contracts.md`: branch/certificate/result/token schemas and invariants.
- `docs/06-backends-and-substrates.md`: local + GitHub + GitLab execution model and restore policy.
- `docs/07-roadmap.md`: M0-M5 milestones and done-when checks.
- `docs/08-risk-register.md`: risk/mitigation tracking table.
- `docs/09-web-research-notes.md`: official references and implications.
- `docs/10-implementation-backlog.md`: prioritized worklist for execution.
- `docs/11-open-questions.md`: decision register for unresolved architecture choices.
- `docs/12-m1-quickstart.md`: commands to use the implemented local backend path.
- `docs/13-m2-github-quickstart.md`: commands to use the implemented GitHub dispatch/collect path.
- `docs/14-m3-proxy-smoke-experiment.md`: experiment report with network diagrams, procedure, and results.
- `docs/15-live-github-e2e.md`: runbook for real dispatch/collect testing with one GitHub runner.

## First implementation target

Phase 0/1 only:
- GitHub backend path.
- Off-chain verifier flow.
- Proxy-first `net_cap` with fail-closed policy.
- Deterministic `certificate.json` + encrypted bundle outputs.
- Cold-start fallback required when checkpoint restore fails.

## Explicitly deferred

- Full marketplace settlement UX.
- Full Mode B economics and transfer semantics.
- GitLab execution backend parity.
- Always-on hosted WebRTC service assumptions.
