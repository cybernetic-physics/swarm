# swarm

Status: planning + M1 local backend scaffold implemented
Last updated: 2026-02-28

`swarm` is the new CLI-first project under `/Users/cuboniks/Projects/agent_swarm/swarm`.

Goal: implement the Phase 0/1 `agent_swarm` launcher as a production-grade CLI that supports attested branching runs, encrypted state continuity, deterministic certificates, and GitHub-first execution. Phase 2+ extends the same contracts to marketplace and GitLab parity.

This planning set was built from:
- Logseq notes in `/Users/cuboniks/Notes/pages` (especially `agent_swarm*`, `popcorn-cli`, `Main TODO`, `Loom client`).
- Local `popcorn-cli` repository patterns (`/Users/cuboniks/Projects/kernel_projects/popcorn-cli`).
- Web research from official docs (GitHub, GitLab, clap, Docker, SQLite).

## Current implementation status

Implemented now:
- Rust workspace with `swarm-cli`, `swarm-core`, `swarm-state`, `swarm-verify`.
- Functional local M1 path:
  - launch/resume/fork with SQLite snapshot transitions,
  - deterministic local tar bundle generation,
  - run status + state inspect,
  - certificate hash/commit verification command.

Not implemented yet:
- M2 GitHub backend dispatch/collect + attested worker execution.
- M3 `net_cap` proxy mode.
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

## First implementation target

Phase 0/1 only:
- GitHub backend only (target for M2).
- Off-chain verifier flow.
- Proxy-first `net_cap` (target for M3).
- Deterministic `certificate.json` + encrypted bundle outputs.
- Cold-start fallback required when checkpoint restore fails.

## Explicitly deferred

- Full marketplace settlement UX.
- Full Mode B economics and transfer semantics.
- GitLab execution backend parity.
- Always-on hosted WebRTC service assumptions.
