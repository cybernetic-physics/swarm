# popcorn-cli baseline mapping

Status: draft
Date: 2026-02-28

## Why `popcorn-cli` is a good baseline

From local repo `/Users/cuboniks/Projects/kernel_projects/popcorn-cli` and related notes:
- Clean Rust CLI entry with `clap` parser and async execution.
- Clear command modules under `src/cmd/*`.
- Simple config file model in user home (`.popcorn.yaml`).
- Two UX modes: interactive TUI and non-interactive plain output.
- Streaming server result handling via SSE.
- Setup/scaffolding command (`setup`) that bootstraps local workflow files.

Related notes:
- `/Users/cuboniks/Notes/pages/popcorn-cli.md`
- `/Users/cuboniks/Notes/pages/agent_swarm GPU MODE Popcorn KernelBot case study.md`

## Reusable patterns for `swarm`

### Keep
- `clap`-based subcommand tree.
- Modular command handlers (`run`, `state`, `verify`, `backend`).
- `--no-tui`/machine-output mode for scripts and CI.
- Explicit config loader/saver with typed struct.
- Streaming status reporting during long execution episodes.
- Deterministic output artifact parsing/printing.

### Adapt
- Replace submission-centric model with branch-node run model.
- Replace leaderboard/GPU selection with branch + backend + policy selection.
- Replace generic result JSON with cert + bundle + token contracts.
- Replace `X-Popcorn-Cli-Id` identity with `swarm` run/request identifiers and signer identity.

### Add
- Attestation verifier commands.
- Capability-token lifecycle commands (`state_cap`, `net_cap`).
- Backend abstraction supporting local and GitHub now, GitLab later.
- Restore-mode telemetry (`checkpoint` vs `cold_start`) in outputs.

## Case-study architecture mapping

`popcorn-cli` ecosystem pattern (CLI -> control plane -> workflow -> artifact collection) maps directly to:
- `swarm` CLI client.
- `swarm` coordinator/backend adapter.
- GitHub workflow execution episode.
- Deterministic artifact collection and verification.

Main deltas for `swarm`:
- Attestation and trust boundary are core, not optional metadata.
- State and network capabilities must ratchet per node transition.
- Branch lineage and replay semantics are first-class data model concerns.
