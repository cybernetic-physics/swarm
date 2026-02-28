# M2 quickstart (GitHub backend)

Status: current (M2 + M2b)
Date: 2026-02-28

For a tested live path (single GitHub runner) with concrete run IDs and findings, see:
- `docs/15-live-github-e2e.md`

This quickstart covers the implemented M2 GitHub adapter path:
- pinned workflow ref parsing and enforcement,
- workflow dispatch via GitHub CLI (`gh api`),
- run ledger tracking under `.swarm/github/runs`,
- collection workflow via `gh run download`,
- restore-mode compatibility policy checks (`checkpoint` vs `cold_start`).
and M2b hardening:
- retry/timeout policy flags,
- artifact schema guards,
- cancel behavior and run status updates.

Run from:

```bash
cd /Users/cuboniks/Projects/agent_swarm/swarm
```

## Prerequisites

- GitHub CLI installed and authenticated:

```bash
gh auth status
```

- A workflow reference pinned to an immutable commit:

```text
owner/repo/.github/workflows/loom-paid-run.yml@<40-hex-commit>
```

## 1) Dispatch (dry run first)

```bash
cargo run -p swarm-cli -- run launch \
  --backend github \
  --node root \
  --run-id m2-github-launch \
  --workflow-ref owner/repo/.github/workflows/loom-paid-run.yml@1234567890abcdef1234567890abcdef12345678 \
  --allow-cold-start \
  --dry-run \
  --json
```

Dry-run output includes `command_preview` and writes:

```text
.swarm/github/runs/m2-github-launch.json
```

## 2) Dispatch (live)

Remove `--dry-run` to perform real dispatch:

```bash
cargo run -p swarm-cli -- backend github dispatch \
  --run-id m2-github-launch \
  --workflow-ref owner/repo/.github/workflows/loom-paid-run.yml@1234567890abcdef1234567890abcdef12345678 \
  --allow-cold-start \
  --max-attempts 3 \
  --timeout-secs 45 \
  --json
```

## 3) Collect artifacts for a known GitHub run id

```bash
cargo run -p swarm-cli -- backend github collect \
  --run-id m2-github-launch \
  --gh-run-id <GH_RUN_ID> \
  --workflow-ref owner/repo/.github/workflows/loom-paid-run.yml@1234567890abcdef1234567890abcdef12345678 \
  --max-attempts 3 \
  --timeout-secs 45 \
  --json
```

Collection downloads artifacts and looks for:
- `result.json`
- `next_tokens.json`

When found, it copies them to local contract paths:

```text
.swarm/local/runs/<run_id>/result.json
.swarm/local/runs/<run_id>/next_tokens.json
```

## 4) Status and logs

```bash
cargo run -p swarm-cli -- run status --run-id m2-github-launch --json
cargo run -p swarm-cli -- run logs --run-id m2-github-launch --json
```

## Compatibility policy behavior

Dispatch records fallback policy in ledger:
- `allow_cold_start` when `--allow-cold-start` is set.
- `fail_closed` otherwise.

During collect:
- if `result.json` reports `restore_mode = cold_start` and policy is `fail_closed`, compatibility check fails.
- if required artifacts are missing or schema-invalid, collect fails with typed artifact errors.

## 5) Cancel a GitHub run

```bash
cargo run -p swarm-cli -- run cancel \
  --run-id m2-github-launch \
  --gh-run-id <GH_RUN_ID> \
  --max-attempts 3 \
  --timeout-secs 30 \
  --json
```

Or backend form:

```bash
cargo run -p swarm-cli -- backend github cancel \
  --run-id m2-github-launch \
  --gh-run-id <GH_RUN_ID> \
  --json
```

## Strict pin enforcement

Unpinned refs are rejected:

```bash
cargo run -p swarm-cli -- backend github dispatch \
  --run-id bad-pin \
  --workflow-ref owner/repo/.github/workflows/loom-paid-run.yml@main \
  --dry-run
```

Expected result: error requiring a `40-hex` commit SHA.
