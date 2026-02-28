# M2 quickstart (GitHub backend)

Status: current (M2 + M2b + encrypted artifact continuity)
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
and encrypted state continuity:
- checkpoint locator contract `gh-artifact://<gh_run_id>/<artifact_name>`,
- encrypted state bundle upload (`state_bundle.tar.enc`),
- dispatch input overrides via env vars for `checkpoint_in`, `state_cap_in`, `net_cap_in`.

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

Optional dispatch input overrides:

- `SWARM_CHECKPOINT_IN`: explicit checkpoint locator (overrides automatic empty checkpoint input).
- `SWARM_STATE_CAP_IN`: prior `state_cap_next` token.
- `SWARM_NET_CAP_IN`: prior `net_cap_next` token.

Example:

```bash
export SWARM_CHECKPOINT_IN='gh-artifact://22521216483/state-bundle-live-1772283564'
export SWARM_STATE_CAP_IN='<state_cap_next token>'
export SWARM_NET_CAP_IN='<net_cap_next token>'
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

## 6) Multi-step encrypted checkpoint continuity

After collecting run `RUN_ID_1`, extract checkpoint + capability inputs:

```bash
RUN_ID_1="live-step-1"
CHECKPOINT_IN="$(jq -r '.bundle_ref' ".swarm/local/runs/${RUN_ID_1}/result.json")"
STATE_CAP_IN="$(jq -r '.state_cap_next' ".swarm/local/runs/${RUN_ID_1}/next_tokens.json")"
NET_CAP_IN="$(jq -r '.net_cap_next' ".swarm/local/runs/${RUN_ID_1}/next_tokens.json")"
```

Dispatch step 2 against the same pinned workflow:

```bash
RUN_ID_2="live-step-2"
SWARM_CHECKPOINT_IN="${CHECKPOINT_IN}" \
SWARM_STATE_CAP_IN="${STATE_CAP_IN}" \
SWARM_NET_CAP_IN="${NET_CAP_IN}" \
cargo run -p swarm-cli -- backend github dispatch \
  --run-id "${RUN_ID_2}" \
  --workflow-ref "${WORKFLOW_REF}" \
  --max-attempts 3 \
  --timeout-secs 45 \
  --json
```

Then collect `RUN_ID_2` as usual. Expected behavior:

- Workflow restores `state_bundle.tar.enc` from `CHECKPOINT_IN`.
- It decrypts with the current ratchet key from `state_cap_in`.
- It executes, re-encrypts the new bundle, uploads `state-bundle-${RUN_ID_2}`.
- `result.json.bundle_ref` points to the new artifact locator for next step chaining.
