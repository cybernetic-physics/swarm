# Live GitHub E2E Test (single runner)

Status: current  
Date: 2026-02-28

This runbook validates the real `swarm-cli -> GitHub workflow -> artifacts -> collect` path using one GitHub runner.

## Executed result (2026-02-28)

Real end-to-end run was executed against `cybernetic-physics/swarm` on commit:

- `d07ced9b9304081f022bee0ddefd5d65693d89b2`

Observed runs:

- `swarm-proxy-smoke` run `22521214487`: `completed/success`
- `swarm-live-run` run `22521216483`: `completed/success`

Live dispatch/collect validation:

- CLI dispatch succeeded for `run_id=live-1772283564`.
- CLI collect succeeded for `gh_run_id=22521216483`.
- Required artifacts were found and validated:
  - `result.json`
  - `next_tokens.json`
- Local materialization succeeded:
  - `.swarm/local/runs/live-1772283564/result.json`
  - `.swarm/local/runs/live-1772283564/next_tokens.json`
- `swarm run status --run-id live-1772283564` returned `status=succeeded`.

Important implementation note discovered during live testing:

- GitHub workflow-dispatch API rejected SHA refs (`HTTP 422: No ref found`) when used as `ref=<commit_sha>`.
- Fix implemented in commit `d07ced9`: dispatch now uses a branch/tag ref (default `main`, configurable with `SWARM_GH_DISPATCH_REF`) while passing `expected_commit_sha` into workflow inputs and enforcing it in-workflow.

Current known limitation:

- Dispatch does not yet auto-return or auto-resolve `gh_run_id`; collect still requires manually selecting the run id from Actions.

## Preconditions

- In repo root:

```bash
cd /Users/cuboniks/Projects/agent_swarm/swarm
```

- GitHub auth and CLI are ready:

```bash
cargo run -p swarm-cli -- doctor --json
```

- `workflow_pin.valid` should be true, or pass `--workflow-ref` explicitly.

## 1) Pick pinned workflow ref

Use the commit currently on `main`:

```bash
COMMIT_SHA="$(git rev-parse HEAD)"
WORKFLOW_REF="cybernetic-physics/swarm/.github/workflows/swarm-live-run.yml@${COMMIT_SHA}"
```

Dispatch uses branch ref `main` by default for GitHub API compatibility.
If you need another branch/tag, set:

```bash
export SWARM_GH_DISPATCH_REF="<branch-or-tag>"
```

## 2) Dispatch live run

```bash
RUN_ID="live-$(date +%s)"
cargo run -p swarm-cli -- backend github dispatch \
  --run-id "${RUN_ID}" \
  --workflow-ref "${WORKFLOW_REF}" \
  --max-attempts 3 \
  --timeout-secs 45 \
  --json
```

This writes `.swarm/github/runs/${RUN_ID}.json`.

## 3) Resolve GitHub run id

Dispatch currently does not return `gh_run_id`, so get it from Actions:

```bash
gh run list \
  --workflow swarm-live-run \
  --limit 10 \
  --json databaseId,headSha,event,status,conclusion,createdAt,url
```

Pick the `databaseId` for the newest `workflow_dispatch` run with matching `headSha`.

## 4) Collect artifacts

```bash
GH_RUN_ID="<databaseId from step 3>"
cargo run -p swarm-cli -- backend github collect \
  --run-id "${RUN_ID}" \
  --gh-run-id "${GH_RUN_ID}" \
  --workflow-ref "${WORKFLOW_REF}" \
  --max-attempts 3 \
  --timeout-secs 45 \
  --json
```

Expected: success and local files written:

- `.swarm/local/runs/${RUN_ID}/result.json`
- `.swarm/local/runs/${RUN_ID}/next_tokens.json`

## 5) Confirm status path

```bash
cargo run -p swarm-cli -- run status --run-id "${RUN_ID}" --json
```

Expected: resolved status from local collected `result.json`.
