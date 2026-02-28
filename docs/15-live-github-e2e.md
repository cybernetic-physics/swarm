# Live GitHub E2E Test (single runner)

Status: current  
Date: 2026-02-28

This runbook validates the real `swarm-cli -> GitHub workflow -> artifacts -> collect` path using one GitHub runner.

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
