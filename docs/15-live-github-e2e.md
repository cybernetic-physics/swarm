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

Current storage mode (workflow `swarm-live-run.yml`):

- Outgoing state bundle is encrypted before upload as `state_bundle.tar.enc`.
- Artifact locator returned to CLI is `gh-artifact://<gh_run_id>/state-bundle-<run_id>`.
- Multi-step resume inputs are passed by CLI via env overrides:
  - `SWARM_CHECKPOINT_IN`
  - `SWARM_STATE_CAP_IN`
  - `SWARM_NET_CAP_IN`
- Intermediate chain-key files are kept in non-uploaded runtime workspace paths (not under artifact upload roots).

## Two-step chain validation (2026-02-28)

A live two-step chain was executed on commit:

- `84d0540d5e095ec463f7961195ce8b290355d39f`

Step 1:

- `run_id`: `live-chain1-1772284401`
- GitHub run: `22521431039`
- URL: `https://github.com/cybernetic-physics/swarm/actions/runs/22521431039`
- Collect result: success, `result.json` + `next_tokens.json` present.
- Produced checkpoint locator:
  - `gh-artifact://22521431039/state-bundle-live-chain1-1772284401`

Step 2 (chained inputs from step 1):

- `run_id`: `live-chain2-1772284431`
- GitHub run: `22521438644`
- URL: `https://github.com/cybernetic-physics/swarm/actions/runs/22521438644`
- Dispatch used:
  - `SWARM_CHECKPOINT_IN=<step1 result.json bundle_ref>`
  - `SWARM_STATE_CAP_IN=<step1 next_tokens.json state_cap_next>`
  - `SWARM_NET_CAP_IN=<step1 next_tokens.json net_cap_next>`
- Collect result: success, `result.json` + `next_tokens.json` present.

Validated outcomes:

- `run1.bundle_ref` matched expected artifact locator for run `22521431039`.
- `run2.bundle_ref` matched expected artifact locator for run `22521438644`.
- `ratchet_step` incremented from `1` (step 1) to `2` (step 2).
- End-to-end chain assertions all passed.

Machine-readable test record:

- `docs/artifacts/2026-02-28-live-two-step-chain.json`

## Two-step chain with strict policy verification (2026-02-28)

A live two-step chain was re-run after M4 Phase 1 integration on commit:

- `918e3a08ddf514c28db73543a1e79374c6643bda`

Workflow ref under test:

- `cybernetic-physics/swarm/.github/workflows/swarm-live-run.yml@918e3a08ddf514c28db73543a1e79374c6643bda`

Step 1:

- `run_id`: `live-m4-policy-step1-1772288317`
- GitHub run: `22522452249`
- URL: `https://github.com/cybernetic-physics/swarm/actions/runs/22522452249`
- Collect result: success, `result.json` + `next_tokens.json` present.
- Strict verifier check:
  - `swarm verify cert --policy-file <policy.json> --require-policy`
  - Result: pass

Step 2 (chained from step 1 outputs):

- `run_id`: `live-m4-policy-step2-1772288427`
- GitHub run: `22522481452`
- URL: `https://github.com/cybernetic-physics/swarm/actions/runs/22522481452`
- Dispatch inputs:
  - `checkpoint_in=<step1 result bundle_ref>`
  - `state_cap_in=<step1 next_tokens state_cap_next>`
  - `net_cap_in=<step1 next_tokens net_cap_next>`
- Collect result: success, `result.json` + `next_tokens.json` present.
- Strict verifier check:
  - `swarm verify cert --policy-file <policy.json> --require-policy`
  - Result: pass

Validated outcomes:

- both strict policy verification checks passed.
- step 2 consumed the step 1 checkpoint chain.
- ratchet advanced from `1` to `2`.

Machine-readable test record:

- `docs/artifacts/2026-02-28-live-m4-policy-two-step-chain.json`

## Negative test: wrong key for newer state (2026-02-28)

Purpose:

- Verify fail-closed behavior when using step-1 capability key material to restore step-2 encrypted checkpoint state.

Executed mismatch input:

- `checkpoint_in`: `gh-artifact://22521438644/state-bundle-live-chain2-1772284431` (from step 2)
- `state_cap_in`: from step 1 (`state_cap_next`)
- `net_cap_in`: from step 1 (`net_cap_next`)

Observed run:

- `run_id`: `live-neg-mismatch-1772284612`
- GitHub run: `22521485655`
- URL: `https://github.com/cybernetic-physics/swarm/actions/runs/22521485655`
- Workflow result: `completed/failure`
- Failure step: `Restore encrypted prior bundle (optional)`
- Failure marker in logs: `openssl ... bad decrypt`

CLI collect behavior:

- `swarm backend github collect` exited with code `4`.
- Error code: `GH_COLLECT_FAILED`.
- Reason: no valid artifacts to download (expected because workflow aborted before artifact emission).

Conclusion:

- Wrong key cannot decrypt newer encrypted state.
- Ratchet enforcement is effective for this path.

Machine-readable test record:

- `docs/artifacts/2026-02-28-live-negative-key-mismatch.json`

## Negative test: wrong newer key for older state (2026-02-28)

Purpose:

- Verify fail-closed behavior in the reverse direction: using step-2 capability key material to restore step-1 encrypted checkpoint state.

Executed mismatch input:

- `checkpoint_in`: `gh-artifact://22521431039/state-bundle-live-chain1-1772284401` (from step 1)
- `state_cap_in`: from step 2 (`state_cap_next`)
- `net_cap_in`: from step 2 (`net_cap_next`)

Observed run:

- `run_id`: `live-neg-reverse-1772284736`
- GitHub run: `22521516075`
- URL: `https://github.com/cybernetic-physics/swarm/actions/runs/22521516075`
- Workflow result: `completed/failure`
- Failure step: `Restore encrypted prior bundle (optional)`
- Failure marker in logs: `openssl ... bad decrypt`

CLI collect behavior:

- `swarm backend github collect` exited with code `4`.
- Error code: `GH_COLLECT_FAILED`.
- Reason: no valid artifacts to download (workflow aborted before artifact emission).

Conclusion:

- Newer key cannot decrypt older encrypted state in this ratchet chain.
- Both mismatch directions are now verified as fail-closed.

Machine-readable test record:

- `docs/artifacts/2026-02-28-live-negative-reverse-key-mismatch.json`

## Direct Q/A verdict (2026-02-28)

Question:

- Does it work the other way: can key 2 open state 1?

Answer:

- No, that also fails.

Live test details:

- Input used:
  - `checkpoint_in = gh-artifact://22521431039/state-bundle-live-chain1-1772284401` (state 1 bundle)
  - `state_cap_in = step 2 state_cap_next` (key 2)
  - `net_cap_in = step 2 net_cap_next`
- Run:
  - `run_id = live-neg-reverse-1772284736`
  - GitHub run `22521516075`
- Result:
  - Workflow `completed/failure`
  - Failed at `Restore encrypted prior bundle (optional)`
  - Log marker: `openssl ... bad decrypt`
  - `swarm backend github collect` failed with `GH_COLLECT_FAILED` (no artifacts)

Ratchet conclusion:

- `key 1 + state 2`: fails
- `key 2 + state 1`: fails
- This is the expected ratchet behavior.

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

For encrypted continuity, extract:

```bash
CHECKPOINT_IN="$(jq -r '.bundle_ref' ".swarm/local/runs/${RUN_ID}/result.json")"
STATE_CAP_IN="$(jq -r '.state_cap_next' ".swarm/local/runs/${RUN_ID}/next_tokens.json")"
NET_CAP_IN="$(jq -r '.net_cap_next' ".swarm/local/runs/${RUN_ID}/next_tokens.json")"
```

and use these inputs for the next dispatch.

## 5) Confirm status path

```bash
cargo run -p swarm-cli -- run status --run-id "${RUN_ID}" --json
```

Expected: resolved status from local collected `result.json`.
