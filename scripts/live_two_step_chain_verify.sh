#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

OWNER_REPO="${SWARM_OWNER_REPO:-cybernetic-physics/swarm}"
WORKFLOW_FILE="${SWARM_WORKFLOW_FILE:-swarm-live-run.yml}"
COMMIT_SHA="${SWARM_COMMIT_SHA:-$(git rev-parse HEAD)}"
WORKFLOW_REF="${SWARM_WORKFLOW_REF:-${OWNER_REPO}/.github/workflows/${WORKFLOW_FILE}@${COMMIT_SHA}}"
DATE_UTC="$(date -u +%F)"
NOW_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
RUN_SUFFIX="$(date +%s)"
RUN1_ID="${SWARM_RUN1_ID:-live-auto-two-step1-${RUN_SUFFIX}}"
RUN2_ID="${SWARM_RUN2_ID:-live-auto-two-step2-${RUN_SUFFIX}}"
OUT_JSON="${SWARM_E2E_OUT_JSON:-${ROOT}/docs/artifacts/${DATE_UTC}-live-two-step-collect-verifier-gating.json}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swarm-live-two-step.XXXXXX")"
trap 'rm -rf "${TMP_DIR}"' EXIT

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $1" >&2
    exit 1
  fi
}

for cmd in cargo gh jq git shasum; do
  require_cmd "$cmd"
done

wait_for_run_id() {
  local start_ts="$1"
  local excluded_ids="${2:-}"
  local candidate=""
  local run_ids=""
  local id=""

  for _ in $(seq 1 120); do
    run_ids="$(
      gh run list \
        -R "$OWNER_REPO" \
        --workflow "$WORKFLOW_FILE" \
        --json databaseId,headSha,event,createdAt \
        --limit 80 | jq -r --arg sha "$COMMIT_SHA" --arg start "$start_ts" '
        [.[]
         | select(.event == "workflow_dispatch" and .headSha == $sha and .createdAt >= $start)
        ]
        | sort_by(.createdAt)
        | reverse
        | .[].databaseId
      '
    )"

    candidate=""
    while IFS= read -r id; do
      if [ -z "$id" ]; then
        continue
      fi
      if [[ " ${excluded_ids} " == *" ${id} "* ]]; then
        continue
      fi
      candidate="$id"
      break
    done <<< "$run_ids"

    if [ -n "$candidate" ]; then
      echo "$candidate"
      return 0
    fi
    sleep 2
  done

  echo "ERROR: timed out waiting for workflow run id after ${start_ts}" >&2
  return 1
}

assert_true() {
  local actual="$1"
  local msg="$2"
  if [ "$actual" != "true" ]; then
    echo "ERROR: ${msg} (actual=${actual})" >&2
    exit 1
  fi
}

assert_zero() {
  local actual="$1"
  local msg="$2"
  if [ "$actual" != "0" ]; then
    echo "ERROR: ${msg} (actual=${actual})" >&2
    exit 1
  fi
}

assert_eq() {
  local lhs="$1"
  local rhs="$2"
  local msg="$3"
  if [ "$lhs" != "$rhs" ]; then
    echo "ERROR: ${msg} (lhs=${lhs}, rhs=${rhs})" >&2
    exit 1
  fi
}

echo "[1/6] Dispatch step1: ${RUN1_ID}"
STEP1_START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
DISPATCH1_JSON="${TMP_DIR}/dispatch1.json"
COLLECT1_JSON="${TMP_DIR}/collect1.json"

cargo run -q -p swarm-cli -- --json backend github dispatch \
  --run-id "$RUN1_ID" \
  --workflow-ref "$WORKFLOW_REF" > "$DISPATCH1_JSON"

GH1_RUN_ID="$(wait_for_run_id "$STEP1_START" "")"
echo "[2/6] Watch step1 GitHub run: ${GH1_RUN_ID}"
gh run watch "$GH1_RUN_ID" -R "$OWNER_REPO" --exit-status

echo "[3/6] Collect step1"
cargo run -q -p swarm-cli -- --json backend github collect \
  --run-id "$RUN1_ID" \
  --gh-run-id "$GH1_RUN_ID" > "$COLLECT1_JSON"

VERIFY1="$(jq -r '.data.verification_ok' "$COLLECT1_JSON")"
ERRORS1="$(jq -r '.data.errors | length' "$COLLECT1_JSON")"
COMPAT1="$(jq -r '.data.compatibility_ok' "$COLLECT1_JSON")"
RESTORE1="$(jq -r '.data.restore_mode' "$COLLECT1_JSON")"
assert_true "$VERIFY1" "step1 verification_ok must be true"
assert_zero "$ERRORS1" "step1 errors must be empty"
assert_true "$COMPAT1" "step1 compatibility_ok must be true"
assert_eq "$RESTORE1" "checkpoint" "step1 restore_mode must be checkpoint"

for a in result.json next_tokens.json certificate.json policy.json; do
  jq -e --arg a "$a" '.data.artifact_report.required | index($a)' "$COLLECT1_JSON" >/dev/null
  jq -e --arg a "$a" '.data.artifact_report.found | index($a)' "$COLLECT1_JSON" >/dev/null
done

RUN1_DIR="${ROOT}/.swarm/local/runs/${RUN1_ID}"
BUNDLE1="$(jq -r '.bundle_ref' "${RUN1_DIR}/result.json")"
STATE_CAP1="$(jq -r '.state_cap_next' "${RUN1_DIR}/next_tokens.json")"
NET_CAP1="$(jq -r '.net_cap_next' "${RUN1_DIR}/next_tokens.json")"
RATCHET1="$(jq -r '.ratchet_step' "${RUN1_DIR}/next_tokens.json")"
STATE_ID1="$(jq -r '.state_id' "${RUN1_DIR}/result.json")"
ARTIFACT_HASH1="$(jq -r '.artifact_hash' "${RUN1_DIR}/result.json")"
POLICY_HASH1="$(jq -r '.policy.policy_hash' "${RUN1_DIR}/certificate.json")"
BUNDLE_SHA1="$(jq -r '.bundle_sha256' "${RUN1_DIR}/result.json")"
EXPECTED_BUNDLE1="gh-artifact://${GH1_RUN_ID}/state-bundle-${RUN1_ID}"
assert_eq "$BUNDLE1" "$EXPECTED_BUNDLE1" "step1 bundle_ref must match run artifact locator"

STATE_CAP1_SHA="$(printf '%s' "$STATE_CAP1" | shasum -a 256 | awk '{print $1}')"
NET_CAP1_SHA="$(printf '%s' "$NET_CAP1" | shasum -a 256 | awk '{print $1}')"

echo "[4/6] Dispatch step2 chained from step1 outputs: ${RUN2_ID}"
STEP2_START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
DISPATCH2_JSON="${TMP_DIR}/dispatch2.json"
COLLECT2_JSON="${TMP_DIR}/collect2.json"

SWARM_CHECKPOINT_IN="$BUNDLE1" \
SWARM_STATE_CAP_IN="$STATE_CAP1" \
SWARM_NET_CAP_IN="$NET_CAP1" \
  cargo run -q -p swarm-cli -- --json backend github dispatch \
    --run-id "$RUN2_ID" \
    --workflow-ref "$WORKFLOW_REF" > "$DISPATCH2_JSON"

GH2_RUN_ID="$(wait_for_run_id "$STEP2_START" "$GH1_RUN_ID")"
echo "[5/6] Watch step2 GitHub run: ${GH2_RUN_ID}"
gh run watch "$GH2_RUN_ID" -R "$OWNER_REPO" --exit-status

echo "[6/6] Collect step2"
cargo run -q -p swarm-cli -- --json backend github collect \
  --run-id "$RUN2_ID" \
  --gh-run-id "$GH2_RUN_ID" > "$COLLECT2_JSON"

VERIFY2="$(jq -r '.data.verification_ok' "$COLLECT2_JSON")"
ERRORS2="$(jq -r '.data.errors | length' "$COLLECT2_JSON")"
COMPAT2="$(jq -r '.data.compatibility_ok' "$COLLECT2_JSON")"
RESTORE2="$(jq -r '.data.restore_mode' "$COLLECT2_JSON")"
assert_true "$VERIFY2" "step2 verification_ok must be true"
assert_zero "$ERRORS2" "step2 errors must be empty"
assert_true "$COMPAT2" "step2 compatibility_ok must be true"
assert_eq "$RESTORE2" "checkpoint" "step2 restore_mode must be checkpoint"

for a in result.json next_tokens.json certificate.json policy.json; do
  jq -e --arg a "$a" '.data.artifact_report.required | index($a)' "$COLLECT2_JSON" >/dev/null
  jq -e --arg a "$a" '.data.artifact_report.found | index($a)' "$COLLECT2_JSON" >/dev/null
done

RUN2_DIR="${ROOT}/.swarm/local/runs/${RUN2_ID}"
BUNDLE2="$(jq -r '.bundle_ref' "${RUN2_DIR}/result.json")"
STATE_CAP2="$(jq -r '.state_cap_next' "${RUN2_DIR}/next_tokens.json")"
NET_CAP2="$(jq -r '.net_cap_next' "${RUN2_DIR}/next_tokens.json")"
RATCHET2="$(jq -r '.ratchet_step' "${RUN2_DIR}/next_tokens.json")"
STATE_ID2="$(jq -r '.state_id' "${RUN2_DIR}/result.json")"
ARTIFACT_HASH2="$(jq -r '.artifact_hash' "${RUN2_DIR}/result.json")"
POLICY_HASH2="$(jq -r '.policy.policy_hash' "${RUN2_DIR}/certificate.json")"
BUNDLE_SHA2="$(jq -r '.bundle_sha256' "${RUN2_DIR}/result.json")"
EXPECTED_BUNDLE2="gh-artifact://${GH2_RUN_ID}/state-bundle-${RUN2_ID}"
assert_eq "$BUNDLE2" "$EXPECTED_BUNDLE2" "step2 bundle_ref must match run artifact locator"

STATE_CAP2_SHA="$(printf '%s' "$STATE_CAP2" | shasum -a 256 | awk '{print $1}')"
NET_CAP2_SHA="$(printf '%s' "$NET_CAP2" | shasum -a 256 | awk '{print $1}')"

EXPECTED_RATCHET2="$((RATCHET1 + 1))"
assert_eq "$RATCHET2" "$EXPECTED_RATCHET2" "ratchet must increment by one from step1 to step2"

mkdir -p "$(dirname "$OUT_JSON")"

jq -n \
  --arg date "$DATE_UTC" \
  --arg executed_at_utc "$NOW_UTC" \
  --arg commit "$COMMIT_SHA" \
  --arg workflow_ref "$WORKFLOW_REF" \
  --arg owner_repo "$OWNER_REPO" \
  --arg run1_id "$RUN1_ID" \
  --arg run2_id "$RUN2_ID" \
  --arg gh1_run_id "$GH1_RUN_ID" \
  --arg gh2_run_id "$GH2_RUN_ID" \
  --arg bundle1 "$BUNDLE1" \
  --arg bundle2 "$BUNDLE2" \
  --arg expected_bundle1 "$EXPECTED_BUNDLE1" \
  --arg expected_bundle2 "$EXPECTED_BUNDLE2" \
  --arg bundle_sha1 "$BUNDLE_SHA1" \
  --arg bundle_sha2 "$BUNDLE_SHA2" \
  --arg state_id1 "$STATE_ID1" \
  --arg state_id2 "$STATE_ID2" \
  --arg artifact_hash1 "$ARTIFACT_HASH1" \
  --arg artifact_hash2 "$ARTIFACT_HASH2" \
  --arg policy_hash1 "$POLICY_HASH1" \
  --arg policy_hash2 "$POLICY_HASH2" \
  --arg state_cap1_sha "$STATE_CAP1_SHA" \
  --arg state_cap2_sha "$STATE_CAP2_SHA" \
  --arg net_cap1_sha "$NET_CAP1_SHA" \
  --arg net_cap2_sha "$NET_CAP2_SHA" \
  --arg ratchet1 "$RATCHET1" \
  --arg ratchet2 "$RATCHET2" \
  --argjson step1_collect "$(cat "$COLLECT1_JSON" | jq '.data')" \
  --argjson step2_collect "$(cat "$COLLECT2_JSON" | jq '.data')" \
  '{
    date: $date,
    executed_at_utc: $executed_at_utc,
    commit: $commit,
    workflow_ref: $workflow_ref,
    owner_repo: $owner_repo,
    run1: {
      run_id: $run1_id,
      gh_run_id: ($gh1_run_id | tonumber),
      url: ("https://github.com/" + $owner_repo + "/actions/runs/" + $gh1_run_id),
      bundle_ref: $bundle1,
      expected_bundle_ref: $expected_bundle1,
      bundle_ref_matches_expected: ($bundle1 == $expected_bundle1),
      bundle_sha256: $bundle_sha1,
      state_id: $state_id1,
      ratchet_step: ($ratchet1 | tonumber),
      artifact_hash: $artifact_hash1,
      policy_hash: $policy_hash1,
      verification_ok: $step1_collect.verification_ok,
      verification_reason: $step1_collect.verification_reason,
      compatibility_ok: $step1_collect.compatibility_ok,
      compatibility_reason: $step1_collect.compatibility_reason,
      errors_count: ($step1_collect.errors | length),
      state_cap_next_sha256: $state_cap1_sha,
      net_cap_next_sha256: $net_cap1_sha,
      artifact_report: $step1_collect.artifact_report
    },
    run2: {
      run_id: $run2_id,
      gh_run_id: ($gh2_run_id | tonumber),
      url: ("https://github.com/" + $owner_repo + "/actions/runs/" + $gh2_run_id),
      bundle_ref: $bundle2,
      expected_bundle_ref: $expected_bundle2,
      bundle_ref_matches_expected: ($bundle2 == $expected_bundle2),
      bundle_sha256: $bundle_sha2,
      state_id: $state_id2,
      ratchet_step: ($ratchet2 | tonumber),
      artifact_hash: $artifact_hash2,
      policy_hash: $policy_hash2,
      verification_ok: $step2_collect.verification_ok,
      verification_reason: $step2_collect.verification_reason,
      compatibility_ok: $step2_collect.compatibility_ok,
      compatibility_reason: $step2_collect.compatibility_reason,
      errors_count: ($step2_collect.errors | length),
      state_cap_next_sha256: $state_cap2_sha,
      net_cap_next_sha256: $net_cap2_sha,
      artifact_report: $step2_collect.artifact_report
    },
    assertions: {
      step1_verification_ok: $step1_collect.verification_ok,
      step2_verification_ok: $step2_collect.verification_ok,
      step1_errors_empty: (($step1_collect.errors | length) == 0),
      step2_errors_empty: (($step2_collect.errors | length) == 0),
      step2_used_step1_chain_inputs: true,
      ratchet_incremented_by_one: (($ratchet2 | tonumber) == (($ratchet1 | tonumber) + 1)),
      bundle_refs_match_run_artifacts: (($bundle1 == $expected_bundle1) and ($bundle2 == $expected_bundle2))
    }
  }' > "$OUT_JSON"

echo "E2E two-step verifier-gated chain PASS"
echo "workflow_ref=${WORKFLOW_REF}"
echo "run1_id=${RUN1_ID} gh_run_id=${GH1_RUN_ID}"
echo "run2_id=${RUN2_ID} gh_run_id=${GH2_RUN_ID}"
echo "artifact_record=${OUT_JSON}"
