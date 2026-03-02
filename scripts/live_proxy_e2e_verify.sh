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
RUN_ID="${SWARM_RUN_ID:-live-proxy-e2e-${RUN_SUFFIX}}"
OUT_JSON="${SWARM_E2E_OUT_JSON:-${ROOT}/docs/artifacts/${DATE_UTC}-live-proxy-e2e.json}"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/swarm-live-proxy.XXXXXX")"
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

echo "[1/4] Dispatch proxy mode run: ${RUN_ID}"
DISPATCH_START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
DISPATCH_JSON="${TMP_DIR}/dispatch.json"
COLLECT_JSON="${TMP_DIR}/collect.json"

cargo run -q -p swarm-cli -- --json backend github dispatch \
  --run-id "$RUN_ID" \
  --workflow-ref "$WORKFLOW_REF" \
  --route-mode client-exit \
  --allow-direct-fallback > "$DISPATCH_JSON"

GH_RUN_ID="$(wait_for_run_id "$DISPATCH_START" "")"
echo "[2/4] Watch GitHub run: ${GH_RUN_ID}"
gh run watch "$GH_RUN_ID" -R "$OWNER_REPO" --exit-status

echo "[3/4] Collect artifacts"
cargo run -q -p swarm-cli -- --json backend github collect \
  --run-id "$RUN_ID" \
  --gh-run-id "$GH_RUN_ID" > "$COLLECT_JSON"

VERIFY="$(jq -r '.data.verification_ok' "$COLLECT_JSON")"
ERRORS="$(jq -r '.data.errors | length' "$COLLECT_JSON")"
COMPAT="$(jq -r '.data.compatibility_ok' "$COLLECT_JSON")"
RESTORE="$(jq -r '.data.restore_mode' "$COLLECT_JSON")"
assert_true "$VERIFY" "verification_ok must be true"
assert_zero "$ERRORS" "errors must be empty"
assert_true "$COMPAT" "compatibility_ok must be true"
assert_eq "$RESTORE" "checkpoint" "restore_mode must be checkpoint"

for a in result.json next_tokens.json certificate.json policy.json; do
  jq -e --arg a "$a" '.data.artifact_report.required | index($a)' "$COLLECT_JSON" >/dev/null
  jq -e --arg a "$a" '.data.artifact_report.found | index($a)' "$COLLECT_JSON" >/dev/null
done

RUN_DIR="${ROOT}/.swarm/local/runs/${RUN_ID}"
POLICY_ROUTE_MODE="$(jq -r '.route_mode' "${RUN_DIR}/policy.json")"
assert_eq "$POLICY_ROUTE_MODE" "client_exit" "policy.json route_mode must be client_exit"

BUNDLE="$(jq -r '.bundle_ref' "${RUN_DIR}/result.json")"
STATE_CAP="$(jq -r '.state_cap_next' "${RUN_DIR}/next_tokens.json")"
NET_CAP="$(jq -r '.net_cap_next' "${RUN_DIR}/next_tokens.json")"
RATCHET="$(jq -r '.ratchet_step' "${RUN_DIR}/next_tokens.json")"
STATE_ID="$(jq -r '.state_id' "${RUN_DIR}/result.json")"
ARTIFACT_HASH="$(jq -r '.artifact_hash' "${RUN_DIR}/result.json")"
POLICY_HASH="$(jq -r '.policy.policy_hash' "${RUN_DIR}/certificate.json")"
BUNDLE_SHA="$(jq -r '.bundle_sha256' "${RUN_DIR}/result.json")"
EXPECTED_BUNDLE="gh-artifact://${GH_RUN_ID}/state-bundle-${RUN_ID}"
assert_eq "$BUNDLE" "$EXPECTED_BUNDLE" "bundle_ref must match run artifact locator"

PROXY_EVIDENCE_EXISTS="false"
if [ -f "${RUN_DIR}/proxy_evidence.json" ]; then
  PROXY_EVIDENCE_EXISTS="true"
  PROXY_VALIDATED="$(jq -r '.proxy_validated' "${RUN_DIR}/proxy_evidence.json")"
  PROXY_ROUTE_MODE="$(jq -r '.route_mode' "${RUN_DIR}/proxy_evidence.json")"
  assert_true "$PROXY_VALIDATED" "proxy_evidence.proxy_validated must be true"
  assert_eq "$PROXY_ROUTE_MODE" "client_exit" "proxy_evidence.route_mode must be client_exit"
fi

STATE_CAP_SHA="$(printf '%s' "$STATE_CAP" | shasum -a 256 | awk '{print $1}')"
NET_CAP_SHA="$(printf '%s' "$NET_CAP" | shasum -a 256 | awk '{print $1}')"

echo "[4/4] Write evidence artifact"
mkdir -p "$(dirname "$OUT_JSON")"

jq -n \
  --arg date "$DATE_UTC" \
  --arg executed_at_utc "$NOW_UTC" \
  --arg commit "$COMMIT_SHA" \
  --arg workflow_ref "$WORKFLOW_REF" \
  --arg owner_repo "$OWNER_REPO" \
  --arg run_id "$RUN_ID" \
  --arg gh_run_id "$GH_RUN_ID" \
  --arg bundle "$BUNDLE" \
  --arg expected_bundle "$EXPECTED_BUNDLE" \
  --arg bundle_sha "$BUNDLE_SHA" \
  --arg state_id "$STATE_ID" \
  --arg artifact_hash "$ARTIFACT_HASH" \
  --arg policy_hash "$POLICY_HASH" \
  --arg policy_route_mode "$POLICY_ROUTE_MODE" \
  --arg ratchet "$RATCHET" \
  --arg state_cap_sha "$STATE_CAP_SHA" \
  --arg net_cap_sha "$NET_CAP_SHA" \
  --argjson proxy_evidence_exists "$PROXY_EVIDENCE_EXISTS" \
  --argjson collect_data "$(cat "$COLLECT_JSON" | jq '.data')" \
  '{
    date: $date,
    executed_at_utc: $executed_at_utc,
    commit: $commit,
    workflow_ref: $workflow_ref,
    owner_repo: $owner_repo,
    route_mode: "client_exit",
    run: {
      run_id: $run_id,
      gh_run_id: ($gh_run_id | tonumber),
      url: ("https://github.com/" + $owner_repo + "/actions/runs/" + $gh_run_id),
      bundle_ref: $bundle,
      expected_bundle_ref: $expected_bundle,
      bundle_ref_matches_expected: ($bundle == $expected_bundle),
      bundle_sha256: $bundle_sha,
      state_id: $state_id,
      ratchet_step: ($ratchet | tonumber),
      artifact_hash: $artifact_hash,
      policy_hash: $policy_hash,
      policy_route_mode: $policy_route_mode,
      verification_ok: $collect_data.verification_ok,
      verification_reason: $collect_data.verification_reason,
      compatibility_ok: $collect_data.compatibility_ok,
      compatibility_reason: $collect_data.compatibility_reason,
      errors_count: ($collect_data.errors | length),
      state_cap_next_sha256: $state_cap_sha,
      net_cap_next_sha256: $net_cap_sha,
      proxy_evidence_exists: $proxy_evidence_exists,
      artifact_report: $collect_data.artifact_report
    },
    assertions: {
      verification_ok: $collect_data.verification_ok,
      errors_empty: (($collect_data.errors | length) == 0),
      policy_route_mode_is_client_exit: ($policy_route_mode == "client_exit"),
      bundle_ref_matches_expected: ($bundle == $expected_bundle),
      proxy_evidence_present: $proxy_evidence_exists
    }
  }' > "$OUT_JSON"

echo "E2E proxy mode (client_exit) PASS"
echo "workflow_ref=${WORKFLOW_REF}"
echo "run_id=${RUN_ID} gh_run_id=${GH_RUN_ID}"
echo "policy_route_mode=${POLICY_ROUTE_MODE}"
echo "artifact_record=${OUT_JSON}"
