# Data contracts

Status: draft
Date: 2026-02-28

## 1) Branch node contract (aligned to Notes)

```json
{
  "schema_version": "agent_swarm-node-v1",
  "node_id": "uuid",
  "parent_node_id": "uuid|null",
  "workspace": {
    "artifact_hash": "sha256:...",
    "artifact_ref": "s3://...|artifact://..."
  },
  "state_db": {
    "state_id": "uuid",
    "snapshot_hash": "sha256:...",
    "snapshot_ref": "s3://...|artifact://...",
    "ratchet_step": 42,
    "engine": { "kind": "sqlite-serialized", "schema_version": "loom-state-v1" }
  },
  "network": {
    "route_mode": "direct|client_exit",
    "token": { "token_ref": "...", "ratchet_step": 42, "expires_at": "RFC3339|null" }
  },
  "attestation": {
    "commit_sha_required": "hex40|null",
    "artifact_hash": "sha256:...|null",
    "proof_ref": "s3://...|null"
  }
}
```

## 2) Certificate contract (Phase 0/1)

```json
{
  "type": "loom-agent-run-v1",
  "job_id": "uuid",
  "request_hash": "sha256(...)",
  "mode": "prompt-run|state-license",
  "parent_state": {
    "state_id": "uuid",
    "bundle_sha256": "...",
    "ratchet_step": 42
  },
  "result": {
    "response_sha256": "...",
    "response_locator": "s3://...|artifact://...",
    "new_state": {
      "state_id": "uuid",
      "bundle_sha256": "...",
      "bundle_manifest_sha256": "..."
    }
  },
  "runtime": {
    "workflow_ref": "owner/repo/.github/workflows/loom-paid-run.yml@<commit>",
    "runner_class": "github-hosted|self-hosted",
    "started_at": "RFC3339",
    "finished_at": "RFC3339"
  },
  "timestamp": "RFC3339"
}
```

## 3) Backend output artifacts

### `result.json`
- run status.
- node transition summary.
- restore mode.
- certificate/artifact refs.
- `bundle_ref` may use `gh-artifact://<gh_run_id>/<artifact_name>` for GitHub-backed encrypted bundles.
- `bundle_sha256` should hash uploaded encrypted bytes (`state_bundle.tar.enc`).

### `next_tokens.json`
- `state_cap_next` envelope ref.
- `net_cap_next` envelope ref.
- ratchet step metadata.
- these capability tokens are required to decrypt/ratchet the next checkpoint in multi-step GitHub flows.

### `bundle_locator_next.json`
- locator + hash metadata for outgoing encrypted bundle.

## 4) Determinism invariants

- Canonical JSON serialization for hashed artifacts.
- Hash exactly uploaded bytes.
- Version every schema explicitly.
- Do not mutate immutable node linkage fields after creation.

## 5) Verification minimum checks

1. Proof/public-input validity.
2. Required commit pin equality.
3. `sha256(certificate_bytes) == artifactHash`.
4. Mode-specific required fields and replay identifiers.
