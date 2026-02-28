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

## 4) Capability ratchet semantics (GitHub encrypted artifact flow)

Current live workflow token payloads are URL-safe base64 JSON objects with this shape:

```json
{
  "version": 1,
  "kind": "state_cap|net_cap",
  "state_id": "state-<run_id>|state-<seed>",
  "ratchet_step": 1,
  "chain_key": "hex-sha256"
}
```

Roles:

- `state_cap`: carries the chain key used for state checkpoint decrypt/encrypt.
- `net_cap`: carries a parallel network capability chain key (ratcheted with the same step cadence).
- `ratchet_step`: monotonic counter for chain progression.

Step `N` execution model:

1. Worker decodes `state_cap_in` and reads `state_cap_in.chain_key`.
2. Worker decrypts prior `state_bundle.tar.enc` with that key.
3. Worker derives next key as:
   - `next_chain_key = sha256(current_chain_key + "::run:<run_id>")`
4. Worker executes and creates next checkpoint.
5. Worker encrypts next bundle with `next_chain_key`.
6. Worker emits `next_tokens.json` with `state_cap_next` / `net_cap_next` and `ratchet_step = prior + 1`.

Compatibility matrix for encrypted bundle restore:

- `state_N` + `key_N`: succeeds.
- `state_N+1` + `key_N`: fails (`bad decrypt`).
- `state_N` + `key_N+1`: fails (`bad decrypt`).

Live evidence (2026-02-28):

- Forward chain success:
  - `docs/artifacts/2026-02-28-live-two-step-chain.json`
- Wrong key with newer state (key 1 + state 2) rejected:
  - `docs/artifacts/2026-02-28-live-negative-key-mismatch.json`
- Wrong key with older state (key 2 + state 1) rejected:
  - `docs/artifacts/2026-02-28-live-negative-reverse-key-mismatch.json`

Security caveat (current implementation):

- Tokens are bearer-style encoded JSON, not signed or KMS-bound.
- Possession of a valid token is sufficient to use that capability.
- Ratchet behavior is verified, but stronger protection still needs:
  - signed capability envelopes,
  - scoped audience/binding checks,
  - external key custody (KMS/HSM) and rotation policy enforcement.

## 5) Determinism invariants

- Canonical JSON serialization for hashed artifacts.
- Hash exactly uploaded bytes.
- Version every schema explicitly.
- Do not mutate immutable node linkage fields after creation.

## 6) Verification minimum checks

1. Proof/public-input validity.
2. Required commit pin equality.
3. `sha256(certificate_bytes) == artifactHash`.
4. Mode-specific required fields and replay identifiers.
