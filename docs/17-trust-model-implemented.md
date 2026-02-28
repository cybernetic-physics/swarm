# Trust Model (As Implemented)

This document describes the trust model of `swarm` based on the code as it exists now, not the roadmap.

Snapshot used for this review:
- Date: 2026-02-28
- Git snapshot: working tree after M4 Phase 1 policy-capsule integration
- Scope: current working tree implementation in `swarm-*` crates and active GitHub workflows

## Scope and Security Goal

Primary goal today:
- Let a CLI-driven multi-step run chain state across GitHub runs with capability ratcheting, artifact handoff, and local verification checks including optional policy-hash binding.

What this system currently tries to prevent:
- Running a different workflow commit than the caller pinned.
- Accepting malformed/missing critical artifacts (`result.json`, `next_tokens.json`).
- Silently falling back to cold start when fail-closed restore policy is expected.
- Reusing mismatched ratchet keys to decrypt encrypted prior state.

What this system does not yet cryptographically guarantee end-to-end:
- Signed/attested capability tokens.
- Full Sigstore/DSSE cryptographic attestation verification in `swarm-verify`.
- On-chain settlement enforcement of policy capsule binding.

## System Trust Boundaries (Current)

```text
Operator machine (trusted by operator)
   swarm-cli
   local .swarm state/ledgers/tokens
   optional swarm-proxy provider process

GitHub control plane (trusted platform assumption)
   workflow dispatch API
   Actions runner execution
   artifact storage/download

Workflow job runtime (trusted only as pinned code)
   consumes state_cap/net_cap/checkpoint inputs
   restores/decrypts prior state bundle (optional)
   ratchets caps and emits result/next_tokens
   uploads artifacts

Verifier process (local/offline)
   validates cert hash binding + commit pin + schema/shape checks
```

Key trust split:
- `swarm` trusts GitHub as execution + artifact substrate for the GitHub backend.
- `swarm` adds local checks to reduce accidental/misconfigured trust, but does not yet replace GitHub trust with independent cryptographic attestation verification.

## Implemented Flow and Controls

## 1) Workflow pinning and dispatch constraints

Implemented controls:
- `workflow_ref` must include `@<40-hex-commit>` (`parse_workflow_ref`).
  - File: `swarm-cli/src/github_backend.rs:251`
- CLI dispatch includes:
  - API `ref=<dispatch_ref>` (default `main`, overridable via `SWARM_GH_DISPATCH_REF`)
  - input `expected_commit_sha=<pinned commit>`
  - File: `swarm-cli/src/github_backend.rs:367`, `swarm-cli/src/github_backend.rs:385`, `swarm-cli/src/github_backend.rs:389`, `swarm-cli/src/github_backend.rs:882`
- Workflow hard-fails on mismatch between caller pin and runtime commit:
  - `expected_commit_sha` vs `${{ github.sha }}`
  - File: `.github/workflows/swarm-live-run.yml:59`

Security effect:
- Prevents an unpinned workflow ref in CLI.
- Prevents successful execution if dispatch lands on a commit not matching the callers pinned commit.

Residual risk:
- If the pinned commit itself is malicious, pinning still succeeds.

## 2) Capability tokens and ratchet model

Token format today:
- URL-safe base64 JSON envelope containing:
  - `version`, `kind`, `state_id`, `ratchet_step`, `chain_key`
  - File: `swarm-core/src/capability.rs:16`
- Encode/decode includes basic field validation only.
  - File: `swarm-core/src/capability.rs:33`

Important current property:
- Tokens are bearer tokens (no signature/MAC/KMS binding in envelope).

Ratchet derivation paths:
- Local engine child derivation:
  - `next_chain_key = sha256(parent.chain_key || "::" || context)`
  - File: `swarm-state/src/lib.rs:1041`
- GitHub workflow derivation uses same shape:
  - `sha256(f"{chain_key}::{context}")`
  - File: `.github/workflows/swarm-live-run.yml:123`

Security effect:
- Forward-step chaining works when tokens are correctly handed forward.
- Mismatched key/state combinations fail decryption in restore path (`openssl ... bad decrypt`).

Residual risk:
- Possession of raw token grants use (bearer semantics).
- No anti-replay/issuer authenticity beyond possession and step-wise decryption behavior.

## 3) State encryption and checkpoint bundle properties

Local engine encryption (`swarm-state`):
- Snapshot encryption uses `ChaCha20Poly1305`.
  - File: `swarm-state/src/lib.rs:1057`
- Key derivation: `sha256("swarm-state-key-v1" || chain_key)`.
  - File: `swarm-state/src/lib.rs:1081`
- Nonce derivation: deterministic from `state_id` + `ratchet_step` with domain tag.
  - File: `swarm-state/src/lib.rs:1092`

GitHub workflow bundle encryption:
- Uses `openssl enc -aes-256-cbc -pbkdf2` keyed by ratchet chain key.
  - File: `.github/workflows/swarm-live-run.yml:204`, `.github/workflows/swarm-live-run.yml:227`

Bundle determinism (local engine):
- Deterministic tar ordering and fixed metadata (`mtime=0`, uid/gid/mode fixed).
  - File: `swarm-state/src/lib.rs:998`

Root key seeding (local engine only):
- Initial root chain keys are deterministic hashes of fixed literals:
  - `sha256("root-state-chain-key")`
  - `sha256("root-net-chain-key")`
  - File: `swarm-state/src/lib.rs:481`, `swarm-state/src/lib.rs:488`

Security effect:
- Confidentiality/integrity of local encrypted snapshots depends on chain-key secrecy.
- Ratchet mismatch naturally breaks decryption.

Residual risk:
- Deterministic root seeds are scaffold-grade, not HSM/KMS-backed entropy.
- GitHub path uses passphrase-based OpenSSL CBC flow rather than AEAD + detached metadata discipline.

## 4) Artifact collection and fail-closed restore policy

Collect behavior (`swarm-cli` GitHub backend):
- Downloads artifacts for a run (`gh run download`).
- Requires presence of `result.json` and `next_tokens.json`.
- In default mode, also requires `certificate.json`; when strict policy mode is enabled (default), also requires `policy.json`.
- Validates minimum shape:
  - `result.json`: `run_id`, `status`, `restore_mode` with enum check (+ `artifact_hash` when cert verification is enabled)
  - `next_tokens.json`: `state_cap_next`, `net_cap_next`
- Enforces compatibility rule:
  - if `restore_mode == cold_start` and ledger policy is `fail_closed`, collect fails.
- Automatically runs certificate verification in collect path (default):
  - verifies `artifact_hash == sha256(certificate.json bytes)`
  - verifies required commit pin matches certificate `runtime.workflow_ref`
  - verifies policy hash binding when certificate includes policy metadata
  - strict mode requires policy presence (`require_policy=true` default)

Security effect:
- Prevents quietly proceeding on missing artifacts.
- Prevents silent downgrade to cold-start under fail-closed expectations.
- Prevents successful collect on certificate hash mismatch, commit mismatch, or required-policy mismatch.

Residual risk:
- Shape validation is intentionally minimal.
- Cert verification can be explicitly bypassed with `--skip-verify-cert` for debugging; production posture should keep default verification enabled.

## 5) Certificate/proof verification behavior (current verifier reality)

Certificate verification (`swarm-verify`):
- Computes `sha256:<hex>` over certificate bytes and checks equality to expected artifact hash.
  - File: `swarm-verify/src/lib.rs:75`
- Validates certificate semantic fields and required commit extracted from `runtime.workflow_ref`.
  - File: `swarm-verify/src/lib.rs:112`, `swarm-verify/src/lib.rs:164`
- Validates optional policy branch:
  - if certificate includes `policy`, verifier requires policy bytes and checks `sha256(policy_bytes)` equals `policy.policy_hash`.
  - strict mode can require policy metadata even when absent by default.
  - File: `swarm-verify/src/lib.rs` (`verify_policy_binding`, `verify_certificate_file_with_policy`)

Proof verification (`swarm-verify`):
- Validates envelope structure and schema version.
- Validates `public_inputs_sha256` matches file bytes.
- Does not cryptographically validate zk proof itself in current implementation.
  - File: `swarm-verify/src/lib.rs:201`

CLI verify interface:
- `verify cert` supports:
  - optional `--policy-file` for policy hash checks when policy metadata exists,
  - `--require-policy` strict mode.
- `verify cert` still accepts optional `--attestation`, but current code does not perform attestation cryptographic verification in this path.
  - File: `swarm-cli/src/main.rs`

Security effect:
- You get byte-hash binding + commit equality checks in explicit `verify cert`, and the same checks are now auto-gated in GitHub collect by default.

Residual risk:
- No in-code Sigstore/DSSE chain verification today.
- Verification is enforced in collect by default, but still depends on caller not opting out with `--skip-verify-cert`.

## 6) Network routing and reverse proxy trust model (`net_cap` + `swarm-proxy`)

Policy evaluation (`swarm-cli/src/net_cap.rs`):
- `route_mode=client_exit` requires proxy-mode ticket unless direct fallback is allowed.
- Expiry checks for tickets.
- Preflight probe through broker with `Proxy-Authorization: Basic session:token`.
  - File: `swarm-cli/src/net_cap.rs:106`, `swarm-cli/src/net_cap.rs:215`, `swarm-cli/src/net_cap.rs:233`

Broker/provider enforcement (`swarm-proxy`):
- Broker maps active providers by `session_id`, requires token match.
  - File: `swarm-proxy/src/lib.rs:205`, `swarm-proxy/src/lib.rs:233`
- Worker requests rejected when no provider or wrong token.
  - File: `swarm-proxy/src/lib.rs:250`, `swarm-proxy/src/lib.rs:259`
- Credentials parsed from proxy auth header (Basic auth).
  - File: `swarm-proxy/src/lib.rs:548`

Ticket/token generation:
- Token derives from session/broker/issued_at + pid/time entropy (runtime-local generation).
  - File: `swarm-proxy/src/lib.rs:703`

Security effect:
- Enforces session/token coupling for brokered access.
- Supports fail-closed routing behavior when configured.

Residual risk:
- No TLS/mTLS built into broker/provider protocol.
- Token issuance is local and not bound to external signer/attestation.

## 7) Schema validation model

What is implemented:
- Schemas are loaded as JSON constants and checked for parseability.
- Value validation is done by custom Rust validators (`validate_*`), not a general JSON Schema engine.
  - File: `swarm-core/src/lib.rs:72`, `swarm-core/src/lib.rs:122`

Schema strictness today:
- Contract schemas broadly allow additional properties.
  - Files under `schemas/*.json`, e.g. `schemas/certificate.schema.json`, `schemas/node.schema.json`

Security effect:
- Core required fields and enums are checked.

Residual risk:
- Unknown extra fields are generally tolerated.
- Effective contract strictness equals Rust validator behavior, not full schema semantics.

## What Is Actually Trusted Today

Hard trust assumptions:
- GitHub correctly identifies and executes `${{ github.sha }}` for the workflow run.
- GitHub artifact upload/download path is available and not maliciously altered in transit by caller environment.
- Local machine filesystem/process boundary protects `.swarm` ledgers and capability-bearing artifacts.

Soft trust assumptions:
- Operators keep collect-time verifier gating enabled (do not use `--skip-verify-cert` in production flows).
- Workflow code at pinned commit is audited enough for use case risk.

Not currently trusted via strong crypto inside this repo:
- Capability token issuer authenticity.
- On-chain policy settlement enforcement (Phase 2+ target, not current behavior).
- Cryptographic validity of external zk proofs/attestations beyond envelope/hash checks.

## Guaranteed vs Not Guaranteed (Current)

Guaranteed by current code paths:
- Unpinned workflow refs are rejected by CLI parser.
- Runtime commit mismatch with caller pin causes workflow failure.
- Missing required collect artifacts fail the collect command.
- Fail-closed restore policy mismatch (`cold_start`) is rejected.
- Mismatched ratchet keys fail encrypted checkpoint restore/decrypt operations.
- Verifier can enforce certificate-hash equality + required commit match.
- Verifier enforces policy hash equality when certificate includes policy metadata, with optional strict policy mode.
- Certificate validation rejects unknown `critical_*` fields in certificate objects.
- Certificate `replay` block (if present) is validated for `nonce` and `expires_at_unix > 0`.
- GitHub workflow emits `artifact_hash` from actual `certificate.json` bytes.
- GitHub collect path now fail-closes on certificate hash/commit/policy verification failures by default.

Not guaranteed yet:
- Signed/non-forgeable capability envelopes.
- Full cryptographic proof verification for zk attestations in `swarm-verify`.
- Transport-layer security for broker/provider path.

## Attack Scenarios (As Implemented)

1. Prover tries unpinned branch/tag workflow ref
- Result: blocked in CLI (`WORKFLOW_REF_UNPINNED`).

2. Prover dispatches to ref that does not match expected pinned commit
- Result: workflow fails at commit validation step.

3. Attacker obtains a capability token
- Result: token can be replayed as bearer capability until ratchet/context makes it unusable.
- Why: token payload is unsigned base64 JSON.

4. Artifact tampering after run
- Result: collect fails by default on cert hash/commit/policy mismatch via verifier-gated checks.
- Caveat: caller can still opt out with `--skip-verify-cert`.

5. Wrong token or missing provider for client-exit proxy
- Result: policy violation / HTTP error (fail-closed when configured).

6. Malicious pinned commit
- Result: all pin checks pass; security depends on audit of that pinned commit.

## Test-Backed Evidence in Repository

Workspace test run used for this trust-model snapshot:
- Command: `cargo test --workspace`
- Date: 2026-02-28
- Result: pass
  - `swarm-cli`: 36 tests
  - `swarm-core`: 13 tests
  - `swarm-proxy`: 4 tests
  - `swarm-state`: 6 tests
  - `swarm-verify`: 19 tests

Notable regression tests covering trust boundaries:
- `net_cap::tests::policy_mismatch_rejected_for_client_exit_non_proxy_ticket`
- `net_cap::tests::no_provider_returns_policy_violation`
- `net_cap::tests::wrong_token_returns_policy_violation`
- `github_backend::tests::reject_unpinned_commit`
- `github_backend::tests::collect_fails_when_required_artifacts_missing`
- `github_backend::tests::collect_parse_failure_persists_last_error_and_run_id`
- `github_backend::tests::collect_verifies_certificate_and_policy_by_default`
- `github_backend::tests::collect_fails_closed_on_certificate_hash_mismatch`
- `github_backend::tests::collect_fails_closed_when_policy_required_but_missing`
- `github_backend::tests::collect_fails_closed_on_required_commit_mismatch`
- `swarm_verify::tests::verify_required_commit_rejects_mismatch`
- `swarm_verify::tests::verify_proof_file_rejects_hash_mismatch`
- `swarm_state::tests::deterministic_resume_artifacts_are_byte_stable_and_ratchet`

## Practical Security Posture (Current)

`swarm` currently implements a pragmatic, fail-closed-in-key-spots orchestration trust model:
- strong operational checks for pinning, artifact presence, policy mismatch,
- deterministic ratchet/chaining behavior for state continuity,
- collect-time verifier gating by default for hash/commit/policy binding.

It is not yet a fully cryptographic remote-attestation trust model. The largest current gap is that capability authenticity and attestation proof validity are not enforced end-to-end by cryptographic verification in the runtime path.

## Auditor Checklist for Current Code

When auditing a run today, check in this order:
1. `workflow_ref` pin and workflow commit check are present and succeeded.
2. `result.json` + `next_tokens.json` exist and match expected run context.
3. Restore mode did not violate fail-closed expectations.
4. Confirm collect reported `verification_ok=true` (or run explicit verifier for independent confirmation).
5. For client-exit mode, verify ticket mode/expiry and broker/provider token match behavior.
6. Treat all capability tokens as high-sensitivity bearer secrets.
