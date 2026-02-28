# Implementation backlog

Status: draft
Date: 2026-02-28

This backlog translates `Main TODO` + `agent_swarm` planning notes into executable `swarm` work items.

## P0 (must complete before beta)

- [ ] Freeze schema contracts (`node`, `certificate`, `result`, `next_tokens`).
- [ ] Implement verifier minimum checks and fixture suite.
- [ ] Create `swarm-core`, `swarm-state`, `swarm-verify`, `swarm-cli` crates.
- [ ] Implement local backend with deterministic bundle pipeline.
- [ ] Implement capability envelope parser/serializer with redaction-safe logging.
- [ ] Implement GitHub dispatch/collect adapter with pinned workflow enforcement.
- [ ] Implement restore compatibility checks and cold-start fallback branch.

## P1 (required for robust MVP)

- [ ] Add proxy-first `net_cap` mode with fail-closed policy path.
- [ ] Add timeout/retry/cancel policy to backend adapters.
- [ ] Add machine-readable error taxonomy and stable exit codes.
- [ ] Add conformance tests for deterministic artifacts across repeated runs.
- [ ] Add storage adapters (local + S3) with manifest integrity checks.
- [ ] Add `doctor` command for env/workflow prerequisites.

## P2 (Phase 2+ readiness)

- [ ] GitLab backend adapter with output parity tests.
- [ ] Policy capsule hash field integration (optional, verifier-gated).
- [ ] Marketplace command surface stubs (`market offer/buy/fulfill`) behind feature flags.
- [ ] Optional attestation proof generation wrapper command.

## Track: security hardening

- [ ] Secret redaction tests for logs.
- [ ] Token rotation atomicity tests.
- [ ] Replay protection fixture coverage (`job_id`, `request_hash`, nonce/expiry).
- [ ] Certificate schema strictness tests (reject unknown critical fields policy).

## Track: developer experience

- [ ] `swarm init` scaffolding command (similar to `popcorn setup`).
- [ ] Sample fixtures for local dry-run and GitHub run.
- [ ] End-to-end tutorial docs.

## Suggested first sprint

1. Bootstrap Rust workspace and command skeleton.
2. Implement schema validation + fixtures.
3. Implement local run/fork/resume loop.
4. Implement verifier command path.
5. Add initial GitHub dispatch command.
