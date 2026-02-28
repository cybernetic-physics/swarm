# Open questions and decisions

Status: draft
Date: 2026-02-28

## Decision log template

Use this format for each decision:
- `id`: DEC-###
- `title`:
- `date`:
- `status`: proposed | accepted | deferred | rejected
- `context`:
- `decision`:
- `consequences`:

## Current open questions

### DEC-001: Mode B transfer semantics
- Question: should state capability delivery be lease-based or ownership transfer?
- Current status: proposed.
- Needed by: before marketplace implementation.

### DEC-002: Proof policy
- Question: mandatory proof per run vs challenge-window model?
- Current status: proposed.
- Needed by: before settlement implementation.

### DEC-003: Production substrate after GitHub-only phase
- Question: self-hosted runner pool vs dedicated VM fleet vs TEE-backed path?
- Current status: proposed.
- Needed by: Phase 2 planning.

### DEC-004: Capability envelope format
- Question: token encoding, key IDs, expiry/nonce handling, and versioning format.
- Current status: proposed.
- Needed by: M0 schema freeze.

### DEC-005: Restore guarantee language
- Question: what exact user-visible SLA is promised for checkpoint restore vs cold-start fallback?
- Current status: proposed.
- Needed by: pre-beta docs.

### DEC-006: Schema evolution policy
- Question: strict compatibility strategy for future schema versions across backends.
- Current status: proposed.
- Needed by: before GitLab parity.
