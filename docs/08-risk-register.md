# Risk register

Status: draft
Date: 2026-02-28

| ID | Risk | Impact | Likelihood | Mitigation | Tracking |
|---|---|---|---|---|---|
| R-01 | Workflow commit not pinned | high | medium | mandatory commit pin check in run spec + verifier | M0 |
| R-02 | Certificate semantics overclaimed | high | medium | document trust boundary; enforce schema + hash checks only | M0 |
| R-03 | Checkpoint restore portability failures | high | high | compatibility checks + required cold-start fallback | M2 |
| R-04 | Capability token leakage in logs | high | medium | secret masking + redaction + no-token logging rules | M1 |
| R-05 | `net_cap` route policy bypass | high | medium | fail-closed policy and egress verification probes | M3 |
| R-06 | GitHub policy/compliance mismatch for service shape | medium | medium | job-scoped design + substrate abstraction + future backend options | ongoing |
| R-07 | oauth3 dependency instability | medium | high | keep as reference only until high findings close | ongoing |
| R-08 | Artifact retention limits break recoverability | medium | medium | durable object store for encrypted bundles | M2 |
| R-09 | Schema drift across backends | medium | medium | strict fixture-based contract tests (`result.json`, `next_tokens.json`) | M2b/M5 |
| R-10 | Incomplete verification path in clients | high | medium | ship verifier commands as core Phase 0/1 functionality | M0-M2 |

## Risk response rules

- Security/trust risks default to fail-closed.
- Runtime portability risks require deterministic fallback classification.
- New backend risk must not alter core artifact/token contracts.
