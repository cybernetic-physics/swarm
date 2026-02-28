# Backends and substrates

Status: draft
Date: 2026-02-28

## Backend strategy

Phase 0/1:
- `local` backend for deterministic local loop.
- `github` backend for attested execution episodes.

Phase 2+:
- `gitlab` backend with contract parity (`result.json`, `next_tokens.json`).

## Execution matrix

| Backend | Phase | Role | Notes |
|---|---|---|---|
| local | 0/1 | fast iteration + deterministic tests | no external attestation required |
| github | 0/1 | primary attested worker backend | commit pin + cert hash flow |
| gitlab | 2+ | secondary backend parity | same bundle/token/cert contracts |
| cloudflare workers | research | optional future runtime | not checkpoint-native |

## Restore policy (mandatory)

Restore order:
1. state DB snapshot.
2. workspace snapshot.
3. volumes (if used).
4. runtime checkpoint (if supported and compatible).
5. `net_cap` route re-establishment.

On failure:
- compatibility failure -> cold-start fallback.
- record fallback reason in run outputs.
- fail closed if policy requires checkpoint restore only.

## GitHub-specific notes

- Treat runs as bounded episodes.
- DinD/CRIU path is best-effort and portability-sensitive.
- Keep large encrypted bundles in durable storage; use artifacts for transport/debug.

## GitLab-specific parity target

- Triggered pipeline receives explicit bundle/token inputs.
- Job emits deterministic `result.json` and `next_tokens.json`.
- Networking follows same `net_cap` lifecycle and fail-closed semantics.

## Networking contract alignment

- `state_cap` and `net_cap` ratchet independently.
- route policy changes should be namespace-scoped when possible.
- live sockets are not portable checkpoint state.
