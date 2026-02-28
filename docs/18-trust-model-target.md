# Trust Model (Target End State)

Status: draft
Date: 2026-02-28
Scope: target security model we are building toward across M4 plus marketplace phases

## Purpose

This document defines the trust model for the finished `swarm` system.

It is intentionally different from `docs/17-trust-model-implemented.md`, which describes the code as it exists today.

## One-line target

A buyer should only pay for a step when they can verify that:
- a specific pinned workflow commit executed,
- under a specific pinned policy capsule,
- on the intended run/session,
- with ratcheted state and network capabilities that cannot be reused out of order,
- and with evidence that can be checked offline and on-chain.

## Security objective

The finished system aims to provide three enforceable properties:

1. Code identity integrity
- The execution is bound to a specific immutable workflow commit.

2. Policy intent integrity
- The execution is bound to a specific policy capsule hash.

3. State continuity integrity
- Each step can only continue from the prior step in the ratchet chain.

## Trust model shape

Like `github-zktls`, this model separates load-bearing trust from convenience UX.

Load-bearing trust (security-critical):
- Sigstore certificate and attestation chain verification.
- GitHub OIDC job identity claims for the runner session.
- Smart contract state on Base Sepolia for entitlement, replay protection, and permit consumption.
- Capability ratchet and encrypted state bundle continuity.

Convenience layer (non-load-bearing):
- GitHub artifacts as storage transport.
- CLI orchestration, logs, status UX.
- Marketplace indexing/discovery UX (if added later).

If convenience components fail, user experience degrades.
If load-bearing components fail, security guarantees fail.

## Actors and trust boundaries

Actors:
- Buyer: pays for execution rights.
- Seller: publishes offer terms (commit/policy/price/step limits).
- Runner: executes workflow step.
- Capability Gateway: releases step-scoped caps only after identity and entitlement checks.
- Verifier: checks run evidence offline and/or on-chain.
- Settlement contracts: enforce payout/dispute rules.

Trust boundaries:

```text
Buyer/Seller wallets
  -> Base Sepolia contracts (entitlement, permits, settlement)

Runner job (GitHub Actions)
  -> GitHub OIDC token
  -> Capability Gateway
  -> receives encrypted state_cap/net_cap for one step

Artifacts and certificates
  -> GitHub artifact transport
  -> local verifier and/or on-chain verifier path
```

## Core trust anchors (target)

1. Sigstore root and Fulcio chain
- Verifier checks certificate chain, signature validity, and attestation linkage.
- Artifact hash and commit claim are cryptographically bound.

2. GitHub OIDC identity for active job
- Gateway accepts cap-release requests only from jobs whose OIDC claims match expected repo, workflow ref, commit SHA, run id, and audience.

3. Base Sepolia contract state
- Entitlement status, permit nonce/consumption, and step monotonicity are checked on-chain.
- Replay is prevented by consumed permit hashes and nonces.

4. Ratcheted capability chain
- Each step has distinct `state_cap` and `net_cap` material.
- Step N+1 depends on outputs of step N.

## Data objects that carry trust

1. Policy capsule (`policy.json`)
- Deterministic JSON policy object.
- Hash `policy_hash = sha256(policy_bytes)` is embedded in certificate.

2. Certificate (`certificate.json`)
- Includes run identity, workflow ref, state continuity fields, and policy hash metadata.
- Certificate bytes are bound to attested `artifact_hash`.

3. Proof envelope
- Links proof/public inputs to certificate hash and expected claims.

4. Capability tokens (`state_cap`, `net_cap`)
- Carry ratchet step and chain context.
- In end state they are delivered as step-scoped encrypted payloads bound to permit and worker key.

5. Settlement claim
- Contract call payload that references proof/certificate claims, replay ids, and entitlement step.

## End-state execution and verification flow

1. Offer publish
- Seller publishes offer terms on-chain:
  - required commit,
  - required policy hash,
  - pricing and step limits,
  - timeout/dispute parameters.

2. Entitlement purchase
- Buyer funds escrow and receives active entitlement.

3. Step permit authorization
- Buyer signs EIP-712 permit for specific step/run/commit/policy constraints.
- Contract validates signer and marks permit consumable.

4. Worker identity check
- Runner requests GitHub OIDC token.
- Gateway validates OIDC claims against permit and offer terms.

5. Capability release gate
- Gateway atomically consumes permit on-chain.
- Gateway releases encrypted `state_cap_in` and `net_cap_in` only for that step.

6. Execution and ratchet
- Runner restores previous encrypted bundle with step cap.
- Runner executes step.
- Runner emits `result.json`, `next_tokens.json`, certificate, and attestation evidence.

7. Verification and settlement
- Verifier checks attestation chain, cert hash binding, commit, policy hash, and continuity checks.
- Settlement contract releases payout only when checks pass.

## Guarantees we are building toward

If all target components are implemented correctly, the verifier/contract can conclude:

1. Code guarantee
- The run is bound to an immutable audited workflow commit.

2. Policy guarantee
- The run is bound to exact policy bytes (via `policy_hash`).

3. Continuity guarantee
- The run belongs to the correct ratchet step and cannot be replayed as another step.

4. Entitlement guarantee
- Capability release occurred only for a valid paid entitlement and valid signed permit.

5. Replay resistance
- Old permits and already-consumed step authorizations are rejected.

## Explicit non-goals even in end state

1. Not a full semantic correctness proof
- We prove code identity, policy binding, and continuity constraints.
- We do not prove the model output is truthful or high quality.

2. Not censorship-proof workflow execution
- GitHub remains an execution substrate with availability/control-plane risk.

3. Not secrecy against a fully compromised runner platform
- This model reduces misuse via gating and cryptographic binding; it does not claim hardware-TEE confidentiality unless a TEE backend is added and verified.

## Main adversaries and intended defenses

1. Malicious buyer replaying old caps or permits
- Defense: on-chain consumed-permit tracking, step nonces, ratchet progression checks.

2. Malicious seller changing policy after purchase
- Defense: on-chain offer pins `policy_hash`; cert verification requires match.

3. Runner/job spoofing capability requests
- Defense: strict OIDC claim validation plus permit binding fields.

4. Artifact tampering in storage channel
- Defense: attestation plus cert hash verification detects tampering.

5. Network route downgrade attempts
- Defense: policy capsule route constraints plus fail-closed net-cap checks.

## Finished-state trust assumptions

Assumptions we still accept in target model:
- Sigstore PKI and transparency ecosystem remain trustworthy enough for attestation validation.
- GitHub OIDC claims correctly represent active job identity.
- Base Sepolia consensus/finality is sufficient for entitlement and settlement state.
- Gateway implementation is correct and hardened, or replaced by a stronger attested service.

Assumptions we reduce compared to current model:
- Reduced reliance on bearer token secrecy alone.
- Reduced reliance on best-effort/offline-only verification.
- Reduced reliance on operator discipline to enforce policy and replay rules manually.

## Maturity gates to call this model "finished"

Gate A: Cryptographic verification completeness
- `swarm-verify` performs full attestation/chain verification, not hash-shape checks only.

Gate B: Policy capsule binding enforcement
- Policy hash is in certificate and enforced in verifier path.
- Strict mode available to require policy presence for market flows.

Gate C: Capability release hard gate
- Capability release is permit-gated and entitlement-gated.
- Permits are one-time and step-scoped with replay protection.

Gate D: Settlement enforcement
- On-chain settlement checks commit, certificate hash binding, policy hash, replay ids, and step validity before payout.

Gate E: Regression and adversarial tests
- Negative tests cover wrong commit, wrong policy hash, wrong permit signer, expired permit, reused permit, wrong step, and cap/token mismatch.

## Relationship to current trust model

- Current state is documented in `docs/17-trust-model-implemented.md`.
- This document is the target model for the finished project.
- The migration path is to move each control from optional or local-only into cryptographically enforced verifier and contract gates.

## Practical summary

The project is building toward a "proof-backed execution entitlement" trust model:
- identity of code is pinned and attestable,
- policy intent is hash-bound and enforceable,
- state continuity is ratcheted and non-replayable,
- economic settlement is contract-enforced,
- and useful worker access is gated by cryptographic permits instead of trust in orchestration alone.
