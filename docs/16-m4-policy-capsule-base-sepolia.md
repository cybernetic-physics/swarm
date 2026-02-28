title:: agent_swarm M4 policy capsule and Base Sepolia settlement design
type:: architecture-note
status:: draft
updated:: 2026-02-28
tags:: agent_swarm, m4, policy-capsule, github-zktls, base-sepolia, solidity, settlement, marketplace, ratchet-keys

## Why this page exists
- The current `agent_swarm` Phase 0/1 path already proves code identity and artifact binding (commit + artifact hash).
- What is still missing is a verifiable policy binding for each run.
- M4 is the bridge: add a policy capsule (`policy.json`) hash into the certificate now, then reuse the same binding in Solidity settlement on Base Sepolia.
- We also need a Phase 3 contract-only marketplace path (no UI required) where on-chain terms gate paid access to ratcheted state/network capabilities.

## Source-of-truth anchors
- Logseq direction
  - [[agent_swarm what to build now]]
    - M4 calls for policy capsule artifact (`policy.json` hash in certificate).
  - [[Conseca and agent_swarm]]
    - policy says what code was allowed to do for the specific task.
  - [[agent_swarm github-zktls integration blueprint]]
    - keep `commitSha` + `artifactHash` trust boundary and layer semantics above it.
  - [[Main TODO]]
    - freeze verifier flow for Phase 0/1 in settlement-compatible form.
- `github-zktls` trust + contracts
  - `docs/trust-model.md`
    - proof guarantees binding of `commitSha`, `artifactHash`, `repoHash`.
    - proof does not guarantee workflow/business semantics.
  - `contracts/src/ISigstoreVerifier.sol`
    - attestation tuple: `artifactHash`, `repoHash`, `commitSha`.
  - `contracts/src/SigstoreVerifier.sol`
    - canonical on-chain decode/verify boundary.
  - `contracts/examples/SelfJudgingEscrow.sol`
    - correct app-level pattern: verify proof -> match certificate hash -> enforce commit pin -> enforce semantics.

## M4 problem statement
- Today we can prove:
  - which commit ran,
  - which artifact bytes were attested.
- Today we cannot prove:
  - which execution policy was in force for that run.
- M4 objective:
  - cryptographically bind a policy capsule to each run certificate so policy tampering becomes detectable.

## Phase model
### Phase 1 (implement now, off-chain verifier path)
- Add optional policy metadata to certificate.
- Add policy-hash verification branch in `swarm-verify`.
- Keep backward compatibility for existing certificates.
- No on-chain dependency required for usability.

### Phase 2 (settlement path, Solidity on Base Sepolia)
- Add a swarm settlement contract that composes `github-zktls` verifier.
- Enforce the same policy-hash check on-chain for payouts/claims.
- Keep off-chain execution architecture unchanged (GitHub workers + artifacts), only add settlement verification.

### Phase 3 (marketplace contracts only, no UI)
- Build contract primitives for offer publication, purchase, entitlement, and payout/dispute.
- Gate paid access to execution by gating ratcheted capability release (`state_cap`, `net_cap`) per step.
- Keep user surface CLI-first (`loom market ...` style) with no web marketplace dependency.
- Keep GitHub as execution substrate for now; contracts govern authorization and payment semantics.

## Data contract changes for M4
### `policy.json` artifact (new)
- Deterministic, machine-checkable policy payload.
- Avoid free-form-only policy in enforcement-critical paths.

Example v1:
```json
{
  "schema_version": "agent_swarm-policy-v1",
  "policy_id": "uuid",
  "route_mode": "direct|client_exit",
  "allowed_tools": ["shell", "git", "cargo"],
  "blocked_tools": ["ssh", "docker"],
  "limits": {
    "max_runtime_sec": 1800,
    "max_retries": 3
  },
  "provenance": {
    "generator": "swarm-policy-engine-v1",
    "generated_at": "RFC3339"
  }
}
```

### Certificate extension (optional)
Example addition to `certificate.json`:
```json
{
  "policy": {
    "schema_version": "agent_swarm-policy-v1",
    "policy_hash": "sha256:<hex>",
    "policy_ref": "gh-artifact://<run_id>/policy-json",
    "policy_generated_at": "RFC3339"
  }
}
```

Rules:
- If `policy` is present, all fields above are required.
- `policy_hash` must be SHA-256 of exact uploaded `policy.json` bytes.
- If `policy` is absent, existing verification behavior remains valid by default.

## Verifier behavior matrix (M4)
### Default mode (backward compatible)
- No policy section in certificate:
  - pass (no policy check).
- Policy section present:
  - require policy bytes,
  - recompute hash,
  - mismatch -> fail.

### Strict mode (later)
- No policy section:
  - fail (`policy required`).
- Policy section present:
  - same hash checks as default mode.

Candidate CLI flags:
- `--policy-file <path>`
- `--require-policy`

## Workflow impact (Phase 1)
1. Generate `policy.json` before execution gates.
2. Enforce deterministic policy checks at action boundaries.
3. Upload `policy.json` as artifact.
4. Include `policy_hash` + `policy_ref` in `certificate.json`.
5. Continue attesting `certificate.json` as the load-bearing attested artifact.

Important trust boundary:
- Attestation binds certificate bytes directly.
- Policy is transitively bound by policy hash inside certificate.

## What "leaning into Solidity on Base Sepolia" means
It does not mean moving execution on-chain.

It means adding on-chain settlement checks that validate the same trust model:
1. Verify GitHub/Sigstore proof via `SigstoreVerifier.verifyAndDecode`.
2. Require `sha256(certificate) == artifactHash`.
3. Require commit pin match.
4. Require policy hash match if terms require policy.
5. Enforce replay protection (`request_hash`, `job_id`-derived key).
6. Release payout only if all checks pass.

## How smart contracts gate access to a GitHub worker
Direct truth:
- Smart contracts cannot directly prevent someone from triggering a GitHub workflow.
- The practical control point is capability access, not workflow start.

Gate design:
1. Worker execution requires valid `state_cap_in` and `net_cap_in` for step `N`.
2. These caps are encrypted key material for the encrypted bundle + network route policy.
3. Capability release happens only after on-chain entitlement/payment checks pass.
4. If entitlement fails, the workflow may still start, but cannot restore paid state and cannot access paid network path.

Result:
- Contract gating is implemented as cryptographic resource gating via ratcheted keys.
- This is equivalent to gating useful worker access, even if `workflow_dispatch` itself remains public.

## Phase 3 contract architecture (marketplace without UI)
Contracts:
- `SwarmMarket`
  - create offers, accept buys, hold escrow, track deadlines/disputes.
- `SwarmEntitlement`
  - records `buyer`, `seller`, `offer_id`, `current_step`, `max_step`, status.
- `SwarmExecutionGate`
  - registers and consumes one-time execution permits.
  - stores `permitHash -> consumed` and enforces monotonic step progression.

Off-chain but mandatory service:
- `Capability Gateway` (stateless API service)
  - verifies GitHub OIDC token claims for the live workflow job.
  - verifies on-chain entitlement + unconsumed permit.
  - releases encrypted `state_cap_in` + `net_cap_in` for the approved step only.

Why this split is necessary:
- On-chain contracts can verify payment/permissions.
- Only off-chain components can inspect GitHub job identity in real time and deliver secret key material to that job.
- GitHub OIDC + on-chain permit state is the bridge.

## Phase 3 permit and ratchet-key model
Permit object (EIP-712 typed data):
- `offer_id`
- `entitlement_id`
- `step`
- `run_id`
- `workflow_ref`
- `commit_sha_required`
- `policy_hash_required`
- `worker_pubkey`
- `expires_at`
- `nonce`
- `action_type` (`EXECUTE_STEP`, `CANCEL`, `ROTATE_KEY`)

EIP-712 domain requirements (mandatory):
- `name`
- `version`
- `chainId`
- `verifyingContract` (`SwarmExecutionGate`)

Signer binding requirements (mandatory):
- permit signer must match entitlement buyer (or an explicitly delegated signer registry entry).
- do not infer scheme from `extcodesize`; require explicit scheme selection.
- for ERC-1271, enforce exact magic return value + returndata length and reject precompile addresses `0x01..0x09`.

Permit validation:
- EOA buyers: `ecrecover` on EIP-712 digest.
- Smart-wallet buyers: ERC-1271 `isValidSignature`.

One-time consumption:
- `SwarmExecutionGate.consumePermit(permitHash, ...)` marks permit used.
- Replay fails at contract level.
- Nonces must be domain-separated:
  - `nonce[entitlement_id][action_type]` (not one flat nonce across actions).
  - avoid cross-function nonce reuse and AA/protocol nonce ambiguity.

Ratchet-key usage:
- Existing swarm state/net ratchet remains (`state_cap`, `net_cap`, `ratchet_step`).
- Phase 3 adds permit binding so each released cap is tied to:
  - one entitlement,
  - one step,
  - one run id,
  - one worker public key.
- Gateway returns caps encrypted to `worker_pubkey`; leaked transport blobs are useless without runner private key.
- Required contract hardening: store `state_cap_commit_n` / `net_cap_commit_n` per entitlement step and require gateway release events to reference those commitments.

Recommended derivation hardening:
- Derive step keys with domain-separated context:
  - `k_state_n = HKDF(chain_key_n, \"swarm-state\" || entitlement_id || step || run_id)`
  - `k_net_n = HKDF(chain_key_n, \"swarm-net\" || entitlement_id || step || run_id)`
- Continue forward ratchet after completion and emit `state_cap_next`/`net_cap_next`.

## Phase 3 failure modes and mitigations
- Gateway compromise or misconfiguration could leak caps.
  - Mitigate by short cap TTL, worker-pubkey encryption, one-time permit consumption, and strict OIDC claim checks.
- Buyer replaying old permit/caps.
  - Mitigate with on-chain consumed permit hash + step monotonic enforcement.
- Wrong workflow/ref receives caps.
  - Mitigate by binding permit fields to `workflow_ref`, `commit_sha_required`, and `run_id`, then checking OIDC claims match.
- Runner crashes after cap release but before settle.
  - Mitigate with per-step expiry and re-issuable permit nonce policy controlled by contract status.

## Phase 3 end-to-end access flow
1. Seller posts offer on Base Sepolia (`commit_sha_required`, `policy_hash_required`, price, step limits).
2. Buyer purchases an entitlement (escrow funded on-chain).
3. Buyer signs EIP-712 execution permit for step `N` (or smart-wallet signs via ERC-1271).
4. Runner starts GitHub job and requests OIDC token.
5. Runner calls Capability Gateway with:
   - OIDC JWT,
   - permit payload/signature,
   - `worker_pubkey`.
6. Gateway verifies:
   - OIDC issuer is `https://token.actions.githubusercontent.com`,
   - OIDC claims match expected `sub`, `repository`, `repository_owner`, `job_workflow_ref`, `sha`, `run_id`, `run_attempt`, and `aud`,
   - permit valid and unexpired,
   - on-chain entitlement active and step not already consumed.
7. Gateway atomically calls `consumePermit` and only on success returns encrypted caps for step `N`.
8. Runner decrypts caps, restores encrypted bundle, executes, emits attested certificate + next tokens.
9. Settlement contract verifies proof/certificate/policy hash and releases payout.

## Phase 3 sequence diagram
```text
Buyer -> SwarmMarket: buyOffer(offer_id) + escrow
Runner (GitHub) -> GitHub OIDC: request JWT (id-token: write)
Runner -> Capability Gateway: OIDC JWT + permit + worker_pubkey
Capability Gateway -> SwarmExecutionGate: consumePermit + entitlement step checks
Capability Gateway -> Runner: enc(state_cap_in), enc(net_cap_in)
Runner -> GitHub workflow: execute with paid caps
Runner -> SwarmPolicyEscrow: claim(proof, cert, settlementClaims, replay ids)
SwarmPolicyEscrow -> SigstoreVerifier: verifyAndDecode()
SwarmPolicyEscrow -> Seller: payout
```

## Base Sepolia constraints (current)
- Network: Base Sepolia
- Chain ID: `84532`
- RPC: `https://sepolia.base.org`
- Explorer: `https://sepolia-explorer.base.org`
- Base public RPC is rate-limited and not production-grade.

## Contract topology
```text
+------------------------------+       +-----------------------------+
| github-zktls SigstoreVerifier|<------| SwarmPolicyEscrow (new)     |
| verifyAndDecode(proof, pi)   |       | - cert hash check           |
+------------------------------+       | - commit pin check          |
                                       | - optional repo filter      |
                                       | - policy hash requirement   |
                                       | - replay guard + payout     |
                                       +-----------------------------+

                  +-----------------------------------+
                  | SwarmMarket + SwarmExecutionGate |
                  | - offers/entitlements/permits    |
                  | - one-time permit consumption     |
                  +-----------------+-----------------+
                                    ^
                                    |
                       +------------+-------------+
                       | Capability Gateway       |
                       | - OIDC claim validation  |
                       | - on-chain permit check  |
                       | - encrypted cap release  |
                       +--------------------------+
```

Principle:
- Reuse `SigstoreVerifier` as immutable dependency.
- Keep swarm business semantics in a thin app contract.

Upgradeability policy (recommended):
- Prefer immutable (non-proxy) deployments for `SwarmPolicyEscrow`, `SwarmMarket`, and `SwarmExecutionGate`.
- If proxies are unavoidable: timelocked upgrades, multisig control, codehash monitoring, and explicit storage-layout checks are mandatory.

## Proposed Solidity interface sketch
```solidity
interface ISwarmPolicyEscrow {
    struct Terms {
        bytes20 requiredCommitSha;
        bytes32 requiredRepoHash;      // optional (0 means skip)
        bytes32 requiredPolicyHash;    // optional in flexible mode
        bytes32 requestHash;
        uint256 deadline;
        address payoutTo;
        uint256 amount;
    }

    function createTerms(Terms calldata terms) external payable returns (uint256 id);

    function claim(
        uint256 id,
        bytes calldata proof,
        bytes32[] calldata publicInputs,
        bytes calldata certificate,
        bytes calldata settlementClaims, // fixed-width ABI-encoded claims blob
        bytes32 jobIdHash
    ) external;
}
```

Claim path checks (ordered):
1. `verifyAndDecode` proof.
2. certificate hash equality.
3. commit pin equality.
4. optional repo filter equality.
5. decode `settlementClaims`; enforce `policy_hash`, `request_hash`, `entitlement_id`, `step`, `buyer_address`.
6. require `sha256(settlementClaims)` equals hash committed inside certificate (or attested as settlement subject).
7. replay check on deterministic claim key.
8. payout.

Payout safety rule:
- Use pull-payment accounting (`claimable[recipient] += amount`) plus `withdraw()` to avoid push-payment receiver griefing.

Settlement profile rule:
- Strict Phase 3 settlement should attest `settlementClaims` as the primary subject hash.
- Certificate-attested settlement is migration-only and should not be the long-term on-chain profile.

Canonicalization requirement:
- Use one canonical encoding for `settlementClaims` (fixed ABI schema + deterministic field order).
- Do not allow alternate hash/encoding paths between off-chain producer and on-chain verifier.

Execution-gate interface sketch:
```solidity
interface ISwarmExecutionGate {
    struct Permit {
        uint256 offerId;
        uint256 entitlementId;
        uint64 step;
        uint8 actionType;
        bytes32 workflowRefHash;
        bytes32 runIdHash;
        bytes20 commitShaRequired;
        bytes32 policyHashRequired;
        bytes32 workerPubkeyHash;
        uint64 expiresAt;
        uint256 nonce;
    }

    function consumePermit(
        Permit calldata permit,
        bytes calldata signature
    ) external returns (bytes32 permitHash);

    function isPermitConsumed(bytes32 permitHash) external view returns (bool);
}
```

## Replay alignment with existing swarm model
- Current swarm already tracks replay identifiers (`job_id`, `request_hash`).
- On-chain claim key should align:
  - `claimKey = keccak256(chainId || address(this) || entitlementId || step || requestHash || jobIdHash || artifactHash)`
- Prevents duplicate payout on repeated submissions of the same attested output.

## Module boundaries
- Keep contracts as separate module but integrated in CLI flow.

Suggested layout:
```text
swarm/
  contracts/
    src/SwarmPolicyEscrow.sol
    src/SwarmMarket.sol
    src/SwarmExecutionGate.sol
    script/DeploySwarmPolicyEscrow.s.sol
    script/DeploySwarmMarket.s.sol
    test/SwarmPolicyEscrow.t.sol
    test/SwarmExecutionGate.t.sol
  services/
    capability-gateway/
      README.md
      src/main.rs
  swarm-cli/
    settle/prepare.rs
    settle/submit.rs
    settle/status.rs
    market/offer.rs
    market/buy.rs
    market/permit.rs
```

This matches your requirement:
- separately load/run module,
- but still ergonomic from CLI.

## Sequence diagrams
### Phase 1 (off-chain M4)
```text
CLI -> GitHub workflow: dispatch with pinned commit
Workflow -> policy.json: generate deterministic policy capsule
Workflow -> execution: enforce policy gates
Workflow -> certificate.json: write policy_hash + policy_ref
Workflow -> attestation: attest certificate.json
CLI -> collect: result + next_tokens + certificate + policy
CLI verifier -> checks: proof + cert hash + commit + policy hash
```

### Phase 2 (Base Sepolia settlement)
```text
Worker -> SwarmPolicyEscrow.claim(...)
SwarmPolicyEscrow -> SigstoreVerifier.verifyAndDecode(...)
SigstoreVerifier -> SwarmPolicyEscrow: attestation tuple
SwarmPolicyEscrow: cert hash / commit / policy / replay checks
SwarmPolicyEscrow -> payout recipient
```

## Security posture notes
- `repoHash` is informational in `github-zktls` trust model unless made mandatory in terms.
- Commit pin remains primary immutable code identity boundary.
- Policy-hash binding proves policy artifact integrity, not full semantic correctness by itself.
- Existing bearer-token caveat for `state_cap` / `net_cap` remains unchanged by M4.

## Test plan
### Phase 1 verifier tests
- matching policy hash -> pass.
- mutated policy bytes -> fail.
- policy metadata present, no policy file -> fail.
- old cert (no policy metadata), default mode -> pass.
- old cert, strict mode -> fail.

### Contract tests
- valid claim path pays out.
- wrong commit reverts.
- certificate mismatch reverts.
- wrong policy hash reverts.
- replay claim reverts.
- deadline expiry rules hold.
- consume-permit front-run attempt cannot grief legitimate gateway release path.
- cross-function nonce reuse test (`EXECUTE_STEP` nonce cannot invalidate `CANCEL` nonce).
- ERC-1271 precompile-address signer rejection test.
- payout path uses pull-claim fallback if direct transfer fails.

### Phase 3 marketplace tests (contract + gateway)
- permit signed for step `N` works exactly once.
- replayed permit fails on `consumePermit`.
- wrong `workflow_ref` or `run_id` in permit fails gateway validation.
- OIDC token with wrong repo/workflow claims fails gateway validation.
- entitlement unpaid/expired/disputed fails cap release.
- cap encrypted for `worker_pubkey_A` cannot be decrypted by `worker_pubkey_B`.
- step `N` permit cannot release step `N+1` keys.

### Live Base Sepolia tests
- deploy `SwarmPolicyEscrow` against known `SigstoreVerifier` address.
- run one successful claim with real GitHub-attested cert.
- run one negative claim with policy hash mismatch.
- record tx hashes and revert selectors in docs.

## Milestones
- M4a: schema + verifier optional branch + regression tests.
- M4b: workflow emits policy artifact + certificate policy fields.
- M4c: Solidity module + Foundry tests.
- M4d: Base Sepolia live settlement test and documentation.
- M5a: `SwarmMarket` + `SwarmExecutionGate` contracts (no UI).
- M5b: Capability Gateway with OIDC + on-chain entitlement checks.
- M5c: ratcheted cap release bound to consumed permit + worker pubkey.
- M5d: live Base Sepolia paid-step test (success + replay failure + wrong-claims failure).

## Open decisions
- When to make strict policy mode default.
- Whether all settlement terms require policy hash or only selected offers.
- Whether to require separate signature over `policy.json` in addition to hash binding.
- Whether to tokenize entitlements as NFTs or keep them internal ids.
- Whether dispute mode pauses cap release immediately or only pauses payout.
- Migration timing for removing certificate-attested settlement and requiring `settlementClaims`-attested mode only.

## References
- Base network information: https://docs.base.org/network-information
- Base deploy guide (Foundry): https://docs.base.org/get-started/deploy-smart-contracts
- EIP-712 typed data signing: https://eips.ethereum.org/EIPS/eip-712
- ERC-1271 contract signature validation: https://eips.ethereum.org/EIPS/eip-1271
- GitHub artifact attestation docs: https://docs.github.com/actions/security-for-github-actions/using-artifact-attestations/using-artifact-attestations-to-establish-provenance-for-builds
- `actions/attest-build-provenance`: https://github.com/actions/attest-build-provenance
- GitHub OIDC overview: https://docs.github.com/actions/concepts/security/openid-connect
- GitHub OIDC token claims reference: https://docs.github.com/en/enterprise-cloud@latest/actions/reference/openid-connect-reference
- GitHub OIDC API gateway pattern: https://docs.github.com/en/actions/how-tos/using-github-hosted-runners/connecting-to-a-private-network/using-an-api-gateway-with-oidc
- `github-zktls/docs/trust-model.md`
- `github-zktls/contracts/src/ISigstoreVerifier.sol`
- `github-zktls/contracts/src/SigstoreVerifier.sol`
- `github-zktls/contracts/examples/SelfJudgingEscrow.sol`
- [[agent_swarm what to build now]]
- [[Conseca and agent_swarm]]
- [[agent_swarm github-zktls integration blueprint]]
- [[Main TODO]]
