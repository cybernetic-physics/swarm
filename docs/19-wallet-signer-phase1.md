# Wallet Signer Module (Phase 1)

Status: implemented
Date: 2026-03-02

## Purpose

This document describes the signer-first wallet module added to `swarm-cli`.

Scope is intentionally narrow:
- Build a reusable signer module.
- Expose wallet commands needed for Phase 1.
- Keep key custody local and pluggable.
- Avoid building a full wallet product UX.

## Why this was added now

M4 and later settlement work (Base Sepolia path) needs:
- deterministic signer identity (`address`),
- read-path chain connectivity (`balance`),
- write-path transaction submission (`send`),
- and safe local secret handling.

The new module provides exactly those primitives while keeping future signer backends open.

## Implemented command surface

New top-level tree in `swarm`:

```text
swarm wallet import private-key
swarm wallet import mnemonic
swarm wallet import keystore
swarm wallet address
swarm wallet balance
swarm wallet send
```

### Command details

1. `wallet import private-key`
- Inputs:
  - `--alias <name>` optional (defaults to `default`)
  - `--private-key <hex>` optional (prompted with hidden input when omitted)
  - `--set-default` optional
- Behavior:
  - derives address from private key,
  - writes secret to OS keychain,
  - writes metadata (alias/backend/address/keyring account) to local registry.

2. `wallet import mnemonic`
- Inputs:
  - `--alias <name>` optional
  - `--mnemonic "<words>"` optional (hidden prompt when omitted)
  - `--set-default` optional
- Behavior:
  - derives signer from BIP-39 mnemonic,
  - stores mnemonic in OS keychain,
  - stores metadata in registry.

3. `wallet import keystore`
- Inputs:
  - `--alias <name>` optional
  - `--keystore <path>` required
  - `--password <value>` optional (hidden prompt when omitted)
  - `--set-default` optional
- Behavior:
  - reads JSON keystore payload,
  - verifies decryptability (password prompt when needed),
  - stores keystore JSON in OS keychain,
  - stores metadata in registry.

4. `wallet address`
- Inputs:
  - `--alias <name>` optional (falls back to default alias)
- Behavior:
  - loads signer metadata,
  - loads secret from keychain,
  - re-derives signer/address to verify integrity,
  - prints canonical `0x...` address and signer metadata.

5. `wallet balance`
- Inputs:
  - `--alias <name>` optional
  - `--rpc-url <url>` defaults to `https://sepolia.base.org`
  - `--chain-id <u64>` defaults to `84532`
- Behavior:
  - resolves address from signer,
  - reads balance via Alloy provider,
  - verifies RPC chain id equals expected chain id,
  - returns wei balance as decimal string.

6. `wallet send`
- Inputs:
  - `--alias <name>` optional
  - `--rpc-url <url>` defaults to `https://sepolia.base.org`
  - `--chain-id <u64>` defaults to `84532`
  - `--to <0x...>` required
  - `--value-wei <uint256>` required
- Behavior:
  - resolves local signer,
  - creates Alloy `EthereumWallet`,
  - submits transaction through configured RPC,
  - verifies expected chain id before returning success,
  - returns tx hash.

## Storage and secret handling model

Design principle: no private material in plaintext config files.

### 1) Metadata registry (non-secret)

File path:
- `~/.swarm/wallet_signers.json`

Stored fields:
- `default_alias`
- signer entries:
  - `alias`
  - `backend` (`private_key|mnemonic|keystore`)
  - `address`
  - `keyring_account`

No private key, mnemonic phrase, or keystore password is written here.

### 2) Secret store (OS keychain)

Backend:
- `keyring` crate (`service = "swarm-cli.wallet"`)

Key format:
- account key: `signer.<alias>`

Stored secret payload per backend:
- private-key backend: raw private key hex string
- mnemonic backend: mnemonic phrase string
- keystore backend: encrypted keystore JSON payload

For keystore use:
- keystore password is not persisted.
- password is requested at runtime for decrypt/usage.

### 3) Memory handling

In-memory sensitive values are wrapped with:
- `secrecy::SecretString`

CLI prompt behavior:
- hidden prompt via `rpassword` when values are omitted from flags.

## Module architecture

Primary file:
- `swarm-cli/src/signer.rs`

Core public operations:
- `import_private_key`
- `import_mnemonic`
- `import_keystore`
- `wallet_address`
- `wallet_balance`
- `wallet_send`

Internal model:
- `SignerBackendKind`
- `StoredSignerRecord`
- `SignerRegistry`
- `LoadedSigner`

Execution style:
- wallet methods are synchronous from CLI perspective.
- async Alloy provider calls are executed via a local Tokio runtime wrapper.

## Pluggability design

The module is backend-driven by `SignerBackendKind` and a single load path that maps backend kind to signer material reconstruction.

Current backends:
- local private key
- local mnemonic
- local keystore JSON

Intended future extension:
- KMS signer backend (metadata + key handle, no local secret)
- hardware signer backend (device locator, remote sign operation)

Because command layer calls module-level abstractions (instead of directly parsing key material in `main.rs`), backend expansion can be added without command-tree rewrite.

## Base Sepolia defaults

Baked defaults in module constants:
- RPC URL: `https://sepolia.base.org`
- Chain ID: `84532`

All read/write commands that hit RPC enforce explicit chain-id agreement:
- if RPC returns unexpected chain id, command errors with `WALLET_CHAIN_MISMATCH`.

This prevents accidental signing/submission on the wrong network when users point at unexpected RPC endpoints.

## Error and exit-code behavior

Wallet path emits prefixed errors for stable classification:
- `WALLET_SIGNER_NOT_FOUND`
- `WALLET_CHAIN_MISMATCH`
- `WALLET_ADDRESS_MISMATCH`

CLI exit-code mapping update:
- `WALLET_*` errors map to exit code `2` (invalid input/policy mismatch class).

JSON mode preserves standard shape:
- `status`
- `code`
- `message`

## Dependency choices and compatibility

Selected stack:
- `alloy = 0.11.1` (pinned)
- `alloy-signer-local = 0.11.1` with `mnemonic` and `keystore` features
- `keyring`
- `secrecy`
- `rpassword`
- `tokio`

MSRV/workspace constraint:
- workspace remains `rust-version = "1.85"`
- dependencies were selected and pinned to compile with Rust 1.85 in this workspace.

Notable compatibility pin:
- `serde` pinned to `1.0.217` to avoid API compatibility break with this Alloy line.

## Security boundaries and tradeoffs

What this improves:
- removes plaintext secret persistence from repo/workspace config files,
- centralizes sensitive handling in one module,
- enforces chain-id checks for network safety.

What this does not solve:
- no hardware enclave-backed signing yet,
- no key rotation workflow yet,
- no multi-account policy/ACL model yet,
- no passphrase caching/agent process yet.

Keystore caveat:
- keystore JSON is stored in keychain; password is prompt-only at use time.
- this keeps decryption control with user input but may be less convenient for automation.

## Test and verification summary

Completed:
- `cargo +1.85.0 check -p swarm-cli` passed
- `cargo test -p swarm-cli` passed (40 tests)
- help-path checks for wallet commands confirmed expected flags/defaults
- JSON error-path smoke for missing signer confirmed `WALLET_SIGNER_NOT_FOUND` and exit code `2`

Known limitation during Rust 1.85 full test build:
- `cargo +1.85.0 test -p swarm-cli` compiles dev-dependency `swarm-proxy`, which currently has a pre-existing unstable `let`-chain pattern on Rust 1.85.
- This issue is outside the new wallet/signer module and predates these changes.

## Files added/changed for this feature

Primary implementation:
- `swarm-cli/src/signer.rs` (new)
- `swarm-cli/src/main.rs` (wallet command tree + execution + exit mapping)

Dependency/config:
- `Cargo.toml`
- `swarm-cli/Cargo.toml`
- `Cargo.lock`

Docs:
- `docs/03-cli-spec.md`
- `README.md`
- `docs/19-wallet-signer-phase1.md` (this document)

## Example workflows

### A) Import private key and inspect address

```bash
swarm wallet import private-key --alias buyer --set-default
swarm wallet address --alias buyer
```

### B) Import mnemonic and check Base Sepolia balance

```bash
swarm wallet import mnemonic --alias settlement
swarm wallet balance --alias settlement --rpc-url https://sepolia.base.org --chain-id 84532
```

### C) Import keystore and send transaction

```bash
swarm wallet import keystore --alias payout --keystore /path/to/keystore.json
swarm wallet send --alias payout --to 0x0123456789abcdef0123456789abcdef01234567 --value-wei 1000000000000000 --rpc-url https://sepolia.base.org --chain-id 84532
```

## Forward plan

Recommended next implementation slices:
1. Add `wallet sign` for typed data / raw message signing.
2. Add signer backend traits for non-local signers (KMS/hardware).
3. Add alias management commands (`wallet list`, `wallet set-default`, `wallet remove`).
4. Add optional per-network profiles and RPC config in `~/.swarm/config.json`.
5. Add integration tests with local Anvil for deterministic send/balance test coverage.
