# CLI specification (v0)

Status: draft
Date: 2026-02-28

## Design goals

- Human-friendly default UX.
- Stable machine output contract.
- Clear phase boundary (Phase 0/1 commands now, Phase 2+ placeholders only).
- No hidden mutable state assumptions.

## Proposed command tree

```text
swarm
  init
  doctor
  config show
  config set <key> <value>

  run launch
    --node <node_id|root>
    --backend <local|github>
    --workflow-ref <owner/repo/path@sha>
    --route-mode <direct|client_exit>
    --out <dir>

  run resume
    --node <node_id>
    --backend <local|github>
    --out <dir>

  run fork
    --node <node_id>
    --label <branch_label>

  run status
    --run-id <run_id>

  run logs
    --run-id <run_id>
    --follow

  state inspect
    --state-id <state_id>

  state fork
    --state-cap <token>

  verify cert
    --certificate <path>
    --attestation <path-or-ref>
    --required-commit <sha>

  verify proof
    --proof <path>
    --public-inputs <path>

  backend github dispatch
  backend github collect

  backend local execute

  schema validate
    --file <node|certificate|result>

  plan show
```

## Global flags

- `--json`: machine-readable output.
- `--quiet`: suppress progress noise.
- `--verbose`: include diagnostic context.
- `--profile <name>`: config profile selection.
- `--no-color`.

## Exit code policy

- `0`: success.
- `2`: invalid input/schema.
- `3`: verification failed.
- `4`: backend dispatch/collection failure.
- `5`: restore failure without allowed fallback.
- `6`: policy violation (net_cap/state_cap semantics).

## Config model

Default path: `~/.swarm/config.toml`

```toml
[identity]
operator_id = "did:key:..."
default_buyer_address = ""

[storage]
default_backend = "s3"
s3_bucket = ""
s3_region = "us-east-1"

[backends]
default_execution = "github"
workflow_ref = "owner/repo/.github/workflows/loom-paid-run.yml@<sha>"

[network]
default_route_mode = "direct"
require_fail_closed_for_client_exit = true

[output]
default_format = "human"
```

## Output contract

### Human mode
- concise progress lines.
- final summary section.

### JSON mode
Single object with stable keys:
- `run_id`
- `status`
- `restore_mode`
- `certificate_ref`
- `artifact_hash`
- `state_cap_next_ref`
- `net_cap_next_ref`
- `errors[]`

## Compatibility rule

Any breaking schema or CLI behavior change must increment:
- CLI protocol version.
- artifact schema version.
