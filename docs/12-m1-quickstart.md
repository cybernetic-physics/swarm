# M1 quickstart (local backend)

Status: current
Date: 2026-02-28

This quickstart exercises the implemented M1 local path:
- SQLite snapshot-based state transitions.
- deterministic local bundle generation.
- local launch/resume/fork/status/inspect commands.

All commands run from:

```bash
cd /Users/cuboniks/Projects/agent_swarm/swarm
```

## 1) Initialize

```bash
cargo run -p swarm-cli -- init --json
```

This creates:
- config at `~/.swarm/config.json`
- local engine root at `./.swarm/local`

## 2) Launch from root

```bash
cargo run -p swarm-cli -- run launch \
  --backend local \
  --node root \
  --run-id m1-launch \
  --allow-cold-start \
  --json
```

## 3) Resume from prior run node

```bash
cargo run -p swarm-cli -- run resume \
  --backend local \
  --node run:m1-launch \
  --run-id m1-resume \
  --allow-cold-start \
  --json
```

## 4) Fork a branch

```bash
cargo run -p swarm-cli -- run fork \
  --node run:m1-resume \
  --label exp-a \
  --json
```

## 5) Read run status

```bash
cargo run -p swarm-cli -- run status --run-id m1-resume --json
```

## 6) Inspect state snapshot metadata

Use the `state_id` returned by run status:

```bash
cargo run -p swarm-cli -- state inspect --state-id <STATE_ID> --json
```

## 7) Verify generated certificate

Use values returned by run status:
- `certificate_ref` -> local file path under `.swarm/local/runs/<run_id>/certificate.json`
- `artifact_hash`

```bash
cargo run -p swarm-cli -- verify cert \
  --certificate .swarm/local/runs/m1-resume/certificate.json \
  --expected-artifact-hash <ARTIFACT_HASH> \
  --required-commit local-dev-commit \
  --json
```

## Local artifacts layout

```text
.swarm/local/
  index.json
  nodes/*.json
  states/*.sqlite.enc
  states/*.meta.json
  bundles/*.tar
  runs/<run_id>/certificate.json
  runs/<run_id>/result.json
  runs/<run_id>/next_tokens.json
```

## Notes

- Current implementation is M1 local backend scope only.
- GitHub execution backend is still M2 work.
- Raw tokens are currently emitted in some local outputs for development; do not treat this as production-safe secret handling.
