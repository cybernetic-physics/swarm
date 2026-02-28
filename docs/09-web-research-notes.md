# Web research notes

Status: draft
Date: 2026-02-28

These references were used to ground the `swarm` planning docs in current primary documentation.

## CLI and Rust

- clap derive tutorial:
  - https://docs.rs/clap/latest/clap/_derive/_tutorial/
- clap Parser trait docs:
  - https://docs.rs/clap/latest/clap/trait.Parser.html

Implication:
- use a strongly-typed clap subcommand tree similar to `popcorn-cli`, but with explicit versioned contracts and machine-output mode.

## GitHub execution and trust

- Workflow syntax:
  - https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions
- Workflow dispatch API:
  - https://docs.github.com/en/rest/actions/workflows#create-a-workflow-dispatch-event
- Actions limits:
  - https://docs.github.com/en/actions/reference/usage-limits-for-self-hosted-runners
- Artifact attestations:
  - https://docs.github.com/en/actions/concepts/workflows-and-actions/artifact-attestations
- New non-zipped artifact support (2026-02-26):
  - https://github.blog/changelog/2026-02-26-github-actions-now-supports-uploading-and-downloading-non-zipped-artifacts/

Implication:
- model GitHub as bounded job episodes with explicit dispatch/collect contracts and attested small artifacts.

## GitLab backend parity

- Pipeline triggers:
  - https://docs.gitlab.com/ci/triggers/
- Job artifacts:
  - https://docs.gitlab.com/ci/jobs/job_artifacts/

Implication:
- design GitLab adapter to mirror the same artifact and token contracts used by GitHub backend.

## Checkpointing and state continuity

- Docker checkpoint:
  - https://docs.docker.com/reference/cli/docker/checkpoint/
- Docker checkpoint create:
  - https://docs.docker.com/reference/cli/docker/checkpoint/create/
- Docker container start:
  - https://docs.docker.com/reference/cli/docker/container/start/
- SQLite serialize:
  - https://www.sqlite.org/c3ref/serialize.html
- SQLite deserialize:
  - https://www.sqlite.org/c3ref/deserialize.html

Implication:
- runtime checkpoint restore remains best-effort; serialized SQLite state continuity is the reliable substrate-independent path.

## Local project references

- popcorn-cli source baseline:
  - https://github.com/gpu-mode/popcorn-cli
- kernelbot launcher architecture:
  - https://github.com/gpu-mode/kernelbot

Implication:
- reuse proven CLI -> control plane -> workflow -> artifact flow, but swap in attested branch/capability contracts.
