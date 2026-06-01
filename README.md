# oxide2

[![pr](https://github.com/watkinslabs/oxide/actions/workflows/pr.yml/badge.svg?branch=main)](https://github.com/watkinslabs/oxide/actions/workflows/pr.yml)

**Oxide is a human-directed, AI-written, vibe-coded operating system in Rust**: Linux-class kernel + userspace, with strict engineering gates around specs, safety, testing, and workflow discipline.

It targets `x86_64-unknown-oxide-kernel` and `aarch64-unknown-oxide-kernel`, with userspace on upstream `*-unknown-linux-musl` (`docs/29a-userspace-platform.md`).

## What Oxide is

Oxide is not "just code that boots." It is a **spec-driven systems project** where behavior is defined in versioned contracts first, then implemented with enforcement in CI and local workflow.

Core identity:

- **Human-directed, AI-implemented:** design intent and acceptance criteria are human-owned; implementation can be AI-heavy.
- **Rust-first kernel engineering:** memory/concurrency/safety rules are explicit and reviewed against specs.
- **Linux-compat target surface:** syscall ABI and userspace expectations track modern Linux-class behavior.
- **Security + workflow as first-class:** hard guardrails prevent unsafe shortcuts from quietly entering `main`.

## Engineering contract

Oxide development is intentionally constrained:

- **Spec-before-code discipline** (`docs/02-spec-discipline.md`): subsystem behavior is contractual, traceable, and reviewed.
- **Manifest-governed scope** (`docs/MANIFEST.md`): every spec is indexed with status and dependencies.
- **Architecture lockstep**: x86_64 and aarch64 are phase gates, not optional follow-ups.
- **Guardrails in code style and review** (`docs/07-toolchain-and-targets.md`, `docs/08-ai-density.md`): no hand-wavy patterns, no silent drift from contract.
- **Testing depth over claims** (`docs/40-ci.md`, `docs/42-test-strategy.md`): unit, integration, hosted kernel tests, QEMU smoke, and CI gating.

## Current capability snapshot

Oxide currently includes major kernel/runtime surface across boot, memory, scheduling, syscall plumbing, process control, proc/dev/tty surfaces, cgroup enforcement work, and interactive shell bring-up in QEMU. The active handoff state and latest landed work are tracked in `state.md`.

For authoritative subsystem status, read `docs/MANIFEST.md` and the referenced spec docs.

## Quick start

```bash
make ci
cargo run -p xtask -- qemu --arch x86_64 --features debug-all
```

## Where to read first

- `docs/00-master-plan.md`
- `docs/MANIFEST.md`
- `docs/02-spec-discipline.md`
- `docs/07-toolchain-and-targets.md`
- `docs/08-ai-density.md`
- `docs/40-ci.md`
- `docs/42-test-strategy.md`
- `state.md`

## License

MIT
