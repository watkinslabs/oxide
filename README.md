# oxide2

[![pr](https://github.com/watkinslabs/oxide/actions/workflows/pr.yml/badge.svg?branch=main)](https://github.com/watkinslabs/oxide/actions/workflows/pr.yml)

A Linux-class kernel + minimal userspace, written in Rust.

Targets `x86_64-unknown-oxide-kernel` and `aarch64-unknown-oxide-kernel`. Userspace built for upstream `*-unknown-linux-musl` (per `docs/29a`). Linux-binary-compatible at the modern syscall ABI.

## Status

Phase 1 substantially done. Both arches boot Limine → `kernel_main`, parse ACPI, bring up PMM, splice kernel-device MMIO via the PMM-backed page-table walker, enable LAPIC (x86) / GIC (arm), take real timer IRQs, run a 4-kthread preempt smoke driven by true IRQ-exit context-switching, and pass a 64-task ctxsw register-canary every boot. The `MmuOps` trait surface (`map`/`translate`/`unmap` for 4 KiB and 2 MiB leaves; `flush_va`/`flush_all_local` arch-native) is exercised end-to-end on every boot.

44 of 46 spec docs FROZEN; 478 hosted unit tests pass; CI runs `make ci` (lint + workspace tests + both arches default + `--features debug-all`) on every PR.

For the live snapshot see `state.md`. For the per-session history see `CHANGELOG.md`.

## Quick start

```
make ci             # full PR gate locally: lint + test + build + build-debug
make qemu-x86       # boot the kernel under QEMU on x86_64 with all debug features
make qemu-arm       # same on aarch64
make help           # list all make targets
```

## Where to start

- `docs/00-master-plan.md` — top-level plan, phases, exit criteria.
- `docs/MANIFEST.md` — index of every spec.
- `docs/02-spec-discipline.md` — how specs evolve.
- `docs/03-modernity.md` — what's in v1 / what's deferred.
- `state.md` — current snapshot (read first when picking up work).
- `CHANGELOG.md` — per-session history of what landed on `main`.
- `CLAUDE.md` — project rules for Claude Code sessions.

## License

MIT
