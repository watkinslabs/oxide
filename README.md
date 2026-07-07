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

Oxide currently includes active kernel/runtime code across:

- x86_64 and aarch64 boot, HAL, traps, syscall entry, timers, MMU, IRQ, and context switching.
- PMM, VMM, slab/kalloc, user address spaces, mmap/fault/COW/rmap paths, and memory smoke/torture tests.
- Scheduler/process code for tasks, clone/fork/exec/wait/exit, process groups, sessions, signals, timers, rlimits, pidfd, futexes, and syscall return handling.
- Linux syscall routing through `crates/kernel/syscalls`, with hundreds of numbered handlers wired into subsystem code.
- VFS, fd tables, dcache/namei, mounts, ext4, tmpfs, devfs, devpts, procfs, sysfs, kernfs, and tracefs.
- Block registry/page cache plus virtio-blk, NVMe, AHCI, PCI, virtio transport, virtio-net/gpu/input/rng/vsock/snd, serial UARTs, PS/2 keyboard, DRM/fbdev/fbcon, VT, and sound/OSS/PCM code.
- Networking for loopback/virtio-net, IPv4/IPv6, ARP/NDP, ICMP, UDP/TCP, AF_UNIX, AF_PACKET, vsock, rtnetlink, sock_diag, and netfilter/nft pieces.
- TTY/PTY/console, virtual terminals, framebuffer console, serial tty, and `/dev/console` routing.
- cgroup v2, namespace pieces, capabilities/creds, seccomp, BPF/cBPF paths, Landlock, and LSM self-attr syscall paths.
- Loadable-module infrastructure, symbol/relocation support, and a partial Linux KPI surface for alloc/device/chrdev/block/DMA/IRQ/PCI/netdev/input/firmware/crypto/sync/time/PM/platform/USB/usercopy.
- Rust glibc-ABI userspace, dynamic-loader pieces, startup objects, NSS/PAM helpers, service-unit parsing/supervision, RPM/package readers, and folded-library shims.

Not done / not Linux-complete:

- One declared syscall constant, `NR_LISTNS`/470, is not actively referenced by the kernel syscall routes.
- The active syscall router still falls back to an older low-level dispatch table containing v1 fallback stubs; syscall semantic completeness needs a generated code audit.
- SMP, CPU hotplug, NUMA policy, swap, full overcommit behavior, async block IO/writeback, and full page-cache waiter/locking depth are incomplete.
- Linux filesystem coverage is narrow: ext4/tmpfs/pseudo filesystems exist, but not XFS, Btrfs, NFS, overlayfs, squashfs, ISO9660, FAT/exFAT, 9p, or full FUSE integration.
- Driver coverage is not Linux hardware complete: no broad USB host/HID/storage stack, Wi-Fi, Bluetooth, vendor GPU drivers, ACPI battery/thermal, or broad NIC/storage matrix.
- Linux KPI/module loading is partial: signature/CRC/vermagic enforcement, W^X module memory, init/exit execution, threaded IRQ depth, and wider driver API coverage remain.
- Networking needs raw socket, conntrack/NAT, nftables depth, IPv6 edge cases, route/rule parity, diagnostics/counters, and packet-socket conformance work.
- glibc/userspace, udev/systemd compatibility, package management, service supervision, BPF/perf/userfaultfd/io_uring, and security/LSM depth remain incomplete.

For the full code-scan status and next implementation list, read [`oxide_status.md`](oxide_status.md). The active handoff state and latest landed work are tracked in `state.md`.

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
