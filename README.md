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
- TTY/PTY/console, virtual terminals, framebuffer console, serial tty, `/dev/console` routing, and enough DRM render-node publication for `/dev/dri/card*` + `/dev/dri/renderD*` smoke coverage.
- cgroup v2, namespace pieces, capabilities/creds, seccomp, BPF/cBPF paths, Landlock, and LSM self-attr syscall paths.
- Firmware identity through ACPI plus SMBIOS/DMI sysfs identity needed by systemd virtualization detection.
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

## Current priority plan

The immediate project goal is not generic feature growth; it is reaching a reliable graphical GNOME boot on the integrated `main` tree, then tightening the Linux-compat surface exposed by that boot.

| Priority | Work | Why it is first |
|---|---|---|
| P0 | Make graphical boot observable over serial: enable a serial getty or equivalent journal extraction path for the live GNOME image. | Current gdm failures hide decisive errors in the journal; without this, boot debugging devolves into slow hypothesis loops. |
| P1 | Stabilize the boot harness: one fresh integrated artifact path, exclusive QEMU runs, explicit image directory, and a smoke target for "reached gdm / reached greeter / failed with journal excerpt". | Recent work proved stale artifacts and mismatched image roots can invalidate results. |
| P2 | Pin the current gdm greeter hang: capture `journalctl -u gdm -b`, task state, and the last VT/DRM/logind/D-Bus operation before the session wrapper receives SIGTERM. | The last known blocker is the greeter session wrapper hanging before `gnome-shell` starts, not a kernel fault or SIGSEGV. |
| P3 | Complete the VT/DRM/logind contract needed by gdm: DRM master/auth ioctls, render node permissions, VT activation/KD mode behavior, seat device access, and session handoff semantics. | This is the highest-probability contract surface between a booting systemd stack and a visible graphical login. |
| P4 | Finish userspace readiness around systemd: udev device events, D-Bus/polkit/logind latency, PAM/NSS paths, tmpfiles/sysusers side effects, and service failure diagnostics. | GNOME depends on these daemons behaving like Linux, not just starting. |
| P5 | Repair known boot reliability defects before broad feature work: intermittent early wedge, stale-artifact risk, serial-vs-framebuffer ambiguity, and missing boot-result classification. | A reliable boot loop is the multiplier for every later fix. |
| P6 | Run generated syscall and UAPI audits after GNOME reaches greeter: remove old fallback stubs, prove declared syscall constants are routed, and rank remaining Linux-compat gaps by real userspace demand. | Once the graphical path is observable, syscall work should be driven by actual failing programs and generated coverage. |
| P7 | Continue broad Linux parity in dependency order: io_uring, userfaultfd, perf/BPF depth, module hardening, USB/HID/storage, Wi-Fi/Bluetooth, ACPI runtime, filesystems, and package-management depth. | These matter, but they do not outrank the current boot-to-GNOME path. |

Near-term working rule: each fix should include a hosted/unit proof where possible and a single boot-facing proof when it touches runtime behavior. Do not use repeated cold boots as the inner loop; add targeted probes or serial/journal extraction first.

The active handoff state is tracked in `state.md`; recent merged work is best read from `git log --oneline --decorate -40`.

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
