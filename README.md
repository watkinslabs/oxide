# oxide2

[![pr](https://github.com/watkinslabs/oxide/actions/workflows/pr.yml/badge.svg?branch=main)](https://github.com/watkinslabs/oxide/actions/workflows/pr.yml)

A Linux-class kernel + minimal userspace, written in Rust.

Targets `x86_64-unknown-oxide-kernel` and `aarch64-unknown-oxide-kernel`. Userspace built for upstream `*-unknown-linux-musl` (per `docs/29a`). Linux-binary-compatible at the modern syscall ABI: `uname.sysname` reports `Linux`, `release` reports `5.15.0-oxide`.

## Status

Phases 0–6 (read-driver layer) closed per `00§3` master-plan ladder. Both arches boot Limine → `kernel_main`. SMP brings up multi-CPU at `-smp 4` (cross-CPU IPI + load balancer verified). A real-musl static-PIE shell runs as PID 1 — you can type at it and it executes builtins against the kernel's filesystem.

### Run an interactive shell

```
cargo run -p xtask -- qemu --arch x86_64 --features debug-all
```

Boot scrolls through ACPI / PMM / VMM / sched / smoke output, then drops to:

```
oxide-sh: builtins exit / echo / help / ls / cat / pwd
oxide$
```

Type past the canned smoke (`ls /proc`, `cat /proc/version`, `exit`) — once the smoke completes the prompt is yours. Builtins:

| | |
|---|---|
| `ls [path]`     | openat(O_DIRECTORY) + getdents64 — works on `/`, `/proc`, `/dev`, `/etc`, etc. |
| `cat <path>`    | read + write to stdout — works on `/proc/version`, `/proc/cpuinfo`, `/etc/passwd`, … |
| `echo <args>`   | write args back |
| `pwd`           | prints `/` (no real cwd yet) |
| `help`, `exit`  | what they look like |

To leave QEMU: `Ctrl-A x`.

### What works

- **Boot:** ACPI parse → PMM (buddy) → demand-paged VMM → LAPIC/GIC → real timer IRQs → preemptive scheduler → user-as activation → ELF static-PIE loader (DT_RELA self-relocs, real auxv).
- **SMP:** Limine MP request → AP startup → per-CPU runqueue + IDTR + LAPIC + sti+hlt idle → cross-CPU resched IPI (vec 0x41) → load balancer migrates CFS tasks. Verified at `-smp 4`: `cpus=4 aps_started=3 resched_ipis_received=3 migrated_total=2`.
- **Userspace:** Real-musl static-PIE binaries run as PID 1. Hand-rolled orchestrator init exec's `yo`/`hi`/`echo`/`cat` then the real-musl `oxide-sh` takes over.
- **Syscalls:** ~280 slots wired (read/write/openat/close/getdents64/exit/fork/execve/wait4/clock_*/etc).
- **Signals:** `rt_sigaction`, `sa_handler` dispatch + signal frame + `rt_sigreturn`, SIGSTOP/SIGCONT scheduler hooks, `kill(-pgid)` POSIX semantics.
- **Procfs:** 80+ paths (status / cmdline / stat / maps / cpuinfo / version / uptime / meminfo / loadavg, full per-pid surface, /proc/sys sysctl tree).
- **Devfs / etc:** /dev/{null,zero,console,tty*,ptmx,pts/*}, /etc/{passwd,group,issue,os-release,…}.
- **PTY:** /dev/ptmx + /dev/pts/<n>, full termios round-trip, cooked-mode line discipline (ICANON / ECHO / ISIG / Erase / Kill / EOF).
- **Tmpfs:** `/tmp/<name>` create-on-write.
- **ext4 RO** (crate-level): superblock + GDT + inode + extent + dir + Mount, 45 hosted tests against a real `mke2fs`-built image.

### Not yet

- **busybox / login / getty:** the in-kernel shell is the only userspace binary today. Real busybox ships once the userspace build pipeline lands.
- **Real disk I/O:** ext4 RO crate works against a memory-backed image; no boot-disk integration yet (Limine module / virtio-blk). Phase 6 final mile.
- **ext4 RW + JBD2:** Phase 7b, not started.
- **Networking:** Phase 8, ENOSYS.
- **Hardening / observability / modules:** Phase 9, ongoing.

### Status numbers

44 of 46 spec docs FROZEN; **45 ext4 + 60+ sched + 100+ kernel hosted tests pass**; CI runs lint + tests + both arches default + `--features debug-all` on every PR.

For the live snapshot see `state.md`. For per-session history see `CHANGELOG.md`.

## Quick start

```
make ci                                                       # full PR gate
cargo run -p xtask -- qemu --arch x86_64 --features debug-all # interactive shell
cargo run -p xtask -- qemu --arch x86_64 --smp 4 --features debug-all  # multi-CPU
make help                                                     # all make targets
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
