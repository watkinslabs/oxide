# oxide2

[![pr](https://github.com/watkinslabs/oxide/actions/workflows/pr.yml/badge.svg?branch=main)](https://github.com/watkinslabs/oxide/actions/workflows/pr.yml)

A Linux-class kernel + minimal userspace, written in Rust.

Targets `x86_64-unknown-oxide-kernel` and `aarch64-unknown-oxide-kernel`. Userspace built for upstream `*-unknown-linux-musl` (per `docs/29a`). Linux-binary-compatible at the modern syscall ABI: `uname.sysname` reports `Linux`, `release` reports `5.15.0-oxide`.

## Status

Phase 3 (M2) substantially done. Both arches boot Limine → `kernel_main`, run a multi-iteration init-loop in user mode (`fork`/`execve`/`wait4`), and pass an extensive boot-time smoke battery before halting cleanly.

What works:

- **Boot:** ACPI parse → PMM (buddy) → demand-paged VMM → LAPIC/GIC → real timer IRQs → cooperative scheduler with IRQ-exit preempt → user-as activation → ELF static-PIE loader (DT_RELA self-relocs, real auxv, AT_PHDR/PHENT/PHNUM/PAGESZ/RANDOM/ENTRY).
- **Userspace:** init blob runs five iterations (`yo` / `hi` / `echo` / `cat` / `pty`-stubbed). `fork` does real per-page COW. `execve` activates a fresh AS, builds the SysV stack, snapshots argv/envp into per-task slots. `wait4` reaps with `WNOHANG` support.
- **Syscalls:** ~280 slots wired across `syscall_glue.rs` real impls + per-arch `glue_fs/proc/time/ioctl/xfer.rs` helpers + a compat tail. Linux ABI surface coverage substantially complete for libc/shell startup probes.
- **Signals:** Real `rt_sigaction` storage; `sa_handler` dispatch with kernel-built signal frame + sa_restorer / `rt_sigreturn`. SIGSTOP / SIGCONT scheduler hooks. SIGCHLD on Zombie. `kill(-pgid)` POSIX semantics.
- **Per-task state:** real `pgid` / `sid` / `cwd` / `cmdline` / `environ` slots; fork inherits all per POSIX. tid → Weak<Task> registry powers `/proc/<pid>/*` and `kill -pgid`.
- **PTY:** Full `/dev/ptmx` factory + `/dev/pts/<n>` registration. 60-byte Linux `struct termios` round-trips through `TCGETS`/`TCSETS`. Cooked-mode line discipline: `ICANON`/`ECHO`/`ISIG`/`OPOST`/`ONLCR`/`OCRNL`/`ICRNL`/`INLCR`/`IGNCR`/`IXON`. All 17 `c_cc` indices defined; `VINTR`/`VQUIT`/`VSUSP` post `SIGINT`/`SIGQUIT`/`SIGTSTP` to the foreground pgrp; `VEOF` (^D) returns EOF on `slave_read`; `VERASE` / `VKILL` line editing with destructive `\b \b` echo. Blocking master + slave reads.
- **Procfs:** 80+ paths. Dynamic `/proc/uptime` (monotonic_ns), `/proc/meminfo` (live PMM stats), `/proc/loadavg` (live tids), full per-pid surface (`status` / `cmdline` / `stat` / `maps` / `comm` / `environ` / `statm` / `fd/<n>` symlinks / `sched` / `wchan` / `oom_score` / `limits` / `personality`). Rich `/proc/cpuinfo`. Writable `/proc/sys/kernel/hostname`. /proc/sys sysctl tree (~30 files).
- **Devfs / etc:** `/dev/{null,zero,full,random,urandom,console,tty[0-6],ttyS0,ptmx,pts/*}`, `/etc/{passwd,group,shadow,shells,profile,issue,motd,hosts,services,protocols,ld.so.{cache,conf},nsswitch.conf,timezone,os-release,machine-id}`. Synthetic directory inodes over the flat path registry — `getdents64` enumerates `/`, `/dev`, `/etc`, `/bin`, `/usr`, `/usr/bin`, `/proc`, `/proc/sys`.
- **Tmpfs:** `/tmp/<name>` create-on-write via `O_CREAT`; `O_TRUNC` and `ftruncate` honored.

Not yet running:

- **musl libc binaries:** A statically linked musl helloworld faults at `__libc_start_main_stage1` with an NX violation jumping to user-stack region. Needs source-level gdb stepping to bisect.
- **Real disk I/O / on-disk filesystem:** v1 has no block layer past the spec.
- **Networking:** v1 has no socket implementation past ENOSYS.
- **SMP:** UP only.

44 of 46 spec docs FROZEN; **614 hosted unit tests pass**; CI runs `make ci` (lint + workspace tests + both arches default + `--features debug-all`) on every PR.

For the live snapshot see `state.md`. For the per-session history see `CHANGELOG.md`.

## Quick start

```
make ci             # full PR gate locally: lint + test + build + build-debug
make qemu-x86       # boot the kernel under QEMU on x86_64 with all debug features
make qemu-arm       # same on aarch64
make help           # list all make targets
```

Boot trace highlights (x86_64 `make qemu-x86`):

```
[INFO]  pmm: 171 MiB free, 0 page(s) reserved
[INFO]  kalloc-smoke: VmaTree insert ok
[INFO]  ksched: starting RR with 4 kthreads
[INFO]  dev-misc-smoke: ok
[INFO]  procfs-smoke: ok
[INFO]  pipe-evt-smoke: ok
[INFO]  tmpfs-smoke: ok
[INFO]  pty-sigint-chain: ok
[INFO]  pty-termios-winsize: ok
[INFO]  pty-smoke: ok
[INFO]  exec-path-smoke: ok
yo
hi
A
oxide 0.1.0-pre #1 SMP PREEMPT
[INFO]  elf-smoke: user task exited cleanly, boot resumed
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
