# 43 Acceptance Criteria

FROZEN 2026-05-02. Dep:every spec above.

## Revision 2026-05-14 (R06)

- Deleted: v1/v2/v2.x split. Per `00§9` every Linux subsystem is in scope; there is no parking lot. Single acceptance set, ordered as a smoke-first staircase.
- Binaries previously labeled "v2" (Go/Rust+tokio/redis/nginx/openssh/chrony) and "v2.x" (systemd/Wayland/Docker/KVM) are listed under their gating phase. Each becomes a hard tag-gate as that phase lands; none are deferred.

## 1 Purpose

Enumerate the binary-level acceptance tests. Each binary listed is the *contract*: if a stock build from upstream against our libc/syscall ABI fails to run, the gating phase is not done.

## 2 Smoke tier — busybox

Linked against our static musl. Smoke target is the first thing
acceptance fires.

| Binary | Why | Tests covered |
|---|---|---|
| `busybox sh` | basic shell | tty, pipe, signals, fork+exec |
| `busybox ls/cat/echo/cp/mv/rm/mkdir/...` | core fs ops | VFS, file I/O, dir |
| `busybox ps/top/uptime/free` | proc/sys reads | `/proc`, `/sys` |
| `busybox dmesg` | log access | `/dev/kmsg` |
| `busybox mount/umount` | mount API | `16`,`19` |

PR-time smoke: `busybox sh -c 'echo hello | wc -c'` returns `6\n`
end-to-end (boot → execve sh → pipe → wc → exit) plus the 6 user
smokes (sem/msg/mq/ptrace/mprotect/dyn).

## 3 Dynamic-userspace tier (gates: phases 27-31)

Adds dynamic linking + libc-with-NSS-PAM + a real PID 1 + agetty.

| Binary | Why | Adds |
|---|---|---|
| Statically-linked Go ≥1.22 (hello + goroutines + channels + http server) | Go runtime exercises clone3, futex, epoll, mmap, tgkill | sched, ipc, vmm |
| Statically-linked Rust + `tokio` | tokio uses epoll/futex/clone3 | same coverage |
| `redis 7` against our musl | event loop, AF_UNIX, TCP | net, ipc |
| `nginx` w/o io_uring | server, signals, pidfile | net, fs, signals |
| `nginx` with `aio threads io_uring;` | io_uring | phase 22 enabled |
| `openssh-server 9.x` | PTY, modern crypto, rlimits | tty, pty, security, net |
| `chrony` / `ntpd` | clock_adjtime, rt_sigtimedwait | time, signals |
| `runc` w/ privileged OCI bundle | container runtime | namespaces + cgroup + seccomp + landlock |
| `bpftrace` simple probe | BPF subset | verifier+loader+kprobe |
| `perf record/report` | PMU sampling | phase 25 |
| `cri-o` or `containerd` minimal | container daemon | runc + extras |

## 4 Distro tier (gates: phases 32-41)

| Binary | Adds |
|---|---|
| `systemd ≥ 254` as PID 1 | full init system — sd_notify, journald protocol, cgroup BPF, ~150 syscalls |
| GUI app on Wayland (`weston` + `weston-terminal`) | full graphics + audio + USB stacks (phases 32, 34, 40) |
| Docker (full Moby) | container ecosystem |
| KVM with QEMU userspace | KVM backend (phase 36) |

## 5 Per-binary test plan

For each acceptance binary:
1. Build from source against our toolchain into the rootfs image.
2. `xtask qemu` boot.
3. Run a scripted scenario (e.g., `busybox ls /; busybox cat /proc/cpuinfo > /tmp/c; busybox grep -c processor /tmp/c`).
4. Capture serial; assert expected substrings.
5. Daemons run end-to-end (start, accept connection, serve test request, clean shutdown) — no duration-based stress.

Stored as `tests/acceptance/<binary>/scenario.sh` + `expected.txt`.

## 6 Release-tag criterion

Per `00§15`. Restated:

- PR-time CI green on the tagged commit, both arches.
- Every acceptance binary whose gating phase is done runs end-to-end on QEMU (boots → exec binary → expected output → clean exit).
- Zero panics, zero oopses across the acceptance run; SHA-256 reconciles on any fs corpus the scenario writes.
- Kernel-completeness audit `docs/kernel-audit.md` shows no stub regressions vs the previous tag.
- All FROZEN specs have their Test Contract green.
- Coverage gates met per `42§10`.

## 7 Failure modes

If acceptance fails for a binary:
- Open question logged in the binary's `tests/acceptance/<bin>/known-issues.md`.
- Fix the kernel. There is no "move to a later acceptance tier" escape hatch.
- Never: silently move pass criterion.

## 8 Cross-spec

Each spec from `10` upward; `00§15` exit criterion; `40` (CI runs acceptance scripts).
