# 43 Acceptance Criteria

FROZEN 2026-05-02. Dep:every spec above.

## Revision 2026-05-08 (R05)

- Changed: §2 v1 must-run shrinks to **busybox-only**. The Go/Rust/redis/nginx/openssh-server/chrony entries move to the v2 must-run table (§3) where they fit — those binaries need a real ld.so loader (DT_NEEDED + GOT/PLT), libc-with-NSS-PAM, and a system manager, all of which are explicitly v2 phases 33-35 per `00§3.2`. Putting them in the v1 gate created an impossible bind: v1 = "kernel substrate + minimum userspace" per `00§3.1`, but the v1 acceptance list demanded a Fedora-class smoke set that requires that v2 substrate to exist.
- Why: the listed Go/Rust/server binaries gate on userspace platform pieces v1 deliberately doesn't ship. The kernel could be feature-complete and still fail v1 acceptance because (e.g.) `ld-musl-*.so.1` doesn't load DT_NEEDED — which is a userspace-platform problem, not a kernel one. Splitting the lists makes each milestone gate on what its own scope can actually deliver.
- v1 contract is now: kernel boots, mounts ext4 RW, runs busybox sh + utils, /proc + /sys readable, /dev/console line-discipline works (Ctrl-C → SIGINT, ICANON line-buffer, ECHO toggle). That matches the v1 substrate from `00§3.1`.
- Affected docs: §2 below; §3 v2 list grows to absorb the moved entries (Go, Rust+tokio, redis, nginx-no-io_uring, openssh-server, chrony).
- Test contract change: PR-time CI smoke-target is now "busybox sh -c 'echo hello | wc -c'" + the existing 6 user smokes; the heavy distro-binary matrix promotes to v2.

## 1 Purpose

Enumerate the binary-level acceptance tests for v1, v2, v2.x milestones. Each binary listed is the *contract*: if a stock build of it from upstream against our libc/syscall ABI fails to run, the milestone is not done.

## 2 v1 must-run (frozen, R05)

v1 = kernel substrate + minimum userspace per `00§3.1`. The
acceptance set is **busybox-only**: every binary here links against
our static musl, no shared-library loader required, no init system
beyond a hand-rolled PID 1.

| Binary | Source | Why | Tests covered |
|---|---|---|---|
| `busybox sh` | upstream busybox built against our static musl | basic shell | tty, pipe, signals, fork+exec |
| `busybox ls/cat/echo/cp/mv/rm/mkdir/...` | same | core fs ops | VFS, file I/O, dir |
| `busybox ps/top/uptime/free` | same | proc/sys reads | `/proc`, `/sys` |
| `busybox dmesg` | same | log access | `/dev/kmsg` |
| `busybox mount/umount` | same | mount API | `16`,`19` |

v1 PR-time CI smoke target: `busybox sh -c 'echo hello | wc -c'`
returns `6\n` end-to-end (boot → execve sh → pipe → wc → exit) plus
the 6 existing user smokes (sem/msg/mq/ptrace/mprotect/dyn).

Everything else moves to §3.

## 3 v2 must-run

Adds the userspace-platform binaries that were on the v1 list
pre-R05 (Go/Rust/redis/nginx/openssh/chrony) — they need real ld.so
+ libc-with-NSS-PAM + system manager per `00§3.2` phases 33-35.

| Binary | Source | Why | Adds |
|---|---|---|---|
| Statically-linked Go ≥1.22 (hello + goroutines + channels + http server) | `go build -ldflags='-extldflags=-static'` | Go runtime exercises clone3, futex, epoll, mmap, tgkill | sched, ipc, vmm |
| Statically-linked Rust + `tokio` | `cargo build --target *-unknown-linux-musl --release` per `29a§2` | tokio uses epoll/futex/clone3 | same coverage |
| `redis 7` against our musl | from source | event loop, AF_UNIX, TCP | net, ipc |
| `nginx` w/o io_uring | from source | server, signals, pidfile | net, fs, signals |
| `nginx` with `aio threads io_uring;` | from source | io_uring | `30` enabled |
| `openssh-server 9.x` | from source | PTY, modern crypto, rlimits | tty, pty, security, net |
| `chrony` / `ntpd` | from source | clock_adjtime, rt_sigtimedwait | time, signals |
| `runc` w/ privileged OCI bundle | container runtime | `26`,`27` full namespace+cgroup+seccomp+landlock |
| `bpftrace` simple probe | BPF subset | BPF verifier+loader+kprobe |
| `perf record/report` | PMU sampling | `37` PMU full |
| `cri-o` or `containerd` minimal | container daemon | runc + extras |

## 4 v2.x must-run

| Binary | Why | Adds |
|---|---|---|
| `systemd ≥ 254` as PID 1 | full init system | sd_notify, journald protocol, cgroup BPF, ~150 syscalls |
| GUI app on Wayland (`weston` + `weston-terminal`) | full graphics + audio + USB stacks |
| Docker (full Moby) | container ecosystem |
| KVM with QEMU userspace | KVM backend (deferred) |

## 5 Per-binary test plan

For each acceptance binary:
1. Build from source against our toolchain into the v1 image.
2. `xtask qemu` boot.
3. Run a scripted scenario (e.g., `busybox ls /; busybox cat /proc/cpuinfo > /tmp/c; busybox grep -c processor /tmp/c`).
4. Capture serial; assert expected substrings.
5. Daemons run end-to-end (start, accept connection, serve test request, clean shutdown) — no duration-based stress.

Stored as `tests/acceptance/<binary>/scenario.sh` + `expected.txt`.

## 6 Exit criteria for v1

Per `00§15`. Restated:

- PR-time CI green on the tagged commit, both arches.
- Every `43§2` minimum acceptance binary runs end-to-end on QEMU (boots → exec binary → expected output → clean exit).
- Zero panics, zero oopses across the acceptance run; SHA-256 reconciles on any fs corpus the scenario writes.
- Kernel-completeness audit `docs/kernel-audit.md` shows no stub regressions vs the sweep landed sessions 38.
- All FROZEN specs have their Test Contract green.
- Coverage gates met per `42§10`.

## 7 Failure modes

If acceptance fails for a binary in v1:
- Open question logged in the binary's `tests/acceptance/<bin>/known-issues.md`.
- Either (a) fix kernel, (b) document binary as "v2.x acceptance" with rationale.
- Never: silently move pass criterion.

## 8 Cross-spec

Each spec from `10` upward; `00§15` exit criterion; `40` (CI runs acceptance scripts).

