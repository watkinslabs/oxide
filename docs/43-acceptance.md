# 43 Acceptance Criteria

FROZEN 2026-05-02. Dep:every spec above.
## 1 Purpose

Enumerate the binary-level acceptance tests for v1, v1.x, v2 milestones. Each binary listed is the *contract*: if a stock build of it from upstream against our libc/syscall ABI fails to run, the milestone is not done.

## 2 v1 must-run (frozen)

| Binary | Source | Why | Tests covered |
|---|---|---|---|
| `busybox sh` | upstream busybox built against our musl | basic shell | tty, pipe, signals, fork+exec |
| `busybox ls/cat/echo/cp/mv/rm/mkdir/...` | same | core fs ops | VFS, file I/O, dir |
| `busybox ps/top/uptime/free` | same | proc/sys reads | `/proc`, `/sys` |
| `busybox dmesg` | same | log access | `/dev/kmsg` |
| `busybox mount/umount` | same | mount API | `16`,`19` |
| Statically linked Go ≥1.22 binary (a hello world that uses goroutines + channels + http server) | `go build -ldflags='-extldflags=-static'` | Go runtime exercises clone3, futex, epoll, mmap, tgkill | sched, ipc, vmm |
| Statically linked Rust binary (using `tokio` runtime) | `cargo build --target x86_64-unknown-linux-musl --release` (per `29a§2`) | tokio uses epoll/futex/clone3 | same coverage |
| `redis 7` (built against our musl) | from source | event loop, AF_UNIX, TCP | net, ipc |
| `nginx` (without io_uring) | from source | server, signals, pidfile | net, fs, signals |
| `openssh-server 9.x` | from source | PTY, modern crypto, rlimits | tty, pty, security, net |
| `chrony` or `ntpd` | from source | clock_adjtime, rt_sigtimedwait | time, signals |

## 3 v1.x must-run

| Binary | Why | Adds |
|---|---|---|
| `nginx` with `aio threads io_uring;` | io_uring | `30` enabled |
| `runc` with privileged OCI bundle | container runtime | `26`,`27` full namespace+cgroup+seccomp+landlock |
| `bpftrace` simple probe | BPF subset | BPF verifier+loader+kprobe |
| `perf record/report` | PMU sampling | `37` PMU full |
| `cri-o` or `containerd` minimal | container daemon | runc + extras |

## 4 v2 must-run

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
5. Run for soak duration (1h continuous load for daemons like redis/nginx).

Stored as `tests/acceptance/<binary>/scenario.sh` + `expected.txt`.

## 6 Exit criteria for v1

Per `00§15`. Restated:

- 168h continuous uptime in 4-CPU QEMU on each arch.
- Concurrent workload: kernel build of itself in a loop + `iperf3` over loopback (≥ 5 GB/s sustained) + `fs_mark` over ext4 + `stress-ng --cpu --vm --hdd` (subset; no swap).
- Every v1 must-run binary: scenario passes; daemons survive 1h soak each.
- Zero panics, zero oopses, zero silent data corruption (SHA-256 reconciles on `fs_mark` corpus).
- Soak artifact signed by single soak box (no second-machine repro per `05§G2`).
- All FROZEN specs have their Test Contract green.
- Coverage gates met per `42§10`.

## 7 Failure modes

If acceptance fails for a binary in v1:
- Open question logged in the binary's `tests/acceptance/<bin>/known-issues.md`.
- Either (a) fix kernel, (b) document binary as "v1.x acceptance" with rationale.
- Never: silently move pass criterion.

## 8 Cross-spec

Each spec from `10` upward; `00§15` exit criterion; `40` (CI runs acceptance scripts).

