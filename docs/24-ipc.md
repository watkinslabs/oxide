# 24 IPC: pipes, signals, futex, eventfd, signalfd, timerfd, AF_UNIX

Status: DRAFT 2026-05-02
Depends on: `01`,`02`,`06`,`12`,`13`,`16`,`23`.
Provides to: `15` syscalls (signal, futex, pipe2, eventfd2, signalfd4, timerfd_create, AF_UNIX in `25`).

## 1 Purpose

Bundle of small inter-task primitives. Each is small individually; spec'd together because they share patterns (wait queue + fd-as-handle).

## 2 Invariants (frozen)

1. Every IPC fd backs a `File` (per `16§6`); operations go through VFS file ops.
2. Pending signals on a thread limited to `RLIMIT_SIGPENDING`; queue is bounded.
3. SIGKILL and SIGSTOP cannot be caught/blocked/ignored; enforced at `rt_sigaction`.
4. RT signals (34..64) queue with `siginfo_t` payloads; standard signals collapse to "pending bit set".
5. Futex wake/wait: no lost wakeup (per `06§6` wait-queue contract).
6. `eventfd` counter never wraps (saturates and returns EAGAIN on add overflow).
7. `pipe2` buffer default `PIPE_BUF=4096`; resizable up to `pipe_max_size` (sysctl, default 1 MiB).

## 3 Pipes

```rust
sys_pipe2(pipefd:UVA<[i32;2]>, flags:u32) -> KR<()>
```

Backing: per-pipe ring buffer in pages, MPMC under per-pipe spinlock + wait queues.

Atomic write rule: writes ≤ `PIPE_BUF` are atomic (not interleaved with other writers).

`O_NONBLOCK`: read returns EAGAIN on empty; write returns EAGAIN if would block.

## 4 Signals

State per task: `sigaction[64]`, `sigmask`, `sigpending` (bitmap), `sigqueue` (linked list of `siginfo_t` for RT signals).

Send paths: `kill`,`tkill`,`tgkill`,`pidfd_send_signal`,`rt_sigqueueinfo`. Internal: page fault → SIGSEGV/SIGBUS, ALRM → SIGALRM, etc.

Delivery: at every kernel→user return, check `sigpending & ~sigmask`. If nonempty, pick (lowest signum first), build `ucontext` on user stack (or sigaltstack), write trampoline arrangement, resume at handler.

Signal trampoline: assembled into vDSO; handles `rt_sigreturn` at handler exit.

## 5 Futex / futex2

```rust
sys_futex(uaddr,op,val,utime,uaddr2,val3) -> KR<i32>     // legacy
sys_futex_waitv(waiters,nr,flags,utime,sig) -> KR<i32>   // new
sys_futex_wake / wait / requeue                          // new
```

Per-system hash table `BTreeMap<(mm_id, uaddr), WaitQueue>` (or sharded; 256 buckets RCU-protected). Waiters park on the queue; wakers walk and wake.

Robust futex: `set_robust_list` registers a per-task list; on task exit, walk it and signal listed futexes.

PI (priority inheritance) futex: defer to v1.x.

## 6 eventfd

A `u64` counter + wait queue. `read` consumes (semaphore mode subtracts 1; default mode reads counter and zeros). `write` adds. EFD_CLOEXEC, EFD_NONBLOCK, EFD_SEMAPHORE flags.

## 7 signalfd

Returns an fd that, when read, yields a `signalfd_siginfo` for the next pending signal in the registered mask. Backed by the task's signal queue + a wait queue.

## 8 timerfd

`timerfd_create(clk_id, flags)` returns fd. `timerfd_settime` arms an `HrTimer` (per `23§8`). On expiry, increments a counter and wakes readers. `read` returns expiry count.

## 9 AF_UNIX

Three flavors: SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET. Per `15` and `25§AF_UNIX`. Path-bound (filesystem) or abstract (`\0`-prefixed). SCM_RIGHTS (fd passing) and SCM_CREDENTIALS (peer cred). Connection state machine like TCP but in-memory.

Backing: per-socket pair of intrusive ring buffers; SCM messages out-of-band ring.

## 10 Concurrency

- Pipe: spinlock per pipe + wait queues for read/write.
- Signal queue: per-task signal-spinlock; class `SignalQueue`.
- Futex hash buckets: RCU + per-bucket spinlock.
- AF_UNIX socket: per-socket spinlock; connection setup takes both endpoints.

## 11 Perf budget

| Op | p99 cy |
|---|---|
| `pipe2` create | ≤ 5000 |
| 4-byte pipe write+read RTT (uncontended) | ≤ 4000 |
| `futex_wake` (no waiter) | ≤ 250 |
| `futex_wake` (1 waiter) | ≤ 1500 |
| `futex_wait` no contention then woken | ≤ 3500 |
| `eventfd` write+read RTT | ≤ 1500 |
| AF_UNIX SOCK_STREAM 64-byte RTT | ≤ 6000 |

## 12 Test contract (frozen)

- Pipe: 100K writers/readers; verify atomic ≤PIPE_BUF; no torn writes; SIGPIPE on writer-only-end-closed.
- Signals: deliver each signum 0..64; verify SIGKILL uncatchable; RT signal queue depth honored.
- Futex: lost-wakeup property test; loom of wait/wake/requeue (depth 8).
- eventfd: semaphore mode + default mode; EAGAIN on overflow.
- timerfd: 100K random timers; expiry within 50µs p99.
- AF_UNIX: pass fd via SCM_RIGHTS, verify recipient gets working fd; pass creds, verify match.
- Soak (bg, not gate per `40§3`): 4h cycles signal-storm + futex-bounce alongside fs/net; zero deadlocks. PR-time gate uses `paranoid-ci` (`debug-ipc`).

## 13 Failure modes

- Pipe broken (no readers, write): SIGPIPE + EPIPE.
- Futex op invalid (op-flags mismatch): EINVAL.
- Signal queue full: `SIGQUEUE_PREALLOC` → EAGAIN; standard signal: collapse silently.
- AF_UNIX connect to nonexistent path: ECONNREFUSED.

## 14 Debug

`debug-ipc`: dump pipe/AF_UNIX buffers on close; futex wait-queue dump; signal delivery trace.

## 15 Cross-spec

`13` (signal delivery checks at preempt/syscall return), `15` (syscalls), `25` (AF_UNIX as a socket family), `23` (timerfd backing).

## 16 Open Questions

- Robust futex list verification: validate user pointers each access (cost) or trust? Lean: trust + `EFAULT`-on-fault.
- POSIX message queues (`mq_*`): defer to v2.
- `eventfd2` with EFD_SEMAPHORE for fairness vs perf: copy Linux exactly.
- PI futexes: v1.x.
