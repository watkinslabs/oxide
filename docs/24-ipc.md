# 24 IPC: pipes, signals, futex, eventfd, signalfd, timerfd, AF_UNIX

FROZEN 2026-06-08. Dep:`01`,`02`,`06`,`12`,`13`,`16`,`23`. Provides:`15` syscalls (signal, futex, pipe2, eventfd2, signalfd4, timerfd_create, AF_UNIX in `25`).

## Revision 2026-06-08 (R04)

- Implemented (F412 Stage E+G): ASYNC signal delivery on
  IRQ-return-to-user + cross-CPU nudge. Closes the last delivery hole:
  a thread spinning in USER code with no syscall to ride (Go's
  async-preemption M:N scheduler) now receives a handler on its next
  timer/IPI IRQ exit.
- Stage E hook (`fs::sig_dispatch::try_deliver_async_irq`): invoked from
  the per-arch IRQ dispatcher (`arch-irq::lapic::oxide_irq_dispatch`
  VEC_TIMER + VEC_RESCHED; `arch-irq::gic::oxide_arm_irq_dispatch`)
  AFTER EOI + tick + softirq, BEFORE `tick_pick_next` (so `current()` +
  CR3/TTBR0 still match the live IRQ frame).
  - **GATE (crash-critical):** delivers ONLY if the interrupted frame
    was USER mode — x86 `frame.cs & 3 == 3`; arm `frame.spsr_el1 & 0xf
    == 0` (EL0t). Kernel-mode IRQ frame ⇒ NO-OP (rewriting a kernel
    return frame to enter a user handler corrupts the kernel resume).
  - Picks the lowest deliverable signal (`sigpending & !sigmask` with a
    registered handler ≠ SIG_DFL/SIG_IGN; SIG_DFL/SIG_IGN left pending
    for the syscall-return default-action triage), builds the full
    `RtSigframe` via `sigbuild::build_{x86,arm}(FrameSrc::Irq, …)` with
    GPs read from `current_irq_frame()`, writes it to the user stack
    below `frame.rsp`−red-zone, then REWRITES THE IRQ FRAME IN PLACE
    (x86 rip=handler/rsp=new_sp/rdi=sig[+rsi=&info,rdx=&uc]; arm
    elr_el1=handler/sp_el0=new_sp/x0=sig[+x1/x2], x30=restorer). The IRQ
    epilogue pops these → iretq/eret enters the handler with correct
    args + SP. Blocks the sig (honors SA_NODEFER); rt_sigreturn (R03,
    always rides a syscall) restores the full mcontext.
  - At most ONE signal per IRQ, delivered to `current()` on the
    interrupted task's own frame regardless of any staged ctx-switch.
    The interrupted USER task holds no kernel lock, so the user-AS
    sigframe write is lock-free.
- Stage G cross-thread nudge (`sched::live::nudge_task`, called by
  `sys_kill`/`sys_tgkill`/pgrp-fan after setting the pending bit): wakes
  a parked target; if the target is running/runnable on a DIFFERENT CPU,
  sends a resched IPI (x86 LAPIC ICR) / SGI (arm GICv3) so it takes an
  IRQ exit and hits the Stage-E hook promptly. UP / same-CPU ⇒ no-op
  (the next local tick delivers).
- Test contract: `/bin/sigurg_async_smoke` — SA_SIGINFO|SA_RESTART
  handler for SIGURG, main thread spins in a tight no-syscall
  `for(;;) counter++` loop, a pthread `pthread_kill`s it; handler sets a
  volatile flag → loop exits + prints `sigurg: PASS`. Both arches. This
  is the exact Go async-preempt mechanism; the Go tools
  (duf/glow/micro/yq/fzf) `--version` returns instead of wedging.

## Revision 2026-06-08 (R03)

- Implemented (F411 Stage C+D): the full builder + full-mcontext
  restore. Replaces the minimal 40/56-byte ad-hoc frame everywhere.
- Builder (`syscall::sigbuild::build_{x86,arm}`, pure/host-tested;
  unsafe plumbing in `fs::sig_dispatch`): writes the real
  `RtSigframe{X86,Arm}` (siginfo_t + ucontext + FP) on the user stack.
  - **Frame source** (`FrameSrc::{Syscall,Irq}`): Syscall reads the GP
    set from the 16-quad syscall full-frame (`current_user_full_frame`)
    / SvcFrame; Irq reads from `current_irq_frame()` (Stage B). Both
    populate the FULL mcontext. Syscall is wired through the
    syscall-tail caller now; Irq is built + hosted-tested, consumed by
    the timer-preempt path (Stage E).
  - **GP→sigcontext map.** x86 syscall full-frame indices (base
    top-0x80): 0 rax(nr) 1 rdi 2 rsi 3 rdx 4 r10 5 r8 6 r9 7 rcx(rip)
    8 r11(rflags) 9 rsp 10 rbx 11 rbp 12 r13 13 r14 14 r15 15 r12 →
    sigcontext r8..rip/eflags; sigcontext.rax = syscall RETVAL (not the
    saved nr) so rt_sigreturn restores the interrupted syscall's value
    (the `$(cmd)`-empty-capture fix). arm SvcFrame: gp[0..17]=x0..x17,
    x18_x29=[x18,x29], x30, x19_x28=x19..x28, sp_el0/elr_el1/spsr_el1 →
    sigcontext regs[0..30]/sp/pc/pstate; regs[0] = syscall RETVAL.
  - **FP.** x86: `fpu_save` → 512-B FXSAVE copied into a 16-aligned
    region below the frame; `uc_mcontext.fpstate` points at it. arm:
    q0-q31/fpsr/fpcr → `fpsimd_context` (magic 0x46508001) at the head
    of `__reserved`.
  - **siginfo_t.** RT-queue record (if present) → its si_code +
    pid/uid/value (SI_QUEUE carries sigval); else SI_USER pid/uid 0.
    Synchronous SIGSEGV → SEGV_MAPERR + si_addr=cr2.
  - **sa_flags honored.** SA_SIGINFO → 3-arg handler (x86 rsi=&info,
    rdx=&uc via the saved-arg slots; arm x1=&info, x2=&uc). SA_ONSTACK
    + alt-stack enabled → frame carved on the alt stack. SA_NODEFER →
    no self-mask (default masks `sa_mask | signo`). SA_RESETHAND →
    sigaction reset to SIG_DFL after build.
  - Invariants kept (docs/54§3): frame at/above handler SP; x86 red-
    zone skip + rsp%16==8; arm sp%16==0; restorer = handler ret target.
- Restore (`restore_{x86,arm}` + `rt_sigreturn_{x86,arm}`): reads the
  on-stack ucontext (which the handler MAY have edited — Go's
  asyncPreempt rewrites uc_mcontext.PC/SP) and restores the FULL GP set
  + PC/SP/flags + FP + sigmask into the syscall frame (the single
  restore target, since rt_sigreturn always rides a syscall). Reloads
  FP from the frame's fpstate. Restores the saved syscall retval.
- The synchronous-fault SIGSEGV path
  (`mm-pmm::user_as::signal::try_deliver_sigsegv_via_handler_x86`) now
  builds the SAME full RtSigframe (fault-frame GP source) so its
  handler's rt_sigreturn restores correctly.
- Test contract: hosted round-trip suite in `syscall::sigbuild` —
  build then EDIT the on-stack ucontext PC/SP/callee-saved reg
  (simulate Go) then restore, asserting the edit propagates and every
  other GPR round-trips; both arches' layouts checked on the x86 host.

## Revision 2026-06-08 (R02)

- Changed: replace the minimal 40-byte/128-byte ad-hoc signal frame
  with the FULL Linux `rt_sigframe` ABI. Delivery builds a real
  `siginfo_t` + `ucontext` (+ FP state) on the user stack; the handler
  is invoked with the 3-arg `SA_SIGINFO` convention `(int, siginfo_t*,
  void*)` when `SA_SIGINFO` is set, 1-arg otherwise; `rt_sigreturn`
  restores the full machine context from the frame.
- Why: Go's async-preemption signal (SIGURG) and correct POSIX
  semantics require user space to read/modify the saved register
  context via `ucontext` and the kernel to faithfully restore it.
  The old frame zeroed `ucontext`, so `sigreturn` could not reconstruct
  the interrupted register state — any handler that resumed (vs. exited)
  ran on corrupt context. SA_SIGINFO was unhonored; SA_ONSTACK,
  SA_RESTART, SA_NODEFER, SA_RESETHAND were not applied.
- ABI (exact Linux uapi offsets, asserted by hosted offset tests):
  - `siginfo_t` = 128 B: `si_signo@0/si_errno@4/si_code@8`, `_sifields`
    union @16; SI_USER/SIGCHLD/SIGSEGV/SI_QUEUE variants.
  - `stack_t` = 24 B (`ss_sp,ss_flags,_pad,ss_size`).
  - x86_64 `sigcontext_64`: GP order r8..rip, `rip@0x80`, eflags/cs/
    err/trapno/oldmask/cr2/fpstate ptr; size 0x100. `ucontext`:
    uc_flags/uc_link/uc_stack/uc_mcontext/uc_sigmask. `rt_sigframe`:
    `pretcode` (restorer ret addr) then uc then info. FP = 512-B FXSAVE.
  - aarch64 `sigcontext`: fault_address@0, regs[31]@8, sp@0x100,
    pc@0x108, pstate@0x110, `__reserved[4096]@0x118` carrying
    `fpsimd_context` (magic 0x46508001, 528 B). `ucontext`:
    uc_sigmask + `__unused[120]` pad to 16-align `uc_mcontext@176`.
    `rt_sigframe`: info then uc (arm orders info first).
  - SA_* flags: NOCLDSTOP=1, NOCLDWAIT=2, SIGINFO=4, RESTORER=0x04000000,
    ONSTACK=0x08000000, RESTART=0x10000000, NODEFER=0x40000000,
    RESETHAND=0x80000000. SS_ONSTACK=1, SS_DISABLE=2.
- Staged rollout (no behavior change lands until its stage):
  - A (this revision): define the user-ABI types at exact offsets in
    `crates/kernel/syscall/src/sigframe.rs` + hosted offset-assertion
    tests. No frame is built/restored yet — pure types, can't break boot.
  - B: build-frame path (both arches) — `setup_rt_frame` writes
    siginfo+ucontext+FP onto the (alt-)stack, sets handler args per
    SA_SIGINFO, applies SA_ONSTACK/NODEFER/RESETHAND/mask additions.
  - C: `rt_sigreturn` restores the full context from the frame;
    SA_RESTART syscall re-entry.
  - D: FP state save/restore (FXSAVE x86, fpsimd_context arm).
- Affected code: `crates/kernel/syscall/src/sigframe.rs` (types, this
  stage); later — `crates/kernel/mm-pmm/src/user_as/signal.rs`,
  `crates/kernel/fs/src/sig_dispatch.rs`, the `rt_sigreturn` handler,
  HAL frame-rewrite paths.
- Test contract change: §12 gains a hosted offset-assertion suite
  (`size_of`/`offset_of` vs. Linux uapi) as the type freeze gate, plus
  later a round-trip "signal handler resumes with intact registers"
  acceptance once Stages B–C land.

## Revision 2026-05-09 (R01)

- Changed: pinned the v1 AF_UNIX cmsg shape. SOCK_DGRAM admitted via
  socket(AF_UNIX, SOCK_DGRAM, 0); each datagram carries its sender's
  (pid, uid, gid) snapshot taken at sendmsg time. recvmsg with
  msg_control buffer writes back any pending SCM_CREDENTIALS or
  SCM_RIGHTS cmsgs. SCM_RIGHTS at sendmsg dups each fd into a
  per-message side-array; recvmsg dups them into the receiver's
  fd_table at delivery.
- Why: F114 admitted socket(AF_UNIX, SOCK_STREAM); SOCK_DGRAM was
  EAFNOSUPPORT. systemd-journald, dbus, ssh-agent rely on dgram +
  SCM_RIGHTS for fd passing. Without per-message metadata the cmsg
  contract can't ride the existing byte-stream rings.
- Affected code: `crates/net/src/unix_sock.rs` (UnixDgramQueue +
  UnixMsg + Cmsg); `kernel/src/syscall_glue_net.rs` (sendmsg
  parses msg_control, recvmsg writes msg_control); fd dup at
  recv-time uses the existing dup3 path.
- Test contract change: §10 acceptance gains a "fd passing over
  AF_UNIX" smoke — task A creates a pipe, sends the read end via
  SCM_RIGHTS, task B receives the cmsg and reads from it.

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

PI (priority inheritance) futex: defer to v2.

## 6 eventfd

A `u64` counter + wait queue. `read` consumes (semaphore mode subtracts 1; default mode reads counter and zeros). `write` adds. EFD_CLOEXEC, EFD_NONBLOCK, EFD_SEMAPHORE flags.

## 7 signalfd

Returns an fd that, when read, yields a `signalfd_siginfo` for the next pending signal in the registered mask. Backed by the task's signal queue + a wait queue.

## 8 timerfd

`timerfd_create(clk_id, flags)` returns fd. `timerfd_settime` arms an `HrTimer` (per `23§8`). On expiry, increments a counter and wakes readers. `read` returns expiry count.

## 9 AF_UNIX

Three flavors: SOCK_STREAM, SOCK_DGRAM, SOCK_SEQPACKET. Per `15` and `25§13`. Path-bound (filesystem) or abstract (`\0`-prefixed). SCM_RIGHTS (fd passing) and SCM_CREDENTIALS (peer cred). Connection state machine like TCP but in-memory.

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
- PR-time gate uses `paranoid-ci` (`debug-ipc`) per `41§3`. Signal-storm + futex-bounce concurrent stressors run in proptest harness, not duration-based.

## 13 Failure modes

- Pipe broken (no readers, write): SIGPIPE + EPIPE.
- Futex op invalid (op-flags mismatch): EINVAL.
- Signal queue full: `SIGQUEUE_PREALLOC` → EAGAIN; standard signal: collapse silently.
- AF_UNIX connect to nonexistent path: ECONNREFUSED.

## 14 Debug

`debug-ipc`: dump pipe/AF_UNIX buffers on close; futex wait-queue dump; signal delivery trace.

## 15 Cross-spec

`13` (signal delivery checks at preempt/syscall return), `15` (syscalls), `25` (AF_UNIX as a socket family), `23` (timerfd backing).

