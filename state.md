# state — hand-off

Branch: F205-ssh-arm-channel-eof (PR #1287). Also open: C12-qemu-kvm-optin (#1288).
Workspace: spec-lint clean. Both arches pass `make smoke`.

## What shipped this session

- **#1287 4057360**: POSIX `fork(2)` bug — `sys_clone` only inherited
  the parent's sigmask if `CLONE_SIGHAND` was set. Linux unconditionally
  copies the mask in `kernel/fork.c::copy_thread`. Without this fix,
  musl's `fork() → __block_all_sigs() → _Fork() → __restore_sigs()` chain
  corrupted the child's mask: child started at 0, the first `__restore_sigs`
  read the *parent's* save buffer and propagated the wrong value forward.
- **#1288 C12 KVM opt-in**: `OXIDE_QEMU_KVM=1 make qemu-x86` switches to
  `-accel kvm`. Default stays TCG (KVM exposes a separate boot-time
  HLT/IF semantics gap that wedges at "keymap loaded"). Lets interactive
  users escape TCG's 100%-host-CPU idle floor.

## What's verified but NOT shipped (rolled back)

F206 attempts to fix the SVC-frame race in `deliver_arm`. Definitively
diagnosed by a `pre-eret` trace at the last kernel call site before
`eret`: `deliver_arm` wrote `frame.elr_el1 = handler` but the eret read
`elr = original PC`. Different addresses. The global
`oxide_svc_frame_base` was stale by the time deliver_arm ran (another
task's SVC entry between this task's syscall body and signal-tail).

With F206 working (per-task svc_frame slot read by deliver_arm), the
trace confirmed `pre-eret elr=handler` and **`HELLO` from `echo HELLO`
reached the SSH client on ARM for the first time ever**. SSH still
times out at 30s on channel close — separate problem: mask=0x10000
(SIGCHLD bit) propagates through dropbear's fork chain and stays
blocked.

Three F206 implementation attempts, all broke ARM smoke at "keymap loaded":
1. Per-task `Task.svc_frame: AtomicU64` set at dispatch entry — wedges.
2. Same field set at signal-tail (post-schedule) — too late, global
   already stale.
3. Linux-style `pt_regs = task->kernel_stack - sizeof(SvcFrame)` —
   wedges. Reason: `Task.kernel_stack` is the *context-switch* stack top
   used by `oxide_context_switch`, NOT the EL1 SVC stack. On aarch64
   our boot installs ONE global `KERNEL_STACK` and writes it to SP_EL1
   once; SP_EL1 isn't re-armed per task on context switch.

## The actual right fix (next session)

**Per-task SP_EL1 setup.** Linux runs every task on its own kernel
stack; SP_EL1 is reloaded on every context switch so the next SVC from
that task pushes its frame on the task-local kernel stack. Then
`pt_regs = current->stack_top - sizeof(pt_regs)` is correct without
any global or per-task race.

Concrete plan:
1. `Task` already has `kernel_stack: AtomicPtr<u8>` — repurpose as
   the EL1 stack top (verify all current users; today it's set via
   `set_kernel_stack` for kthreads).
2. `oxide_context_switch` (asm in
   `crates/arch/hal-aarch64/src/context.rs`) gains `msr sp_el1, x9`
   on the load side, where x9 = next->kernel_stack.
3. SVC entry uses SP_EL1 = current task's stack → frame sits at top-288.
4. `deliver_arm` reads frame from `current->kernel_stack - 288`. No
   global. No race.
5. Drop `oxide_svc_frame_base` and `current_svc_frame()`.

Risks: must allocate kernel stacks for ALL tasks (kthreads + user
processes). Today only kthreads have explicit stacks via
`set_kernel_stack`; user tasks share the global one. Allocator pressure
is small (~16 KiB × N tasks).

## Also worth knowing

- **CPU at 100%**: TCG interpretation, not a kernel bug. Guest is
  halting properly (`halt_forever()` does `schedule → halt → loop`).
  KVM accel resolves this on x86 with a kernel-side fix for the
  KVM/HLT divergence (separate work).
- **PTY mode broken differently**: `ssh -tt` fails with "ttyname fails
  for openpty device" — a separate bug from the channel-close hang.
  Likely missing `/proc/self/fd` symlink or wrong `/dev/pts/N` entry.
- **debug-ssh trace surface**: rt_sigaction, rt_sigprocmask (with
  caller_pc), deliver/deliver-masked, pipe_create/close, sys_exit drop,
  pselect6 ready/EINTR/timeout, syscall nr/rv tid-tagged. Lives under
  `kernel/src/syscalls/signal_trace.rs` + `signal_dispatch.rs`.

## Repro

    pkill -f qemu-system; rm -f /tmp/uart.sock /tmp/qa.log
    setsid bash -c 'OXIDE_QEMU_UART_SOCK=/tmp/uart.sock \
        OXIDE_QEMU_HEADLESS=1 \
        exec make qemu-arm FEATURES="debug-ssh" \
        > /dev/null 2>&1 < /dev/null' &
    until [ -S /tmp/uart.sock ]; do sleep 1; done
    socat -u UNIX-CONNECT:/tmp/uart.sock OPEN:/tmp/qa.log,creat,trunc &
    until ss -lnt | grep -q 2222; do sleep 5; done
    time timeout 30 sshpass -p swordfish ssh \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -p 2222 alice@127.0.0.1 'echo HELLO'
    # Post-F206: HELLO reaches client; exit=124 at 30 s.
    # Without F206: nothing reaches client.

`grep -a` mandatory on `/tmp/qa.log` (per `docs/54§6`).

## See also

- `docs/54-asm-correctness.md` — checklist for new asm patches.
- F203/F204/F205 commit messages — three prior SSH-targeted PRs.
- `kernel/src/syscalls/signal_dispatch.rs` — Signum-typed dispatch.
- `crates/arch/hal-aarch64/src/vbar.rs` line 244-247 — where the
  to-be-replaced `oxide_svc_frame_base` global gets written.
