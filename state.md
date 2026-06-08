# Session hand-off — preemptive signal delivery (full rt_sigframe buildout)

## Arc of this session
TUI startup-hang → traced to REAL kernel gaps (not terminal/DSR):
- **futex WAIT_BITSET/WAKE_BITSET (9/10)** fell to `_ => 0` (instant return) → pthread/Go
  thread-startup spin-deadlock. **Fixed B67 (#1624, merged). starship launches.**
- **timerfd TFD_TIMER_ABSTIME** ignored → Go netpoller timer never fired. **Fixed B68
  (#1625, merged).** + console DSR/OSC query responder (tty/vtquery).
- HHDM 512 GiB (B66), /proc audit confirmed built-out (task #2) — earlier/merged.

## THE remaining blocker: Go runtime needs preemptive async signal delivery
Go tools (duf/glow/micro/yq, even fzf hangs-on-exit) livelock. ROOT: Go async-preemption
sends SIGURG (via tgkill) to a thread spinning in USER code; kernel must deliver it on a
timer-IRQ return. Rust(starship)+C+C++ tools WORK; only Go needs this.
**Surprise from gap-analysis: timer-IRQ PREEMPTION + ctx-switch ALREADY EXIST** (both
arches, 14§R07 — the "iretq-frame gap" is closed). The ONLY missing piece is **async
signal delivery on IRQ-return-to-user + the full rt_sigframe** (current frame is minimal
40B rip/rsp/rflags, no siginfo/ucontext — insufficient for Go).

## PLAN: full signal-ABI buildout (user chose "full, not minimal"). 8 stages A–H.
Most infra EXISTS: sigaction storage(flags/mask/restorer task.rs:646), sigaltstack
storage(task.rs:237), RT queue, timer preempt, ctx-switch, send_resched_ipi(lapic.rs:235),
FXSAVE/FPSIMD(hal-*/fpu.rs). New work:
- **A DONE (F409, pushing):** user-ABI types `crates/kernel/syscall/src/sigframe.rs`
  (SigInfoUser 128B, x86 SigContextX86 rip@0x80, arm SigContextArm pc@0x108, ucontext,
  fpstate, sa::/ss::/si:: consts) + 8 offset tests + docs/24§4 R02.
- **B NEXT (CRITICAL asm):** save FULL GP set at IRQ entry. x86 `hal-x86_64/src/irq.rs`
  10 stubs (vec 0x40,0x41,0x50-0x57) currently push scratch only (rax,rcx,rdx,rsi,rdi,
  r8-r11); ADD rbx,rbp,r12-r15. Frame offsets shift: today vec@72, RIP@88, CS@96(RPL=ring),
  RSP@112. Update `oxide_irq_resume_user` pops (irq.rs:236) + `new_kernel_with_irq_frame`/
  `new_user_with_irq_frame` scaffold (context.rs:118 "17×8=136B" → grows by 6 slots) +
  oxide_irq_dispatch frame reads (arch-irq/lapic.rs) + arm `vbar.rs` IRQ handler (add
  x19-x28 like its SVC frame does) + arm resume epilogue. Use an asm `.macro` to avoid
  10× copy errors. **Every timer tick traverses this — offset/align bug crashes on 1st
  tick. Boot-gate BOTH arches to login.** Also flush FXSAVE into frame at deliver.
- **C:** rewrite deliver_x86/arm (`fs/src/sig_dispatch.rs:148/280`) to build full
  rt_sigframe from a frame-source (syscall frame OR IRQ frame); honor SA_SIGINFO(3-arg
  rsi/rdx=&info/&uc; arm x1/x2), SA_ONSTACK(alt-stack), SA_NODEFER, SA_RESETHAND.
- **D:** rewrite rt_sigreturn_x86/arm (sig_dispatch.rs:227/372) to restore FULL mcontext
  (ALL GPRs+PC/SP/flags+FP) from the possibly-handler-EDITED on-stack ucontext (Go rewrites
  uc.PC/SP→asyncPreempt). Single restore target = the syscall frame rt_sigreturn rides.
- **E (CRITICAL):** async-delivery hook in IRQ epilogue (lapic.rs/vbar dispatch) AFTER
  resched pick: only if interrupted USER (x86 CS&3==3 / arm SPSR.M==EL0t) AND current()
  has deliverable sig → build frame from IRQ frame, redirect iretq/eret PC→handler. Target
  post-switch current(), its IRQ frame.
- **F:** sigaltstack/SA_ONSTACK consume (131_sigaltstack.rs fields are dead storage) +
  SA_RESTART (rewind user PC by syscall-insn width on restartable EINTR).
- **G:** tgkill/kill (234/062) send_resched_ipi to target on another CPU + wake Sleeping.
- **H:** R-blocks done/todo: docs/24§4 R02 done(A); docs/54(asm), docs/14(FPU+R07),
  docs/13§9(preempt-point) still need R-blocks as B/E land.

Risks ranked: B (IRQ full-GP asm) + E (async deliver, wrong-EL→kernel-frame crash) are the
killers — isolate, boot-gate hard. Do NOT rebuild working pieces (preempt/ctx-switch/IPI/FP).

## Verify each stage
Hosted offset/round-trip tests where possible (verify-left). Boot gate per stage: BOTH
arches to login. Final gate: a SIGURG smoke (spin in user, tgkill from another thread,
handler reads/edits ucontext, runs) THEN duf/glow/micro/yq launch on x86 AND arm.

## Reverted (do not resurrect as-is)
An agent's combined epoll-poll + futex-reorder + nanosleep-EINTR attempt was net-negative
(nanosleep-EINTR churns Go without signal-delivery; yq never worked anyway — was masked).
Reverted to clean B68. EpollInode::poll IS a real gap (epoll.rs no poll() → nested epoll
always-ready) — fold into the buildout if it helps, but it's not the root.

## Boot-test recipe (x86)
`cargo run -p xtask -- rootfs --arch x86_64 && ...kernel --arch x86_64 --features debug-boot
&& ...grub --arch x86_64 --features debug-boot --build-only`. Boot: qemu-system-x86_64 q35
-cpu host -enable-kvm -smp 2 -m 2G -cdrom target/oxide-x86_64-grub.iso -boot d + virtio-blk
serial=oxide-root/oxide-home + `-serial unix:/tmp/x.sock`. Login alice/swordfish. Targeted
syscall trace (arm-on-execve TRACE_ARMED in sched::trace + 059_execve) is the proven way to
find a hang's exact blocking syscall — floods serial if ungated.

## Counters / workflow
max F=409 (this), B=68. Author Chris Watkins <chris@watkinslabs.com>, no Co-Authored-By.
spec-lint clean before commit. Branch-per-stage, gh pr merge --delete-branch. Smoke push may
SSH-idle-timeout after passing → re-push SKIP_SMOKE=1 same commit if branch not on origin.
