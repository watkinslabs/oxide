# IRQs-on-in-kernel migration plan (Linux IRQ model)

**Goal:** move from "kernel runs every syscall/fault IF=0" (the big-lock model) to Linux-style
"IRQs enabled during syscalls/faults." Fixes the root cause of N22 + all desktop slowness
(timer tick freezes for seconds during I/O storms — memory `kernel-runs-if0-during-syscalls-faults`).

**Model target:** IRQs-on + **PREEMPT_NONE** first (interrupts serviced during syscalls, but
kernel code NOT involuntarily preempted — reschedule only at return-to-user + voluntary points).
Full kernel preemption (PREEMPT_FULL) is a separate, larger, deferred tier. PREEMPT_NONE delivers
the entire freeze fix and keeps per-CPU/`current` safety unchanged.

## Already built (mature — no work)
- `lock_irqsave`/`IrqGate`/`save_enable` both arches (sync/lib.rs, hal-*/irq_gate.rs).
- `preempt_count`, `need_resched`, `should_resched_to_user` = a working PREEMPT_NONE engine (sched/preempt.rs).
- `schedule()` already masks IRQs around the pick/switch, releases rq.inner via raw_unlock on incoming stack (switch.rs) — Linux-correct as-is.
- `local_bh_disable`/softirq/`in_interrupt`, `PerCpu<T>`, x86 IST (#DF/NMI/#DB/#MC), #PF-on-RSP0-nestable.

## The work, in dependency order

### Phase 0 — FOUNDATION (prerequisite for all IRQs-on)
0a. **Per-CPU IRQ/softirq stack (Linux IRQSTACK).** [LARGE] Run hard-IRQ handler + `do_softirq` on a
    dedicated per-CPU stack, not the interrupted task stack. THIS is the ARM x27=0 fix: that fault is
    KERNEL-STACK OVERFLOW — IRQ+softirq (incl. the virtio-blk completion bottom-half that re-enters
    block work) piling onto an already-deep ext4→block task stack (C213 class). x86: switch RSP in the
    stub or IST-route IRQ vectors; ARM: switch SP at top of oxide_irq_vector_handler + before do_softirq
    (ARM has no IST). Ref docs/54§1.6, 22.
0b. **Hard-IRQ accounting.** [MEDIUM] Wire the reserved HARDIRQ preempt_count field (preempt.rs:79-80):
    irq_enter adds, irq_exit clears, in_interrupt() counts it. + close the softirq enable/accounting race
    (set count before daifclr/sti). [SMALL]
- CORROBORATION (boot-free, do FIRST): build `debug-stack-guard`/VMAP guard pages; confirm the ARM x27
  fault becomes a guard-page abort at the stack boundary → validates 0a.

### Phase 1 — DE-RISK THE TICK (highest leverage)
Extend the B1344 ktimers-exile pattern (already moved reap/wake/PSI off the hard tick) to the remaining
tick lock-takers: **loadavg resample, bridge STP tick, fbcon answerback drain, vvar realtime publish.**
This ELIMINATES conversion targets #3/#4/#6/#7/#8 outright and returns `tick_poll_combined` (hooks.rs)
to near-lock-free. [~3-5 days]

### Phase 2 — LOCK CONVERSION (the scope driver)
17 distinct locks shared between process- and IRQ/softirq-context, ~150-180 acquisition sites.
`06§3.1`: EVERY site of a shared lock must convert (one missed plain `.lock()` re-opens the deadlock).
- Enabling infra: implement `Spinlock::lock_bh()` (06§3.1 lists it; only BhGuard composition exists) [~1d];
  wire the `06§5` CI lint (bare `lock()` on an IRQ-shared class = build fail) [~2-3d].
- Mechanical irqsave flips — short-hold locks: CLOCK, IRQ_RECORDS, blk DEVICES/inflight, ANSWERBACK,
  WAKE_LISTS, NET_NS, IfaceRegistry.inner (~7 locks, ~60 sites). Cost multiplier: arch-neutral crates
  can't name X86IrqGate/ArmIrqGate — each needs a cfg-gated gate alias/macro (the tx_lock! pattern). [~1wk]
- Restructure / bh-defer (irqsave insufficient — long holds / blocking waits): fbcon VT_STATE (full-screen
  blit), snd CTX, input CTXS+EvdevQueue.buf (nested), net MODERN_DEVS, vsock CTX, tty inner (line-discipline;
  make UART/PS2 RX defer to a softirq like virtio-input), and net bridge state (worst — holds across a
  blocking done.wait() from the ISR; exile to ktimers per Phase 1). ~2-4d each → ~3wk.

### Phase 3 — PER-SITE BUSY-POLL FIXES (device waits, after their lock is dropped/restructured)
Apply the B1386 pattern (enable IRQs across the lock-free poll only). Sites holding a lock across the poll:
**virtio-gpu/fbcon (hot desktop path — also THE fbcon CPU bottleneck), AHCI, virtio-snd control, virtio-net TX.**
virtio-blk already done (B1386). Overlaps Phase 2.

### Phase 4 — THE FLIP (small, LAST — only after Phases 0-3)
Enable IRQs at syscall/fault entry, gated on the interrupted context's saved IF/DAIF:
- x86 syscall: `sti` after the 16 pushes (syscall.rs ~L170), `cli` before epilogue (~L185). No gate.
- x86 fault: enable before current_handler() (fault.rs:284), gated on `f.rflags&(1<<9)` AND `vector==14`
  (#PF only — #DF/NMI/#DB/#MC are IST-routed, non-reentrant). Re-mask before return.
- ARM SVC: `msr daifclr,#2` after frame save (asm.rs:233), `daifset,#2` at restore (asm.rs:286). No gate.
- ARM fault: gate in asm on SPSR.I (bit7): `mrs x9,spsr_el1; tst x9,#(1<<7); b.ne 1f; msr daifclr,#2; 1:`,
  re-mask at restore. No IST needed (same-EL uses SP_ELx).
[~2 days incl. lockstep boot-verify. This is the payoff PR — whole kernel goes IRQs-on.]

### Phase 5 — OPTIONAL / DEFERRED
- Long-compute cond_resched points: zram codec, ext4 journal commit, PMM zeroing (worst tick-freeze after
  block I/O). [MEDIUM] — can run concurrent with Phase 2+.
- PREEMPT_FULL (full kernel preemption): drop the from_user gate on oxide_irq_resched_on_exit + add
  preempt_disable around every per-CPU/`current` critical section + re-audit current_ref borrows. [LARGE]
  Not required for the freeze fix; strictly a worst-case-latency improvement.

## Effort
- Phase 0: ~1.5-2 wk (IRQ stack is the big item).
- Phase 1: ~1 wk.
- Phase 2: ~4-6 wk (dominated by the ~7 restructure cases).
- Phase 3: overlaps Phase 2, ~1 wk net.
- Phase 4: ~2 days.
- **Total ≈ 7-10 weeks** for IRQs-on + PREEMPT_NONE, dominated by the lock conversion.

## B1386 implication
B1386 (per-site IRQ-enable in the virtio-blk wait) is UNSAFE without Phase 0 — it triggers the ARM stack
overflow (and the same latent risk on x86 under deep chains). HOLD B1386; it becomes safe once the per-CPU
IRQ stack lands, or fold it into Phase 3. Do NOT merge B1386 standalone.

## Key files
Foundation: hal-x86_64/src/irq.rs, fault/stubs.rs, idt.rs, tss.rs; hal-aarch64/src/vbar/asm.rs;
  arch-irq/src/{lapic,gic}/dispatch.rs; sched/src/preempt.rs, bh.rs.
Locks: sched/src/{registry.rs,live/ttwu.rs}, net/src/**, tty, fbcon, timekeeper, drv-virtio-*.
Entry flip: hal-x86_64/src/{syscall.rs,fault.rs}; hal-aarch64/src/vbar/asm.rs, fault.rs.
Template: sched/src/live/wait_list.rs (cfg-gated lock_irqsave macro), net tx_dispatch.rs (tx_lock!).
Specs: docs/06§3.1/§5 (locks), docs/13§8-12 (sched), docs/20-23 (HAL/IRQ), docs/54 (asm).
