# Handover — ARM IRQs-on register corruption + branch state

## 1. Goal / context
Making the kernel **IRQs-on-in-kernel (preemptible, Linux-style)** to fix the
N22 / desktop-slowness root cause: the IF=0 big-lock model freezes the timer
tick for seconds during I/O storms → wakeup latency → slow service startup.
User chose this path 2026-07-25 ("full Linux IRQ style", "at all cost").
Migration plan: `scratch/irqs-on-kernel-migration-plan.md` (7-10 wk).

Two shortcuts were measured and REJECTED (data, not opinion):
- **B1387 park-not-spin**: kills the freeze (395→14 tick gaps) but adds ~2ms/IO
  wake latency (no wakeup preemption under IF=0; smp=1 wakee waits behind the
  runqueue) → boot 3.5× slower → N22 SSH times out.
- **B1386 busy-poll-IRQs-on alone**: x86 still 488 tick gaps (max 1.8s), N22
  times out. The freeze has MANY IF=0 sources, not just block I/O. Only the
  whole-kernel flip fixes N22.

So N22 requires the full migration, whose foundation is IRQs-on. That flip
corrupts on ARM — the blocker below.

## 2. The ARM corruption (THE blocker)

**Repro:** branch **F700-irqs-on-arm-crack** = F699 per-CPU IRQ stack + B1386
busy-poll IRQ-enable + diagnostic probes. Boot ARM tcg (`mcp__qemu`).
Deterministic data-abort at execve **"interp place ok"** (~guest 8s, tcg-var):
```
EC=data-abort-same-el  far=0x514  elr=do_request busy-poll (ldr [x27,#1300] =
self.poisoned, x27=self=0)  x30=0x40007050 (ld-linux entry)  sp_el0/x8/x26 =
user-stack ptrs.
```
i.e. `do_request` runs at EL1 with the **new program's initial user register
file**; its `self` pointer (x27) is 0.

**GDB gotcha (cost ~8 false "GRUB hangs"):** with `mcp__qemu__qemu_start
paused=false`, the GDB stub still HALTS the CPU — you MUST call
`mcp__qemu__qemu_continue` to actually run. "Empty serial" = you forgot to
continue, NOT a hang. Fatal-fault breakpoint: objdump `oxide_fault_print_rust`,
find `tbz w0,#0` target (`+0x88`-ish), break `*<that addr>`.

**PROVEN by probes (one boot each) — every candidate RULED OUT:**
- IRQ save/restore CLEAN: `[IRQ@dorequest]` — 806 IRQs hit do_request, ALL with
  x27=0xffffffff847fa000 (valid). Not the IRQ path.
- Sync-fault path: `[FAULT@dorequest]` — only the FATAL fault; no resolved
  demand-page faults in do_request. Not the fault path.
- F699 IRQ-stack switch DISABLED → corruption persists. Exonerated.
- execve SVC-frame patch (`059_execve/aarch64.rs`): `[EXECVE-PATCH]` never fired
  — fault precedes the patch. Per-CPU→per-task SVC-frame handoff already handled
  (`switch.rs:296` restores per-task `svc_frame`; set at dispatch `core.rs:386`).
- resume_user / sync_restore erets: `[RESUME-CORRUPT]` never fired.

**Conclusion:** a **WILD WRITE into do_request's KERNEL-STACK register spills**
overwrites x27's spilled `self`→0 and neighbor slots→the new program's
user-context, mid-execve-load, non-IRQ, non-fault. The memory-corruption class
(CLAUDE.md §11/12).

**Leading hypothesis to test next:** do_request may run with SP near
`kstack_top`, so its frame overlaps the SVC frame at `kstack_top-288`; a
SVC-frame patcher (execve/signal.rs writes elr_el1/sp_el0) then corrupts
do_request's spills. CONFIRM: get do_request's EXACT SP at the fault (read the
saved frame in `default_vector_handler`, now saves x0-x30 at [sp..0x118]) and
compare to `kstack_top-288`. If overlap → find who writes the SVC frame while
do_request runs there. Else → `debug-heappoison` / a hardware watchpoint on the
spill slot to name the writer (per CLAUDE.md §12 free-IP method).

**FIXED (real, Linux-parity, committed):** `oxide_default_vector_handler` now
saves x19-x28 (Linux `kernel_entry` saves all GPRs; oxide relied on AAPCS across
a fault handler that can block+reschedule with IRQs on). Did NOT fix this bug
but is correct and should land.

Full detail also in auto-memory `arm-irqs-on-corruption`.

## 3. Branch state (vs origin/main @ 67b76ae6a, PR#3900)

**No open PRs.** `main` = origin/main (clean, known-good). One uncommitted probe
edit in the F700 worktree (`kmain/early.rs` IRQSTK klog).

| Branch | rel. to main | merged? | contents / disposition |
|---|---|---|---|
| **F700-irqs-on-arm-crack** (HEAD) | +4 / -0 | no | Repro + foundation + the default_vector_handler fix + all diagnostic probes + F699-switch isolation-disable. **Do NOT merge as-is** (carries probes + disabled switch). Cherry-pick the `default_vector_handler` fix (eb9131661) to a clean branch when ready. |
| **F699-percpu-irq-stack** | +1 / -0 | no | Per-CPU guard-paged IRQ stack, both arches (Phase-0 foundation). Clean, mergeable once the flip is validated. Currently a no-op-ish foundation. |
| **B1386-block-wait-irqs-on-tick-unfreeze** | +2 / -0 | no (pushed to origin) | Busy-poll IRQ-enable + migration plan. Insufficient alone (§1). Keep as reference. |
| **B1387-blk-sleep-not-spin** | +2 / -0 | no | Park-not-spin investigation + a real thundering-herd fix (per-condition BLK_COMPL/BLK_TURN queues) + select_idle_sibling. The herd fix is genuinely correct and extractable. |
| **B1378-remove-boot-ip-seed-hack** | +2 / **-26** | no | STALE (26 behind main). Net NIC admin-DOWN + boot IP-seed hack removal (N22, Linux parity) + debug-netlink dump. Rebase onto main before touching; unrelated to the ARM crack. |
| B1385-wakelat-measure | +0 / -1 | **MERGED** (= main tip / PR#3900) | Done. |

**Counter collisions to fix (metadata/index.md):** local `F699-percpu-irq-stack`
and `F700-irqs-on-arm-crack` REUSE counters already taken by
`origin/F699-tcp-edge-fixture` and `origin/F700-bridge-ioctl-owner`. Rename the
local ones to fresh F-numbers before pushing, or they collide on origin.

## 4. Recommended next moves
1. Land the `default_vector_handler` x19-x28 fix on a clean, correctly-numbered
   branch (it's Linux-correct regardless of the crack).
2. Crack the wild write: confirm the SP/SVC-frame-overlap hypothesis, then
   watchpoint the spill slot to name the writer.
3. Then resume the migration phases (plan §2-4): tick de-risk → lock conversion
   → the flip. Boot-verify BOTH arches at each gate (lockstep HARD RULE).
