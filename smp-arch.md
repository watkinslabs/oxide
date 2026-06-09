# SMP scheduler architecture — Linux-compliant, no hacks

Companion to `sched-anal.md`. That doc fixes the **single-CPU** preemption +
signal shape (Phase A). This doc covers the rest: real multi-CPU, per-CPU
runqueues, migration/affinity, and the kernel-wide concurrency hardening that
"100% Linux-compliant SMP" actually requires (Phases B, C). Specs touched at
freeze: `13` (sched), `06` (locks/RCU/PerCpu), `15` (syscall ABI for affinity).

## Compliance target

- Scheduling classes, highest→lowest: stop, deadline (SCHED_DEADLINE),
  rt (SCHED_FIFO/RR), fair (CFS/EEVDF, SCHED_OTHER/BATCH/IDLE), idle. Today
  only fair (`cfs.rs`) + rt (`rt.rs`) exist; stop/deadline are Phase B/C adds.
- Fair class: nice→weight (EEVDF lag in modern Linux; CFS vruntime acceptable
  for v1, EEVDF a later revision). cgroup `cpu.weight`/bandwidth ride `26`.
- Per-task affinity (`cpus_allowed`/cpumask), `sched_setaffinity`/`getaffinity`.
- Wakeups place tasks on a target CPU (`select_task_rq`) and IPI it.
- Load balancing across CPUs (sched domains, periodic + newidle).

## Preempt-model decision (PICK ONE — affects the whole design)

| Model | Kernel code preemptible? | Effort | Recommendation |
|---|---|---|---|
| PREEMPT_NONE | no (only explicit yields) | — | too weak; not our goal |
| PREEMPT_VOLUNTARY | only at return-to-user + cond_resched points | low | **Phase A/B default** |
| PREEMPT_FULL | yes, any preemptible kernel point | high | **Phase C target** |
| PREEMPT_RT | + sleeping spinlocks, threaded IRQs | very high | out of scope v1 |

**Decision: ship VOLUNTARY first, design every interface so FULL is a later
flip, not a rewrite.** Rationale: VOLUNTARY needs only the return-to-user slow
path (Phase A already builds it) + `preempt_count` honored at `preempt_enable`.
FULL additionally needs every kernel preemptible point audited for re-entrancy;
doing that before SMP is correct would multiply the risk. The reschedule IPI,
per-CPU rq, and `preempt_count` we build for VOLUNTARY are exactly what FULL
also uses — no throwaway work.

## Analysis — current reality (audited, file:line verified)

- **Two switch engines, both live** (the root problem):
  - voluntary `schedule()` executes the switch inline (`live/schedule.rs:209`,
    `ArchCtx::switch` ~`:325`).
  - IRQ tail STAGES a switch: `set_need_resched` (`lapic.rs:104`) →
    `tick_pick_next` (`lapic.rs:131`) → `schedule_from_irq` (`schedule.rs:345`)
    → `stage_switch` per-CPU slots (`live/preempt.rs:91`, `NEXT=8`/`CUR=16`),
    consumed by the asm epilogue `mov rax,gs:[8] … call oxide_context_switch`
    — copy-pasted **~12×**, one per vector stub (`hal-x86_64/src/irq.rs`),
    mirrored on arm (`hal-aarch64/src/vbar.rs:426`).
  - → split ownership of `rq.current`, the saved-frame contract, and the
    asm-offset-vs-Rust-const coupling (12 copies). This is what corrupted
    under timer preempt / fork first-run / signal return last time.
- **UP-only core**: `schedule()` holds `rq.inner` across the switch
  ("UP v1 — no concurrent CPU"). Fatal under real SMP.
- **Per-CPU scaffolding exists**: `runqueue::GLOBALS[MAX_CPUS]`, per-CPU idle,
  `preempt_count`/`need_resched` are per-CPU atomics. But wakeups are
  local-only; no `select_task_rq`, no reschedule IPI, no load balance, no
  affinity, no `finish_task_switch` lock handoff. AP reaches long mode but is
  gated out of the scheduler (`smp_x86.rs`).
- **Signals**: delivered in the syscall-dispatch tail (`fs/sig_dispatch.rs`),
  NOT on a unified return-to-user path, and NOT from the IRQ path.
- **Tests**: only CFS/RT pick-order unit tests exist. NO hosted contract tests
  for Context/frame layout, first-run/fork return, or signal-frame round-trip.

## Target architecture

### Ownership invariants (one owner per truth — enforce before coding)

- `rq->lock` (per-CPU) owns that CPU's runqueue membership + `rq.current`.
- `schedule()` is the ONLY task-switch primitive.
- return-to-user slow path owns "reschedule before user return" + signal frame.
- `preempt_count` (per-CPU) owns "may we schedule here".
- a task's `on_rq` + `on_cpu` own its placement; migration is the only mover.
- reschedule IPI owns "make a remote CPU re-enter schedule".

### Phase A — UP-correct, one engine (= sched-anal.md)

**Grounded reality (verified in `context.rs` + `live/schedule.rs` — corrects
the first audit):**
- There is ONE low-level primitive: `oxide_context_switch` (saves rsp/rbp/rbx/
  r12-r15, loads next's, wrmsr next.fs_base, `ret`). `ArchCtx::switch` is a thin
  Rust wrapper that adds fs_base **save** (rdmsr prev) + restore around it.
- `schedule()` calls the wrapper inline. The IRQ epilogue calls
  `oxide_context_switch` **directly** (staged), SKIPPING the fs_base-save — a
  latent bug a single call-site would fix.
- First-run scaffolds (`new_kernel_with_irq_frame`, `new_user_with_irq_frame`,
  `new_user_for_fork`) bake `rsp[0]=oxide_irq_resume_user`, so the primitive's
  `ret` lands in the shared epilogue → pop scratch → `iretq` to (user|kernel).
  Resumed-existing tasks instead `ret` back into the wrapper. Both compose on
  the SAME contract.
- Frame/scaffold contract tests ALREADY exist: `context.rs:389-473`
  (`layout_offsets_match_asm`, `new_kernel_with_irq_frame_layout`, …).

So A2 is NOT "unify two contracts" (there is one). A2 = **move the resched
call-site** from IRQ-dispatcher staging to the return-to-user epilogue and
route through the one `schedule()`; the switch primitive + scaffold are
untouched. This also fixes the fs_base-on-preempt save (preempt now goes
through the wrapper).

Steps (each: hosted test where possible → build both arches → boot→login→
shell→fork, repeated):
1. Add a Rust epilogue helper `irq_exit_to_user(frame)` called from
   `oxide_irq_resume_user` BEFORE the pop/iretq: `if from_user(frame) &&
   should_resched() { take_need_resched(); schedule() }` → (A4) signal frame.
   Safe: scratch+IRQ frame live on the stack (restored after), `schedule()`
   from preempt_count==0 doesn't hold the rq lock.
2. Repoint the timer/IPI dispatcher: keep `set_need_resched`, DELETE the
   `tick_pick_next`→`schedule_from_irq`→`stage_switch` chain. Each vector
   stub's ~12 staging blocks → plain `jmp oxide_irq_resume_user`.
3. Delete now-dead `schedule_from_irq`, `stage_switch`, `tick_pick_next`,
   `PERCPU_*_CTX_OFF`.
4. Unify signal delivery into `irq_exit_to_user` (off the syscall tail).
5. `preempt_enable` already routes through the one `schedule()` hook; keep.
6. Result: VOLUNTARY preempt, single switch call-site, fs_base-save fixed.
   (Kernel-interrupted ticks no longer preempt — acceptable; kthreads yield
   cooperatively. FULL preempt is a Phase-C flip via an `irq_exit_to_kernel`.)

### Phase B — SMP

1. **rq->lock handoff** (`finish_task_switch`): `schedule()` picks under the
   source rq->lock, switches, and the NEXT task releases the PREV's rq->lock
   after the switch (Linux's `context_switch`→`finish_task_switch`). Removes
   the "lock held across switch by one CPU" UP assumption.
2. **ttwu**: `try_to_wake_up` → `select_task_rq` (affinity + idlest/wake-affine)
   → enqueue on target rq under its lock → if target running else, `resched_curr`
   → **reschedule IPI** to that CPU. Add the `smp_mb__after_spinlock` wake
   barrier.
3. **AP bring-up into the scheduler**: per-CPU init (GS/TPIDR, TSS/idle, lapic
   timer), AP enters its idle→`schedule()` loop; BSP `smp_send_reschedule`.
4. **Affinity**: per-task cpumask (`cpus_allowed`), `sched_setaffinity`/
   `getaffinity` syscalls, forced migration (stop-task/migration path).
5. **Load balancing**: sched_domains/groups, periodic `load_balance` on tick +
   newidle balance, `can_migrate_task` (cache-hot/affinity/running checks).

### Phase C — kernel-wide concurrency hardening

1. Audit EVERY shared structure (each `Spinlock`, registry, fd table, VFS,
   PMM, slab, signal state) for true concurrent access; convert to real
   contended locks or RCU per `06`.
2. Memory-ordering pass: acquire/release + `smp_mb` where Linux has them.
3. `loom` model-checks for: rq enqueue/pick vs steal, ttwu vs schedule,
   wait/wake, exit/reap, fork-vs-signal. `miri` for UB.
4. Optional later: PREEMPT_FULL flip, stop/deadline classes, EEVDF.

## Test matrix (prove contracts BEFORE boot — sched-anal.md rule 3)

**Hosted unit (must exist before the Phase A switch-core patch):**
- Context/frame layout: `offset_of!` asserts coupling Rust ⇄ asm staging slots.
- scheduler rotation: N runnable tasks round-robin; RT preempts fair; idle only
  when empty (extend existing).
- preempt gating: `preempt_count>0` blocks resched; re-arm on enable.
- first-run + fork-child first return: saved Context → trampoline entry.
- signal frame build/`rt_sigreturn` round-trip incl. saved retval (B21 guard).
**loom (Phase B/C):** the model-check list above.
**qemu/system:** boot→login→shell→fork/exec, repeated; `smp=N` all CPUs online;
affinity honored; load spreads; spin-loop async-preempt repro. NEVER trust
`oxide login:` alone.

## Sequencing / blast radius

A1 tests → A2 return-to-user slow path (additive) → A3 delete IRQ-tail engine
(subtractive, on the net) → A4 unify signals → **boot/login both arches** →
B1 rq-lock handoff → B2 ttwu+IPI → B3 AP bring-up → B4 affinity → B5 balance →
C continuous. Each step single-purpose, hosted-tested where possible, loom for
the concurrent ones. Never combine A-core with futex/timerfd (sched-anal §4).

## Begin here

Phase A1: write the hosted scheduler/frame contract tests (the safety net),
then A2/A3 collapse to one engine. No SMP code until Phase A boots clean on
both arches.
