# Session hand-off — SMP scheduler rework in progress (F425)

## MERGED to main this session (all CI-green)
- PR #1659 B75: virtio-blk busy-poll → adaptive spin-then-sleep + real MSI
  completion IRQ (fixes the x86 SMP=2 residual login freeze).
- (in #1659) fix(ci): tty `core` module was gitignored (`core`/`core.*`
  patterns) → broke all kernel CI; anchored patterns to root, tracked the file.
- PR #1660 F424: in-guest full-RAM memtest (`debug-memtest`).
- PR #1661 B76: aarch64 used only 1 GiB of `-m 2G` — no FDT on the EDK2/ACPI
  path → 1 GiB fallback. Now sizes RAM from the EFI memory map
  (EfiConventionalMemory + reclaimed BootServices, ACPI pinned in place);
  PMM MAX_REGIONS 32→128. → ~1.90 GiB. Per-EFI-type RAM log added.

## ACTIVE BRANCH: F425-smp-scheduler (NOT a PR yet, do NOT merge)
Goal: real SMP + preemption the Linux way, 100% compliant, no hacks.
Plan docs at repo root: `sched-anal.md` (UP preempt/signal shape) +
`smp-arch.md` (full Phase A/B/C, the authoritative design — READ IT FIRST).

### Committed on the branch (clean, builds, two-engine state STILL INTACT,
### x86 login-verified; nothing half-applied):
- smp-arch.md: plan, twice-corrected vs real code. Key facts: ONE switch
  primitive `oxide_context_switch` (`ArchCtx::switch` wraps it +fs_base);
  frame/scaffold contract tests ALREADY exist (context.rs:389-473); preempt
  model = VOLUNTARY first → FULL (Phase C).
- Phase-A seam: `should_resched()` + `should_resched_to_user(user)` in
  sched/preempt.rs + tests; CFS rotation contract test. 87 sched tests green.
- **Keystone design DONE (smp-arch.md Phase A step 0):** `finish_task_switch`
  handoff. preempt_count is PER-CPU; rule = schedule() entry +1, INCOMING
  task's finish_task_switch −1 (net 0/switch). first-run scaffold must route
  `ret → oxide_finish_switch_tramp(call finish_task_switch; jmp resume_user)`.
  COUPLING: schedule_from_irq does no +1 → finish would underflow if it lands
  first → finish_task_switch + engine-collapse MUST be ONE coordinated change.

### Verified-then-REVERTED probes (findings only, code reverted):
- Removing `tick_pick_next` (cooperative-only, no IRQ preempt) still boots to
  login (12.6s) → boot doesn't depend on IRQ-tail switching.
- Routing IRQ-exit through schedule() naively leaves preempt_count==1 on
  first-run (the PreemptGuard the scaffold bypasses) → that's WHY step 0 exists.

## FIRST TASK next session — the coordinated keystone (Phase A, one change):
1. Add `finish_task_switch()` (Rust: preempt_enable; Phase B: release prev
   rq-lock) + `oxide_finish_switch_tramp` asm (both arches).
2. schedule(): replace PreemptGuard with explicit preempt_disable at entry +
   finish_task_switch() after oxide_context_switch returns; balance early-return.
3. Scaffolds (new_kernel_with_irq_frame / new_user_with_irq_frame /
   new_user_for_fork, x86 + arm): bake rsp[0]=finish_switch_tramp.
4. IRQ exit → resched via the one schedule(): at `oxide_irq_resume_user` top,
   `mov rdi,[rsp+0x60]` (saved CS) `; call oxide_irq_resched_on_exit` (Rust:
   if should_resched_to_user(cs&3==3) { take_need_resched(); schedule() }).
   CS is at rsp+0x60, rsp 16-aligned, in BOTH entry paths (verified).
5. DELETE schedule_from_irq, stage_switch, tick_pick_next, PERCPU_*_CTX_OFF,
   and the ~12 gs:[8]/gs:[16] staging blocks (x86 irq.rs + arm vbar.rs).
6. Hosted tests: +1/−1 balance, underflow guard. Then build BOTH arches →
   boot→login→**shell→fork/exec, REPEATED** (not just `login:`); fail-fast on
   any intermittent login/shell/fork-corruption sign (sched-anal.md §6).
Do it as ONE coordinated commit per the coupling; verify hard before Phase B
(rq-lock handoff, ttwu+IPI, AP bring-up, affinity, balance).

## Deferred follow-ups (noted, not started)
- 64 MiB `kalloc::STATIC_HEAP` → dynamic (biggest RAM win, both arches).
- pre-session uncommitted (NOT mine): server.py, 060_exit.rs — git stash list.

## ENV QUIRKS
- Long builds/boots: Bash run_in_background + Monitor until-loop on the output
  file. `pkill ... || true` (set -e aborts on pkill no-match).
- Multi-line `git commit -m` mangles under the snapshot shell → use `-F file`.
- ALWAYS `pkill -9 -f qemu-system; sleep 3` before a boot (disk-lock contention
  incl. the grub build's own smoke qemu).
- `xtask grub --arch <a>` builds THEN boots interactively (grep output for
  `oxide login:`); doesn't self-exit. `make smoke`/pre-push hook is separate +
  self-terminating.
