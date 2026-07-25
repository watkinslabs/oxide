# state.md — session hand-off

## Headline
**ARM IRQs-on register corruption CRACKED and FIXED** (B1388) — the blocker for
the whole IRQs-on-in-kernel (preemptible-kernel) migration. ARM now boots real
systemd userspace with IRQs enabled in kernel context: udevd / journald /
resolved / auditd / userdbd starting, `local-fs.target` + `paths.target` +
`swap.target` reached, ~123s guest (tcg), **zero faults** in a 169K-line log.

## Root cause (not what the prior sessions assumed)
It was never memory corruption. `oxide_default_vector_handler` — the aarch64
fault vector — saved the GPRs but left **ELR_EL1 / SPSR_EL1 / SP_EL0 live in the
system registers** across the handler call, then `eret`'d from them. Correct only
while a fault handler can never block. Under IRQs-on the demand-page handler
blocks in virtio-blk `do_request`, the task is switched out, and another task's
exception entry/return overwrites ELR_EL1/SPSR_EL1 — so the handled-path `eret`
returns to a **stale kernel PC while restoring that frame's user register file**.
Presented as `do_request` running at EL1 with `x27(self)=0`, `x30`=ld.so entry,
`x8`/`x26` user-stack pointers. Linux `kernel_entry`/`kernel_exit` always
round-trip these through `pt_regs` (`docs/54§1.6`). x86 is structurally immune
(its fault frame is the CPU-pushed iret frame).

Decisive tell: **SP_EL1 == kstack_top exactly**, frame at `kstack_top-288`. An
empty stack mid-function means control ARRIVED via an exception return, not a
call chain ⇒ the bug is the eret's PC, not the registers.

Anti-thrash method note: every prior probe tested one hypothesis per boot and all
returned negative. What worked was ONE build dumping, at the fatal fault, the
interrupted SP + kstack-slot owner + `arch_ctx` + a ring of what `schedule()`
saved/restored per task — the whole hypothesis space in a single boot.

## Fix (B1388-arm-fault-vector-elr-spsr)
- `vbar/asm.rs`: save elr/spsr/sp_el0 into the frame at entry (offsets
  176/184/192 — one 288-B shape shared by the SVC/IRQ/undef/fault frames) and
  restore before the eret. Includes the x19-x28 save (same class: AAPCS relied
  upon across a handler that can block+reschedule).
- `fault.rs`: 8th arg = frame base; the exception-table fixup patches the frame's
  ELR slot, never live ELR_EL1 (which `kernel_exit` would discard).
- Verified: both arches build; `cargo test -p hal-aarch64` 47 passed / 0 failed;
  `make smoke-x86` PASS (basic.target, 72s); ARM boot verified via the qemu MCP.

## Open work
1. **Resume the IRQs-on migration** — `scratch/irqs-on-kernel-migration-plan.md`
   §2-4: tick de-risk → lock conversion → the whole-kernel flip. Foundation
   branches are unmerged and now unblocked:
   - `F699-percpu-irq-stack` — per-CPU guard-paged IRQ stack; clean, mergeable.
   - `B1386-block-wait-irqs-on-tick-unfreeze` — busy-poll IRQ-enable. Measured
     insufficient alone (x86 still 488 tick gaps, max 1.8s) but the right step 1.
   - `B1387-blk-sleep-not-spin` — carries a genuinely correct thundering-herd fix
     (per-condition BLK_COMPL/BLK_TURN queues + select_idle_sibling) worth
     extracting. The park-not-spin part was measured and rejected (~2ms/IO).
   - `F700-irqs-on-arm-crack` — repro + the diagnostic post-mortem probes (kstack
     slot ownership, arch_ctx dump, switch save/restore ring). Do NOT merge as-is
     (probes + F699 switch deliberately disabled); keep it as the migration lane.
2. `B1378-remove-boot-ip-seed-hack` is 26 commits behind — rebase before touching.
3. ARM userspace now shows service-level failures that were masked by the fault:
   `upower.service: Failed to spawn 'start' task: File exists` (ERRNO=17) —
   a real Linux-incompat to chase.

## Counters
`metadata/index.md`: B next=1389, F next=701 (origin already holds
F699-tcp-edge-fixture + F700-bridge-ioctl-owner; the local F699/F700 names
collide with them and must be renamed before any push).

## First command next session
    git -C /home/nd/oxide/kernel log --oneline -3 && cat scratch/irqs-on-kernel-migration-plan.md
