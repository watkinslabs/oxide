# state.md — session hand-off

## Headline
**x86 GREEN. ARM RED — and PROVEN pre-existing, not caused by this session.**
`make smoke-x86` passes on main (`basic.target`, 89s). ARM faults at ~11s guest.
Repo cleaned to a single branch; two dead test gates repaired; the ARM IRQs-on
register corruption (a separate, real bug) cracked and fixed in #3901.

## ARM: what is PROVEN (stop re-deriving this)

**The fault is a kernel-stack overflow during IRQ dispatch.** Every instance has
the same shape:

    data-abort-same-el, WRITE, translation fault
    elr = oxide_default_vector_handler + 0x08..0x44   (its own frame store)
    lr  = inside oxide_irq_vector_handler
    far = a guard page

i.e. an IRQ arrives, the dispatch tree runs, a synchronous fault nests inside it,
and the fault vector's frame store runs off the end of the stack it is on.

**It is NOT a regression from this session.** All three IRQs-on PRs
(#3901 IRQ stack + fault-vector ELR/SPSR, #3902 block busy-poll, #3914 blk
no-park-on-IRQ-stack) were reverted together on a branch and ARM **still faulted,
identically** (`far=fffffb0000041000`, a task-kstack guard page). The revert was
therefore discarded — it fixes nothing and would have thrown away real work.
Corroboration: `archive/C116-network-mmsg-ordering-probes` records the same ARM
fault on **2026-07-17**, a week earlier, during "concurrent dynamic-loader
activity" plus a task kernel-stack underflow, and calls it "a global N22 blocker".

**Which stack overflows depends on the IRQ-stack switch:**
  * switch DISABLED → the dispatch runs on the interrupted TASK stack and
    overflows it (`far` = task-kstack guard). Also reproduced at 32 KiB stacks, so
    headroom alone does not fix it.
  * switch ENABLED (main today) → `far` = the IRQ stack's one-past-the-end edge,
    with SP measured at `top + 224` and 15,792 bytes still FREE below. So the IRQ
    stack does not overflow; SP **escapes past its top**. `top + 224` is exactly
    `(top - 64) + 288`, i.e. `oxide_irq_resume_user` ran `add sp, sp, #288` with
    SP on the IRQ stack. That is the bug to fix in the switch.

**Hypotheses tested and DISPROVEN (do not retry):**
  1. IRQ-stack switch is the cause — no, the fault predates it and survives its removal.
  2. Sleeping on the shared IRQ stack — real bug, fixed in #3914, not this fault.
  3. Kernel-stack headroom — no, still faults at 32 KiB.
  4. `schedule()` called on the IRQ stack — guarded, still faults.
  5. AP sharing the BSP's IRQ stack — no, `smp_arm.rs` arms the AP its own.

**Next experiment (do this BEFORE changing code):** boot with
`FEATURES=debug-armctx` and read the `[ARMCTX]` block. It prints the interrupted
SP, its kstack slot + owner, the task's `arch_ctx`, and the `schedule()`
save/restore ring. One run already showed a first fault with
`interrupted_sp = 0xffffffff801ad09c` — inside `.text`
(`kmain::hooks::tick_poll_combined + 0x4b4`), i.e. **SP loaded with a code
address**, which is a clobbered stack pointer, not a depth problem. Chase that:
which path writes a return address into SP.

Cost note: an ARM smoke is ~3 min (link) + ~66s (boot). `[FAULT]` now fails the
attempt immediately (#3913) instead of burning 600s x 3.

## The ARM fix (PR #3901)
`oxide_default_vector_handler` — the aarch64 fault vector — saved the GPRs but left
**ELR_EL1 / SPSR_EL1 / SP_EL0 live in the system registers** across the handler
call, then `eret`'d from them. Sound only while a fault handler can never block.
Under IRQs-on the demand-page handler blocks in virtio-blk `do_request`, the task
is switched out, and another task's exception entry/return overwrites
ELR_EL1/SPSR_EL1 — so the handled-path `eret` returns to a **stale kernel PC while
restoring that frame's user register file**. Presented as `do_request` at EL1 with
`x27(self)=0`, `x30`=ld.so entry, `x8`/`x26` user-stack pointers. Linux
`kernel_entry`/`kernel_exit` always round-trip these through `pt_regs`
(`docs/54§1.6`); x86 is structurally immune (CPU-pushed iret frame).

Fix: save elr/spsr/sp_el0 into the frame at entry (offsets 176/184/192 — one 288-B
shape now shared by the SVC / software-step / undef / fault frames) and restore
before the eret; the exception-table fixup patches the frame's ELR slot, never the
live register. Shipped with the per-CPU IRQ stack (F699), which it REQUIRES: the
frame grew 176→288 B and without moving the softirq dispatch tree off the task
kstack, an IRQ frame + block/ext4 dispatch + a nested fault frame overflows the
16 KiB stack (caught by the guard page during review).

Decisive tell: **SP_EL1 == kstack_top exactly**, frame at `kstack_top-288`. An
empty kernel stack mid-function means control ARRIVED via an exception return, not
a call chain ⇒ the defect is the eret's PC, not the register file. Four prior
sessions read the coherent user register file as a wild write into kernel-stack
spills; a coherent full register file is a RESTORE, never corruption.

Anti-thrash method: one build dumping, at the fatal fault, the interrupted SP +
kstack-slot owner + `arch_ctx` + a ring of what `schedule()` saved/restored per
task — the whole hypothesis space in a single boot. Kept as `debug-armctx`
(PR #3904, off by default).

## Merged this session (11 PRs)
#3901 IRQ stack + fault-vector ELR/SPSR · #3902 block busy-poll IRQs-on ·
#3903 per-condition BLK_COMPL/BLK_TURN queues + select_idle_sibling ·
#3904 debug-armctx · #3906 N22 IFF_UP finding · #3907 udev worker_watch tests ·
#3908 SIOCETHTOOL ETHTOOL_GLINK · #3909 untracked files into scratch/ ·
#3910 restore `cargo test -p sched` (187 tests had NEVER run) ·
#3911 detached disk fails Eio not Ebusy.

## Verified at this checkpoint
- `make smoke-x86` PASS — `basic.target` in 89s (on this exact main).
- ARM boot to `basic.target`/`sysinit`/`sockets`/`getty` with IRQs-on, zero faults
  in a 169K-line log — but via the qemu MCP on the F700 config (IRQ-stack switch
  DISABLED, probes on), NOT on main as it stands. See ARM REGRESSION.
- `make smoke-arm` on main: FAULTS (above).
- x86_64 + aarch64 kernel targets build.
- `cargo test -p sched` 187/0 · `-p net` 983/0 · `-p drv-virtio-blk` 25/0 ·
  `-p hal-aarch64` 47/0.

## Known-bad, NOT fixed (each needs its own lane)
1. `cargo test -p block` — `default_queue_limits_are_canonical_single_block_topology`
   fails on main, parallel AND single-threaded. Discard defaults
   (`max_hw_discard_sectors` 4294967295 vs expected 0).
2. `cargo test -p net` — two `arp::ioctl` tests fail under the PARALLEL runner
   only (shared global stack, order-dependent); 983/0 single-threaded.
3. `recvmmsg` timeout-copyback rule is CONTESTED — main copies back when a
   datagram arrived; the archived C116 branch copies back only when MSG_DONTWAIT
   was absent, citing a host-oracle frame that contradicts main. Possible live
   conformance bug. Detail + the resolving experiment in `scratch/network-plan.md`.
4. `siocgif` tests live inside `include!("kernel_body.rs")` (kernel-target-only),
   so they never execute hosted.
5. MII register ioctls (SIOCGMIIPHY/SIOCGMIIREG/SIOCSMIIREG) unimplemented;
   working code in `archive/C116-network-mmsg-ordering-probes`.

## Next work
Resume the IRQs-on migration — `scratch/irqs-on-kernel-migration-plan.md` §2-4:
tick de-risk → lock conversion → the whole-kernel flip. The foundation (per-CPU
IRQ stack + the fault-vector fix + block busy-poll) is now ON MAIN — but settle
the ARM REGRESSION above FIRST; do not build phase 2 on an ARM base that faults. N22 remains gated on the NM device-model question
recorded in `scratch/network-plan.md` (kernel hardcodes IFF_UP at NIC
registration where Linux registers admin-DOWN).

## Recovery
Every deleted branch and stash is an `archive/*` tag (20 on origin, 24 local).
`git tag -l 'archive/*'`. `archive/stash-09` is local-only — its base commit
carries a 128 MB blob GitHub rejects; contents are two file deletions, no source.

## First command next session
    git -C /home/nd/oxide/kernel log --oneline -3 && cat scratch/irqs-on-kernel-migration-plan.md
