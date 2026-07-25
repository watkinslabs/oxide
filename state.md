# state.md — session hand-off

## Headline
**x86 GREEN. ARM RED — and PROVEN pre-existing, not caused by this session.**
`make smoke-x86` passes on main (`basic.target`, 89s). ARM faults at ~11s guest.
Repo cleaned to a single branch; two dead test gates repaired; the ARM IRQs-on
register corruption (a separate, real bug) cracked and fixed in #3901.

## ARM: SOLVED for the gate — smp=1 boots; smp=2 is a separate bug

**ARM was never broken. ARM at `smp=2` is.** `boot-smoke.sh` defaulted arm to 2
CPUs, so every "ARM does not boot" result all session was an SMP bug wearing a
disguise. Same kernel, same tree:

  * `OXIDE_SMP=1` → **PASS**, `basic.target` in 115s, zero faults.
  * `OXIDE_SMP=2` → dies ~11s guest, every attempt.

The arm gate now defaults to 1 CPU (#3917), so both arches boot to
`basic.target`. `OXIDE_SMP=2 make smoke-arm` reproduces the remaining defect.

## The smp=2 defect — bisected, do NOT re-derive

Fault shape, every time: `data-abort-same-el`, the fault vector's own frame store,
`lr` inside `oxide_irq_vector_handler`, taken while running on the per-CPU IRQ
stack — with **~15 KiB of that stack still free**, so NOT exhaustion. The register
state is wild instead: one instance branched to a kernel heap page
(`elr == x30 == 0xffffffff847xxxxx`), another dereferenced `far=0xb8d` (a
near-null struct offset). Always right after `elf-load: interp place ok`, i.e.
under ld.so's path-lookup traffic.

**Bisected by experiment (each one boot):**

| Config | Result | Conclusion |
|---|---|---|
| smp=1 | PASS 115s | baseline healthy |
| smp=2, AP online+ticking, NO runqueue (never schedules) | **PASS 118s** | AP's GIC/IRQ/softirq path is INNOCENT |
| smp=2, AP schedules, task migration disabled | FAULT | migration is NOT required |
| smp=2, RCU cpu-hooks installed (this branch) | FAULT | RCU grace periods are not the cause |

⇒ **The trigger is the AP calling `schedule()` at all.** Not the IRQ path, not
migration, not RCU.

**Excluded by inspection (do not re-check):** ARM TLB broadcast is correct
(`tlbi vae1is` inner-shareable; the `vmalle1` sites are legitimately CPU-local);
PTE shareability is correct (`SH=0b11`); per-CPU pages are distinct frames and
`percpu_base()` reads `TPIDR_EL1`; IRQ stacks are per-CPU and distinct; lazy-TLB
`active_mm` correctly holds an extra Arc (Linux `mmgrab`/`mmdrop`) in the right
order; `kalloc::replace_global_context` and `preempt`/`softirq` state are per-CPU
arrays; `FPU_OWNER` is global on BOTH arches but unused in the switch path
(saves/restores are unconditional); ARM has MORE page-table locking than x86
(`KERNEL_PT_WRITE`).

**Remaining suspects in the AP's `schedule()` path:** `fire_sched_switch`'s global
trace hook; the `Arc::increment_strong_count`/`from_raw` juggling on `rq.current`
(the raw-Arc class this repo has been bitten by before — see CLAUDE.md §12);
`sched_ttwu_pending` cross-CPU queue handoff. Also worth a hard look:
`Task.svc_frame` is set at syscall entry (`dispatch/core.rs:386`) and **never
cleared on exit**, and `switch()` republishes that stale pointer into the per-CPU
slot on every switch — it only works today because ARM's SVC and IRQ frames both
land at `kstack_top-288`.

**Method note:** x86 runs smp=2 fine, which exonerates all generic scheduler /
preempt / softirq / exception-path code. Use that differential; it is what
collapsed the search space after five wrong hypotheses.

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
