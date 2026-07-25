# state.md — session hand-off

## Headline
**Partial checkpoint — x86 green, ARM RED.** The ARM IRQs-on register corruption is
cracked and fixed (#3901) and ARM reached `basic.target` with IRQs-on during the
session. But main's CURRENT ARM config has a fault the verified boot did not have:
see "ARM REGRESSION" below — treat main as a checkpoint for x86 only until that is
settled. Repo fully cleaned: 377 remote branches → 1, zero stashes, zero open PRs,
clean tree. Two dead test gates repaired.

## ARM REGRESSION — first thing to fix
`make smoke-arm` on main faults at ~11.5s guest, immediately after
`elf-load: interp place ok` (dynamic-loader activity):

    esr=0x02000000 ec=0x00 (unknown)  elr=lr=0xffffffff805c11f8  far=0x7ffff77e647a

`0xffffffff805c11f8` is inside **.data**, 0x18 past
`sched::timers::backend::STATE` — the kernel took an indirect branch into data and
executed it as instructions, then cascaded (a later frame shows a branch to 0x100).

**Prime suspect, stated as a suspect and not a conclusion:** the only ARM boot
verified clean this session (qemu MCP, `basic.target`, zero faults in a 169K-line
log) ran with the **F699 per-CPU IRQ-stack switch DISABLED** — that branch had
deliberately turned it off for isolation. Main now has it **ENABLED** via #3901.
The IRQ-stack switch is SP manipulation in the IRQ entry asm, which fits a
"branched to garbage" symptom.

**The one discriminating test:** flip the IRQ-stack switch off in
`hal-aarch64/src/vbar/asm.rs` (`mov x19, sp` / `mov sp, x19`, as
`archive/F700-irqs-on-arm-crack` does) and re-run `make smoke-arm`. Fault gone ⇒
the switch is the cause; fault persists ⇒ suspect the pre-existing ARM
dynamic-loader instability that C116 recorded on 2026-07-17 (same phase of boot:
"reproducibly faulted during concurrent dynamic-loader activity", plus an observed
task kernel-stack underflow). Enable `debug-armctx` for the post-mortem dump.

NOTE: measure over N sequential boots before concluding — this is the intermittent
class, and one boot lies.

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
