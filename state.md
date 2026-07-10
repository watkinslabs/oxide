# state — live-gnome boot (Goal 3)

Branch: `main` (clean). Two fixes merged this session; live-gnome still blocked by ONE heap UAF.

## Landed this session
- **B709 (PR#2944, merged)** — sb-root `d_count` pin. `d_make_root` inc_count; `get_mountpoint`
  dget / `put_mountpoint` dput; `dput` never kills an `is_root` dentry. Removed the
  `resolve_mount`/`mounts_in_ns` #PF-on-dead-root fault class.
- **B710 (PR#2945, merged)** — `rseq_writeback` pre-validates the user VMA (present+WRITE)
  before writing (kernel has NO exception table). Removed a userspace-triggerable kernel #PF.

Both correct + Linux-faithful, but both fixed DOWNSTREAM victims, not the root corruptor.

## The remaining blocker (the real Goal-3 wall)
ONE heap **UAF**: a stale pointer writes small values (0,1,4)/garbage into a FREED block;
whatever reuses that fixed slot is the victim, so the symptom moves with layout but the
trigger is deterministic (~54s live-gnome boot). All one bug:
- `resolve_mount`/`mounts_in_ns` #PF on a DEAD sb-root dentry  → B709 (victim fixed)
- `Task.rseq_ptr` corrupted to `4` → rseq #PF               → B710 (victim fixed)
- `Task::state corrupt` panic (sched/task/methods.rs:239, AtomicU8 scribbled)
- under `debug-heappoison`: boot reaches **96s** then `KAlloc::dealloc+0x177` #PF,
  cr2=garbage (corrupt free-list next-ptr). Poison delaying reuse = proof it's a UAF.

`uaf_lookup` (hal-x86_64/fault.rs:316) runs on every #PF GPR but printed no `[UAF]`:
corruption already propagated past the quarantine window. It only names a victim while a
GPR still points into freed+poisoned memory.

## NEW this session — it is a REUSE-dependent UAF (proven)
Enlarging the poison quarantine ring (QN 2048->16384, ~64MB held-out, 4G RAM) delayed block
REUSE and pushed the boot 55s -> 162s (past nearly all services, into systemd-udevd) with NO
crash. So the crash needs a freed block to be REUSED; holding it out avoids the fault. That
is a use-after-free where REUSE supplies the garbage the stale ref then derefs (faults are
consistently near-null derefs: cr2 = 4/9/0x71/0xbb = a pointer field read as null/small).
Poison variants tried this session (all feature-gated `debug-heappoison`, OFF by default;
uncommitted diag lives in `crates/shared/kalloc/{src/poison.rs,Cargo.toml}` layered on top of
another lane's redzone helpers — do NOT `git checkout` poison.rs, it would nuke their work):
- verify-on-eviction + periodic poison-head scan (first 16B, offset 0/8 = Arc refcounts):
  fired NOTHING -> corruption is NOT a write to a quarantined block's head.
- big ring (QN 2048->16384) + full-block 0xEE poison: NO crash, NO uaf hit, boot crawls to
  152-162s. => poison MASKS this bug (holding blocks out of reuse removes the trigger; the
  stale ref never reads a still-poisoned block in the window). Confirms reuse-dependent UAF
  but poison-catching is a dead end here.

## Next task (do NOT blind-boot / do NOT spin more poison variants — that is the thrash)
The decisive non-perturbing tool is a **HW watchpoint** on the recurring victim slot in a
NORMAL (non-poison) build:
1. Boot a debug-boot build, reach the ~55s crash, note the corrupted victim VA from the FAULT
   regs (mounts_in_ns is the most frequent site; dead-root was 0x810d7b28 pre-B709).
2. Reboot the SAME build; DON'T set breakpoints at entry (kernel VA unmapped -> "Cannot insert
   breakpoint"). Instead run_until an early post-paging marker (~5s), interrupt, then set a
   gdb hardware `watch`/`rwatch` on that VA, continue, catch the store/read + backtrace = the
   corruptor. (Note: can't interrupt AFTER a fault — the handler does cli;hlt — so set the
   watchpoint BEFORE ~55s.)

Suspects: fork/COW churn; a Weak/raw ptr outliving its Arc (smp=1 panic Weak::upgrade
sync.rs:3287); epoll Arc<File> (smp=2 #UD); the MOUNTS BTreeMap (mounts_in_ns most frequent).

## First command next session
Boot debug build, capture exact victim addr at the ~54s crash, reboot same build paused,
set a gdb write-watchpoint on that addr to catch the corrupting store:
`make kernel boot PROFILE=live-gnome ARCH=x86_64` (or qemu MCP `qemu_start`).

Uncommitted in tree (other lane, do not commit with kernel fixes):
`crates/shared/kalloc/src/poison.rs`. Untracked scratch: `again.ms`, `round2.md`, `log.txt`.
