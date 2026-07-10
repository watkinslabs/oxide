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

## Next task (do NOT blind-boot per no-repeated-long-boots)
Catch the WRITER, two options:
1. **HW write-watchpoint (non-perturbing, preferred).** The victim VA is stable across builds
   (dead-root was 0x810d7b28 / lockref +0x68 = 0x810d7b90). Boot a debug-boot build, set a
   gdb hardware write-watchpoint on that qword before ~54s, catch the store of the garbage
   value → names the corruptor + stack. (Same build, <=2 boots.)
2. **Wire redzone / poison-verify into KAlloc.** `crates/shared/kalloc/src/poison.rs` already
   has (uncommitted) `alloc_layout`/`arm_redzone`/`check_redzone` (REDZONE_BYTES=32). Pad every
   alloc + verify at dealloc -> catches an overflow writer at free time. Also add a
   full-block-fill + verify-on-eviction to catch a UAF write into a quarantined block.
   NOTE: poison-based tooling MOVES this layout-sensitive bug (see memory); watchpoint is
   less perturbing.

Suspects (prior notes): fork/COW churn; a Weak/raw ptr outliving its Arc (smp=1 panic
Weak::upgrade sync.rs:3287); epoll Arc<File> (smp=2 #UD).

## First command next session
Boot debug build, capture exact victim addr at the ~54s crash, reboot same build paused,
set a gdb write-watchpoint on that addr to catch the corrupting store:
`make kernel boot PROFILE=live-gnome ARCH=x86_64` (or qemu MCP `qemu_start`).

Uncommitted in tree (other lane, do not commit with kernel fixes):
`crates/shared/kalloc/src/poison.rs`. Untracked scratch: `again.ms`, `round2.md`, `log.txt`.
