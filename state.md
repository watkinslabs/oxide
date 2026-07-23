## Handoff: corruptor free-site DETERMINISTICALLY NAMED (FdTable::close); reframed = stale raw-Arc refcount op

### Headline — the multi-session heap corruptor is now cornered to a specific class
Built a **free-IP provenance** diagnostic (C204, merged) that records each kalloc block's
last dealloc-return-IP and prints it when a corrupt free-list node is found. Because the
corrupt node is FREE when detected, its last free-IP names where the WRITER's victim was
freed. RESULT (deterministic, cracked a multi-session mystery):
```
[KALLOC] corrupt-node last-free-ip base=ffffffff819a3d58 free_ip=0xffffffff805e9345
  → addr2line → vfs::fdtable::model::FdTable::close  (the drop(f) → File::Drop)
```
So the corrupt block is an **`ArcInner<File>`** (or a dentry/inode freed inside File::Drop).

### Reframed mechanism (2nd agent) — a stale raw-Arc REFCOUNT op, NOT a list-pointer write
`ArcInner<T>` layout: strong@0, weak@8, data@16. kalloc's `HoleHdr{size@0, next@8}`.
The corrupt node's `next@8` (e.g. `0x…819a1460`) is kalloc's OWN free-list link (a real
free hole in the arena) — NOT an external write. The DAMAGE is at `size@0` = the freed
ArcInner's old strong-count word, overwritten to a count-like value (`0x1FFFFFFFF`, `0`,
`0xaaaaaa`). ⇒ the corruptor is a **stale `Arc::increment_strong_count`/`from_raw`/manual
refcount store** on a raw pointer to a block that was freed and recycled (as an
ArcInner<File> this run — victim varies by layout, matching the whole hunt's signature).
This CONFIRMS the original 3-agent CPU-UAF thesis and pins the class.

### Where the stale raw-Arc op lives (suspects) — sched/mm raw-refcount machinery
grep: NO raw `Arc<File>`/`*const File` `into_raw`/`from_raw`/`increment_strong_count`
anywhere in vfs/fs/net/mm. ALL the heavy manual raw-Arc machinery is on **Task/
AddressSpace/AnonVma/FileRmap/Tty in sched/mm**: `sched/live/wait_list.rs:95-97`,
`runqueue.rs`, `schedule/active_mm.rs`, `zombies.rs`, `futex/wait.rs`, and
`schedule/switch.rs finish_switched_from` (writes on_cpu via raw Task ptr). **B1345
(merged) fixed ONE such instance** (msleep leaked a one-shot → wake_all on a freed stack
WaitList). At least one MORE stale raw-Arc op remains — a stale `increment_strong_count`
/`from_raw`/`on_cpu.store` on a freed Task/AS pointer.

### First task next session — NAME THE WRITER (free-IP named the victim; now catch the write)
1. **Targeted HW watchpoint**: `debug-hw-watchpoint` exists (C203 fixed its false-positive
   storm) but the v1 single-block scope MISSED (writes an OLD freed block). Enhance: when
   kalloc frees a block, if the free-IP is FdTable::close (or just: rotate all 4 DR regs
   over the last-N frees and HOLD them), arm+HOLD the watchpoint; the stale
   increment_strong_count store then #DB-names the writer rip via hal-x86_64 `[HWWP]`.
2. **Audit the sched/mm raw-Arc ops** (the list above) for a `raw` that can be stale:
   `rq.switched_from`/`reap_pending`/`current` used after the Task frees via a non-tracked
   path; a `Weak`/`Arc` `from_raw` double-reclaim; an `increment_strong_count(raw)` where
   `raw` outlived its Arc. B1345 was exactly this shape.
3. Verification is now DETERMINISTIC: after a candidate fix, the free-IP tool should stop
   printing corrupt nodes (and boots stop crashing at `[ZRAM-SYSFS] disksize=`).

### Separate REAL bug found (agent #1) — OFD/POSIX record locks never released on close
`crates/kernel/fs/src/posix_lock.rs`: `release_for_file` (:242) is documented "called from
`vfs::set_drop_hook` chain" but **`vfs::set_drop_hook(...)` is NEVER called** in the repo
(only defined, `vfs/file/hooks.rs:20`). File::Drop's flock hook (`file/lifetime.rs:29-35`)
is ALSO gated on `flock_op != 0`, and **`flock_op` is never written** (dead gate,
`file/model.rs:93`). So an `fcntl(F_OFD_SETLK)` lock (keyed `Owner::Ofd(Arc::as_ptr(file)
as usize)`, `072_fcntl.rs:295`) SURVIVES File::Drop and leaks in
`posix_lock::TABLE`. Linux-incompat: a NEW open at the reused address inherits stale
locks. FIX: install the hook at boot AND fire it unconditionally in File::Drop (drop the
dead flock_op gate), or fold OFD release into the unconditional
`inode.file_lock_context().release_file(self_ptr)` at `lifetime.rs:28`. (`LockEntry.owner`
is a value key, never dereferenced — a correctness bug, NOT the offset-0 corruptor.)

### Session scoreboard (8 PRs merged)
B1344 IRQ-safety deadlock fix; B1345 msleep one-shot stale-WaitList UAF fix; C202
corruption-probe on fast profile; C203 HW-watchpoint disarm; C204 free-IP provenance
(named the free-site); D360 corruption characterization (CPU stale-kernel-ptr static-heap
UAF; device/mapping/buddy ruled out; victim = offset-0 Rust Box/Vec/String, kmalloc ruled
out — kmalloc/devm put data at base+32 so can't hit offset-0 HoleHdr).

### Boot recipe
`qemu_start(x86_64, features="debug-boot,debug-dealloc-diag", paused=false)` → **then
`qemu_continue`** (REQUIRED; times out 120s = expected) → `qemu_serial` (>90KB → saved to
file; python-grep `last-free-ip|corruption-probe|invalid-free-span|merge-header-outside|[PANIC]`).
`addr2line -Cfi -e <elf> 0x<free_ip>` names the victim's freer. `qemu_stop` each instance.
