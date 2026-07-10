# Handoff — Goal 3 blocker CONFIRMED a UAF in udevd's kernel path (heap-poison proved it)

Goals 1 (console) + 2 (ext4) done. Goal 3: boot runs the full dbus/logind/NM
stack; dies ~55-65s in a refcount abort BEFORE gnome-shell/gdm. This session
BUILT a heap-poison diagnostic and used it to PROVE the crash is a use-after-free
(not an overflow, not an SMP race) living in udevd's device-enumeration path.

## What's proven now (evidence, not hypothesis)
1. **Not an SMP race.** smp=1 PANICs `alloc/src/sync.rs:3287` (Weak::upgrade
   overflow) ~65s; smp=2 #UDs on an Arc<File> strong-clone in epoll scan_once
   ~55s. A count > isize::MAX ⇒ reading freed-and-reused memory ⇒ UAF.
2. **It's a UAF in udevd's kernel path (CONFIRMED causally).** With
   `debug-heappoison` on (poison the leading 16B of freed blocks 0xEE +
   quarantine to delay reuse):
   - NON-poison boot: `Started systemd-udevd.service` at 46.6s (udevd works).
   - POISON boot (full-block AND 16B-head): udevd `Main process exited,
     code=exited, status=1/FAILURE` on its FIRST start, restart-loops forever.
   ⇒ udevd's kernel path READS a freed object's leading word (refcount/ptr at
   off 0-16). Non-poison: that block is reused → garbage huge count → epoll #UD.
   Poison: leading word = 0xEE → udevd gets bad data → exit 1. Same root UAF.
3. Because udevd dies under poison, the fork/openat/epoll STORM never builds →
   the original #UD is masked → the [UAF] fault-probe never fires (udevd exits
   cleanly, no CPU fault). So the tool CONFIRMED the UAF but hasn't NAMED the
   exact free-site yet.

## The diagnostic tool (merged, off by default) — `debug-heappoison`
- `crates/shared/kalloc/src/poison.rs`: poison leading 16B of freed blocks
  <=4096B with 0xEE, hold in a 2048-entry quarantine ring (delay reuse), really
  free only on eviction. `kalloc::uaf_lookup(addr)` → (base,size) if addr is in
  a quarantined (freed) block.
- `crates/arch/hal-x86_64/src/fault.rs`: on an unhandled fault, sweeps every GPR
  through `uaf_lookup` and prints `[UAF] reg=.. ptr=.. IN FREED block base=..
  size=..` — size names the victim type. (Only fires on a CPU fault.)
- Cascade: `kmain` feature `debug-heappoison = ["kalloc/debug-heappoison"]`.
  Boot: `qemu_start features=debug-boot,debug-heappoison smp=2`.

## NEXT — name the free-site (pick one; the FIRST is the sharp experiment)
1. **Force the silent udevd UAF to FAULT so the probe names it.** Change the
   poison of the leading 8B to a NON-CANONICAL POINTER (e.g. 0x00DE_AD00_DEAD_00DE)
   instead of 0xEE. If the freed object's leading word is a deref'd POINTER
   (vtable / next / data ptr — many kernel structs), udevd's read → #GP/#PF →
   the GPR sweep prints [UAF] with the freed block's base+size. (0xEE only traps
   the Arc-COUNT case via #UD, which udevd doesn't reach.) One boot, smp=2.
2. **Audit udevd's kernel path for a freed-object read**: AF_NETLINK
   kobject_uevent, sysfs/kernfs, devtmpfs/devfs dentry-inode lifecycle, inotify
   on /dev. Prime: a dentry/inode/kobject freed while a uevent/netlink skb or a
   devfs registry entry still references it. Related: [[mknod-bypasses-dcache-negative]],
   [[mount-dentry-sharing-gotcha]], the "13 unreaped zombies" lead
   [[qemu-vsock-cid-and-sigchld-reap]].
- RULED OUT by code-read (refcount-correct): fdtable fork_clone/get/close/dup,
  epoll scan_once, zombies park/unpark, File Drop, runqueue swap_current.

## First commands next session
1. `cd /home/nd/oxide/kernel && git log --oneline -3`
2. Experiment 1: edit `crates/shared/kalloc/src/poison.rs` POISON to a
   non-canonical ptr for the first 8B, rebuild, `qemu_start
   features=debug-boot,debug-heappoison smp=2`, run_until '\[UAF\]|FAULT|PANIC'.
3. If it faults with [UAF] size=N → find the type with sizeof == N → audit its
   free vs the udevd read that keeps a stale ref.

## Gotchas
- gdb `qemu_interrupt` will NOT preempt a `cli;hlt` panic-halt (times out) — read
  crashes from serial, not the backtrace.
- run_until buffers exceed the token cap; parse the saved tool-result file w/ python.
- No boot-per-hypothesis loops [[no-repeated-long-boots]] — 3 poison boots done;
  the non-canonical variant is the ONE decisive next boot, then audit.
- live-gnome→gnome image (2.8GB); backups ../images/out/*.premerge.bak.
