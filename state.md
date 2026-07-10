# Handoff — ext4 SMP corruption FIXED (B707); live-gnome now blocks on an all-idle wakeup stall

Goals 1 (console) + 2 (ext4) done. Goal 3 (visible gnome desktop): the big
blocker of this whole campaign is FIXED and boot-verified. New frontier below.

## Landed this session (merged to main)
- **B707 / PR#2936 — ext4 metadata-transaction race (the rootfs corruptor).**
  `run_journaled` (write_at/unlink/truncate/alloc_block/free_block/inode-alloc)
  had NO serialization; only `create_op` held `op_lock`. Concurrent tasks/CPUs
  raced the group bitmaps/GDT/counters/shadow → double-alloc, wrong counts, stale
  csums, unattached inodes. This corrupted the rootfs during boot (e2fsck: group
  13 block-bitmap csum, group 5 inode-bitmap csum, unattached inode 43017) and
  the resulting garbage inode-table blocks yielded garbage `Arc<dyn InodeOps>` →
  the ~55-65s #UD / `Weak::upgrade` panic that dominated this session. NOT a
  kernel UAF, NOT udevd (the debug-heappoison "udevd UAF" lead was a misdirection;
  the user's e2fsck evidence cracked it). Fix: reentrant transaction gate in
  `run_journaled` keyed on `ctx_id()` (kernel: task-id hook set by kmain via
  `ext4::mount::set_ctx_id_hook`; hosted: per-thread). Gate:
  `crates/kernel/ext4/tests/balloc_uninit_e2fsck.rs` — 4-thread create/write/unlink
  churn on a clean-image copy, asserts `e2fsck -fn` clean (reproduced the exact
  boot corruption before, clean after, 3/3). Full ext4 suite + both arches green.
  [[gnome-blocker-refcount-uaf]] [[ext4-work-no-booting]]
- **C108 / PR#2935 — debug-heappoison** (off-by-default UAF localizer). Kept as a
  tool though its "udevd UAF" conclusion was wrong.

## Boot-verify (smp=2, fresh rootfs) — corruption GONE
No FAULT / PANIC / EIO / BadChecksum / spawn-fail. Boots clean through
journal-flush + userdbd (~24s). The ext4 fix is confirmed end-to-end.

## NEW frontier — all-idle missing-wakeup at ~24-35s (separate, pre-existing)
After `systemd-userdbd` starts (~24s), the system goes fully idle and a watchdog
fires: `[CPU-STALL] cpu=0 no heartbeat for 10s (seen by cpu=1) tid=0 syscall=none
nr_running=0`. All tasks blocked, nothing runnable, nothing wakes CPU 0 → missing
wakeup. NOT the txn gate (a gate spin-deadlock would show nr_running>=1; this is
nr_running==0). Prime suspect: af_unix listener accept-readiness → epoll wake for
userdbd's varlink socket, or a timerfd/futex wake. [[desktop-blocker-tmpfiles-userdbd]]
Note: this boot used `rebuild_rootfs=true`; confirm the fresh image carries the
../images nss fix (`group: files systemd`) — if not, this may be the userdb stall.

## First commands next session
1. `cd /home/nd/oxide/kernel && git log --oneline -3`  # main @ 200552b9 (B707 merge)
2. Repro: `mcp__qemu__qemu_start arch=x86_64 features=debug-boot,debug-wakelat smp=2 mem=4G rebuild_rootfs=true`
   → run_until 'CPU-STALL' (fires ~35s). debug-wakelat shows the last WLBLK (what
   the idle tasks are parked on) before the stall.
3. Identify the parked service + what should have woken it (af_unix accept / epoll
   gen / timerfd). Hosted-repro the wake path if possible.

## Gotchas
- run_until / qemu_serial buffers hit the 63KB token cap — the visible tail may be
  EARLIER than the guest's real position; parse the saved tool-result file, and
  check for `[CPU-STALL]` / `[NMI-BT]` which appear at the true tail.
- gdb `qemu_interrupt` won't preempt a `cli;hlt` idle/panic — read serial.
- ext4 corruption: reproduce hosted (writable image copy + `e2fsck -fn`),
  CONCURRENTLY (single-threaded churn is clean). No boots for ext4 [[ext4-work-no-booting]].
- Clean gnome image: `/home/nd/oxide/images/out/gnome-x86_64-root.img` (dumpe2fs/e2fsck OK).
