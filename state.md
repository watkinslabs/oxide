# Handoff — live-gnome boot advanced 26s→53s (4 fixes merged); next = mount-registry corruption

Goals 1 (console) + 2 (ext4) done. Goal 3 (visible gnome): huge progress this
session — the boot now clears every prior blocker and reaches ~53s (NetworkManager,
accounts-daemon, rtkit, sssd, nss-user-lookup.target all start), close to graphical.

## Merged this session
- **B707/#2936** — ext4 SMP metadata-transaction race (rootfs corruption during
  boot: group-13 block-bitmap csum, unattached inodes). Reentrant txn gate. The
  session-long ~55-65s #UD/Weak::upgrade abort was a DOWNSTREAM symptom of this
  (clobbered inode table → garbage Arc<dyn>), NOT a kernel UAF.
- **B708/#2938** — four fixes; un-broke the boot B707's gate deadlocked:
  1. **ext4 gate deadlock (B707 regression, CRITICAL):** the gate busy-spun, but
     ext4 ops hold it across SLEEPING block I/O → a spinning waiter pinned its CPU
     and the sleeping owner never released → `[CPU-STALL]` in truncate_inode ~10s
     after userdbd (this WAS the "post-userdbd wakeup stall" I mis-chased as
     epoll/af_unix). Fix: gate spin yields via a hook (kmain→`sched::live::tick_yield`).
  2. **SMP virtio #PF in PCI enum:** APs on pre-PCI `kernel_master()` CR3 #PF'd on a
     virtio notify VA. Fix: `mmio_map::map_pages` resyncs the master PML4 per splice.
  3. **epoll per-epitem sub id:** ADD/DEL keyed PollSubscribers on `ep.id`; two fds
     sharing a source collided + DEL orphaned the other's wake. Now per-epitem id.
- Diagnostic tool C108/#2935 (debug-heappoison, off by default).

## NEXT BLOCKER (deterministic, reproduced #PF then #GP across 2 boots) — mount-registry garbage
At ~52.8-53.2s, during NetworkManager/accounts-daemon path resolution:
`[FAULT] #PF NP-R-K rip=vfs::mount::resolve_mount cr2=0x11a` (and a #GP on the
next boot, rbx=0x60). Disasm at the fault: a loop over a struct with two parallel
arrays — one at off 0x60 (Arc<Mount>, `lock incq` clone) and one at off 0xc0
(pointer, then `movzwl 0xba(%rax)` reads a u16 Mount field). One 0xc0-array entry
is **0x60** (garbage) → deref [0x60+0xba] faults. So a mount COLLECTION has a
corrupt/garbage entry (0x60) — a mount-subsystem UAF or bad insert, NOT caused by
this session's changes (mount code untouched). resolve_mount
(`crates/kernel/vfs/src/mount/attrs.rs:136`) calls walk_to_mount (namei/root.rs) +
mount_by_id (`MOUNTS.lock().get`) + check_mnt (`m.ns==current_ns()`).
NEXT: find which mount collection has the two-array layout (0x60/0xc0) — likely the
per-ns mount list or MOUNTS BTreeMap node — and the insert/free path that leaves a
0x60 entry. Related: [[mount-dentry-sharing-gotcha]]. Reproduce: boot smp=2 to ~53s.

## First commands next session
1. `cd /home/nd/oxide/kernel && git log --oneline -4`  # main @ addb3341 (B708 merge)
2. Boot: `mcp__qemu__qemu_start arch=x86_64 features=debug-boot smp=2 mem=4G rebuild_rootfs=true`
   → run_until 'FAULT|resolve_mount' (fires ~53s, deterministic).
3. addr2line the fault rip on the build's elf; disasm ±0x40; identify the 0x60/0xc0
   two-array struct; trace its insert/remove for the 0x60 (garbage/UAF) entry.

## Gotchas
- run_until/qemu_serial buffers cap ~64-117KB (token limit) — the visible tail may be
  EARLIER than the guest; parse the saved tool-result file with python; check for
  `[FAULT]`/`[CPU-STALL]` at the true tail.
- Boots are ~flaky; but this mount fault is DETERMINISTIC (2/2). ext4: hosted e2fsck
  gate, no boots [[ext4-work-no-booting]]. Clean image: `../images/out/gnome-x86_64-root.img`.
- The again.ms notes (root author) diagnosed the epoll+mmio blockers (both now fixed).
