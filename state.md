# Handoff — live-gnome boots to graphical.target + gdm; 2 real fixes; next = epoll File-refcount #UD

Main has B706 merged (+ B703/B704/B705 earlier). Goals 1+2 done. **Goal 3 hugely
advanced this session: from "246s userdb stall, never reaches sysinit" → boots to
graphical.target in ~50s, gnome services spawn (dbus-broker/udevd/resolved start),
gdm reaching. Blocked now at ~55s on a kernel #UD in epoll scan_once.**

## Landed this session (all merged)
- **nss fix (../images, config)**: dropped `[SUCCESS=merge]` → `group: files systemd`
  on lite+gnome trees; re-packed both images (userns mkfs.ext4 -O ^has_journal -d);
  repointed `output/live-gnome-x86_64-root.img -> gnome-x86_64-root.img`. Killed the
  ~240s userdb keep-alive stall. Backups `out/*.img.premerge.bak`. [[desktop-blocker-tmpfiles-userdbd]]
- **B706 (#2933)** ext4: alloc_inode read+csum-verified the on-disk inode bitmap for
  EXT4_BG_INODE_UNINIT groups (mkfs lazy-inits high groups on large images) → stale
  block → BadChecksum → EIO. On the 2.8GB gnome image (groups 6-21 UNINIT) every
  PrivateTmp service's mkdir /var/tmp/... + /run/udev EIO'd → "Failed to spawn 'start'
  task: EIO" → all of dbus/logind/resolved/udev/rtkit/upower failed. Fix: synthesize a
  zeroed bitmap for UNINIT groups. Boot-verified spawn failures 19→0. Real ext4 bug.

## NEXT BLOCKER (precisely located) — #UD in epoll scan_once (File Arc refcount)
At ~54.9s (gnome services starting): `[FAULT] vec=6 (#UD) rip=ffffffff80104f79`.
addr2line → `fs/src/epoll.rs` `scan_once`. Disasm: the abort is reached via
`0x80104c13: lock incq (%r14); 0x80104c17: jle <ud2>` — an **Arc<File> strong-count
increment inside `fdt.get(e.fd)`** (r15=FdTable, rdx=e.fd, r14=the File* at that slot)
that aborts because the incremented count is <= 0 (overflow/corruption). So epoll's
per-scan `fdt.get(e.fd)` clones a File whose refcount is garbage → **use-after-free /
dangling File in the fd table** (or a refcount that wrapped), exposed by gnome's heavy
fd open/close churn. Not reproduced on lite (lighter fd load).
NEXT: instrument scan_once to log e.fd + File ptr + strong_count before the clone; find
which fd (type/name) has the bad File. Likely a fd-table slot not cleared on close while
still in an epoll interest set, or an epoll entry holding a stale fd whose slot was
reused. Hosted test: register an fd in epoll, close it, epoll_wait → must not UAF.

## First commands next session
1. `cd /home/nd/oxide/kernel && git log --oneline -3`  # main @ dbf588a9
2. Boot: `mcp__qemu__qemu_start arch=x86_64 features=debug-boot accel=kvm smp=2 mem=4G rebuild_rootfs=true`
   → run_until 'FAULT.*UD' (fires ~55s). It IS the gnome image now (live-gnome→gnome).
3. Add a scan_once trace (e.fd, Arc::strong_count(&f)) BEFORE the fdt.get clone; boot;
   the last fd before #UD = the culprit. Then fix the fd/File lifecycle bug.

## Gotchas
- NEVER `git add -A`. ext4 = hosted + e2fsck [[ext4-work-no-booting]].
- live-gnome now boots the GNOME image (2.8GB); backups at ../images/out/*.premerge.bak.
- gnome image geometry: 22 groups, 6-21 INODE_UNINIT (why B706 mattered).
