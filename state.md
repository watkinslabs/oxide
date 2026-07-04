# state.md — session handoff

## Headline
Multiple greeter-blocking bugs FOUND + FIXED this session (all measured,
committed, boot-verified on branch B318, pushed). The chain now gets much
further: logind's `/sys` works, seat0 is created, coldplug succeeds, udevd
processes devices, and **card0's uevent now reaches udevd** (grp1=1 at t=6.1).
Still `CAN_GRAPHICAL=0` — the NEW frontier is that udevd processes PCI/platform
devices (107×, a re-processing loop → boot slowdown) but does NOT complete the
VIRTUAL devices (drm card0 / block / input): no `/run/udev/data/c226:0` db and
no master-of-seat tag is ever written, so seat0 never becomes graphical.

## Fixes landed this session (branch B318, PR #2338, all pushed)
- 6caec86e fix(sysfs): block/input `uevent` WRITABLE + emit → coldplug (udevadm
  trigger) no longer fails EROFS; udevd now receives device uevents.
- 21b4368e fix(sysfs): drm device_add uevent DEVPATH → devices/virtual/drm/<card>
- 3a477d2b fix(vfs): identify a mount by `mnt_root` not `sb.s_root`  ← seat0
- 8e81fd93 fix(vfs): d_drop must not unhash a mounted dentry (D_MOUNTED guard)
- 18200270 fix(sysfs): /sys/dev/char/226:0 → devices/virtual/drm/card0
- crates/kernel/vfs/tests/greeter_sysfs_after_pivot.rs — 5 hosted tests (pass).

## NEXT frontier — udevd doesn't complete VIRTUAL devices  [START HERE]
MEASURED (probe: any openat under /run/udev/data|tags with a write flag, + emit
grp1 for drm):
- card0's uevent IS emitted+delivered: `add@/devices/virtual/drm/card0 grp1=1`
  at t=6.121 (coldplug, udevd's group-1 socket up since t=3.98).
- udevd writes 107 `.#+pci:...` + 2 `.#+platform:...` db files — but ZERO for
  block/input/drm/virtual, and ZERO tag writes. So it processes PCI/platform,
  never completes card0 (no `/run/udev/data/c226:0`, no master-of-seat tag).
- 107 writes for a handful of PCI functions ⇒ a RE-PROCESSING LOOP (likely the
  `bind_device_cb` "change" uevent re-triggering process→bind→change), which is
  also why the boot is ~3–4× slower (reaches graphical ~150s vs ~43s).
Candidates to MEASURE next:
1. Does udevd spawn a worker for card0's event and does it FAIL/exit? Check
   `[EXIT] exe=...udev...` + recent-syscall ring right after t=6.1.
2. Is card0's RAW uevent well-formed enough for udevd to build the sd_device
   (ACTION/DEVPATH/SUBSYSTEM/MAJOR/MINOR/DEVNAME)? drm.rs write emits all; verify
   udevd's from-uevent device build succeeds (a missing key drops it silently).
3. The PCI re-process loop: is `bind_device_cb`/driver-bind emitting "change"
   in a cycle? If udevd is saturated looping on PCI, card0's queued event may
   just never get a worker. Fix the loop first — it may unblock everything.
Also still latent: the LIVE cooked-uevent path (udevd→logind monitor) measured
broken earlier (COOKTRACE=0) — needed for live attach once card0 is tagged.
drm.rs:114 subsystem symlink is 3 `../` (should be 4) — basename still "drm", non-fatal.

## What was THE bug (measured end-to-end, not guessed)
`containing_mount_id → parent_by_dentry → visible_mnt_id_of_root_dentry /
mount_with_root_dentry` matched a mount by **`sb.s_root()`**. A bind/clone
mount's real root dentry is the PER-MOUNT `mnt_root` override, which differs from
the shared `sb.s_root()`. So a task chrooted/pivoted onto a systemd-sandbox bind
root resolved its root dentry to the NS-ROOT mount instead.

MEASURED chain (via probes on the ACTUAL inode logind's openat returns, no
re-resolve): logind root dentry = mnt 397's `mnt_root` (`is_root=1`,
`owner_mnt=397`), but `containing_mount_id` returned **381** (ns root) →
walk seeded mnt 381 → `__lookup_mnt(381, /sys-dentry)` missed the sysfs under
397 → logind's `/sys` = empty ext4 underlay (fsid 0x1, while 159 other opens got
sysfs 0x0102199400000002) → `/sys/dev/char/226:0` ENOENT → no device attach → no
seat0. FIX (commit 3a477d2b): match on `mnt_root()` (falls back to sb.s_root, so
singleton procfs/sysfs sharing is unchanged) + collapse to the ns-root id only
when a candidate IS the ns root (a sandbox bind root is self-parented `is_root()`
but is a task's private root, not the ns root). RESULT: containing_mount_id → 397,
`/sys` crosses into sysfs, seat0 created. 98+ vfs tests green. Boots reliably
(seat0 in 3/3; a graphical=0 boot is the pre-existing ~50% GRUB-hang, not a
regression — see CLAUDE.md).

## Diagnostic method that WORKED (measure, don't guess)
The decisive probes: (a) log the fsid of the ACTUAL inode `openat` returns (no
re-resolve → no root-provider ambiguity); (b) `current()->exe_path` to identify
the process; (c) compare `root_vfs.mnt_id` vs `containing_mount_id(root_dentry)`
vs `root_mount_id(ns)`; (d) scan `all_mounts()` for the one whose `mnt_root()`
IS a given dentry. All traces were reverted after use.

## Boot harness
`bash <scratchpad>/boot.sh <log> 100` (kills stale qemu, boots live-gnome ISO,
serial→log). Build: `cd ../oxide-images && make kernel ARCH=x86_64 && cd
../kernel && cargo run -q -p xtask -- artifacts --arch x86_64 && cd
../oxide-images && cargo run -q -p imagectl -- build-boot --profile live-gnome
--arch x86_64`. STALE-ARTIFACT TRAP: a compile FAIL still lets `xtask artifacts`
export the last-good kernel — always confirm the build `Finished` line.
seat0 check: `grep IS_SEAT0 <log>`; CanGraphical: `grep CAN_GRAPHICAL <log>`.

## Ledger
metadata/index.md: B next=319 (318 used this session), D next=120, F next=650.
