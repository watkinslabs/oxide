# state.md — session handoff

## Headline
**Primary greeter blocker FOUND + FIXED (measured, committed, boot-verified):**
logind now attaches devices and `/run/systemd/seats/seat0` is created (was
absent). Branch B318 (pushed): the `mnt_root` mount-identification fix + d_drop
invariant + dev_index_target symlink fix. Remaining gate: `CAN_GRAPHICAL=0` —
card0 still not attached because logind's `/run/udev` has no `tags`/`data`.

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

## NEXT blocker — CAN_GRAPHICAL=0: udevd writes NO device db/tags  [START HERE]
MEASURED (decisive, and the mount fix is RULED OUT as the cause):
- logind's `/run/udev` = fsid 0x8, contains ONLY `control` — `tags`/`data`
  `<unresolved>`. So `/sys/dev/char/226:0` is never chased (dev-index 226:0
  lookup fires 0×), card0 never attaches → `CAN_GRAPHICAL=0` → gdm child exits 1.
- WHY: a broad probe (any openat whose RESOLVED path is under `/run/udev/`,
  W=create/write vs r) shows **udevd makes ZERO writes to `/run/udev/data` or
  `/run/udev/tags`** — it only READS. So udevd never reaches `device_update_db`
  / `device_tag`. No tags because nothing is written, not because of visibility.
- REGRESSION RULED OUT: temporarily reverting ONLY the mnt_root fix (keeping
  d_drop) and re-booting → udevd STILL writes 0. So udevd-not-writing is
  PRE-EXISTING, not caused by this session's changes. The mnt_root fix is a real
  correctness win (logind /sys works, seat0 created) and stays.

So the real remaining gate is CARD0 UEVENT DELIVERY. Full measured timeline:
- t=1.84: kernel emits card0's device_add uevent
  (`add@/devices/virtual/drm/card0` AFTER the devpath fix — commit 21b4368e;
  was `/devices/platform/dri/card0`). BUT `listeners=0 grp1(udevd)=0` — udevd
  isn't up yet (starts t=8.5), so this initial emit is LOST.
- t=5.29–6.12: systemd-udev-trigger (coldplug) runs. It DOES enumerate
  `/sys/class/drm` (probe fired t=5.80), so it FINDS card0. BUT it does NOT
  write card0's `uevent` (DrmUeventFileOps::write probe fires 0×) — so card0 is
  NEVER re-triggered. udevd (t=8.5) thus never receives card0 → never runs
  device_update_db/device_tag → no `/run/udev/tags/master-of-seat/c226:0` → no
  attach → `CAN_GRAPHICAL=0` → gdm child exits 1.

**NEXT: why does udev-trigger enumerate card0 but not write its uevent?**
Measure (drm.rs probes, klog): trace card0's `uevent` file OPEN (read vs write,
which path — `/sys/class/drm/card0/uevent` symlink vs `/sys/devices/virtual/drm/
card0/uevent`) during coldplug. Candidates: (a) udevadm trigger opens uevent
O_WRONLY and the write is dropped/misrouted (not reaching DrmUeventFileOps::
write); (b) the enumerator lists card0 but a match/filter skips the trigger
write; (c) the write targets the class symlink and symlink-target write doesn't
resolve to the device uevent. Also verify the group-1 udevd socket is bound
(grp1≥1) by t≈5.8 so a re-emit would actually buffer.
Then: the LIVE cooked-uevent path (udevd→logind monitor) was ALSO measured
broken long ago (COOKTRACE=0) — likely a SECOND fix needed for live attach.
Latent: drm.rs:114 subsystem symlink `../../../class/drm` (3 ups) → wrong;
should be `../../../../class/drm` (4 ups). Basename still "drm" so non-fatal.

Also latent (fix once card0 attaches): drm.rs:114 subsystem symlink is
`../../../class/drm` (3 ups) → resolves to /sys/devices/class/drm (wrong);
should be `../../../../class/drm` (4 ups) like block.rs/input.rs. sd_device reads
SUBSYSTEM by symlink BASENAME so it still yields "drm", but fix it anyway.

## Landed this session (branch B318, PR #2338, all pushed)
- 21b4368e fix(sysfs): drm device_add uevent DEVPATH → devices/virtual/drm/<card>
- 3a477d2b fix(vfs): identify a mount by mnt_root not sb.s_root  ← THE big fix
- 8e81fd93 fix(vfs): d_drop must not unhash a mounted dentry (D_MOUNTED guard)
- 18200270 fix(sysfs): /sys/dev/char/226:0 → devices/virtual/drm/card0
- crates/kernel/vfs/tests/greeter_sysfs_after_pivot.rs — 5 hosted regression
  tests for sysfs reachability across sandbox relocation (all pass).

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
