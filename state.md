# state.md — session handoff

## Headline
7 greeter-blocking kernel bugs FOUND + FIXED this session (measured, committed,
boot-verified, branch B318 pushed). The ENTIRE kernel seat/graphics/udev chain
now works: **`CAN_GRAPHICAL=1` achieved** (seat0 graphical, card0 tagged
master-of-seat, GPU detected via 61-gdm.rules -> `gdm-machine-has-hardware-gpu`).
Greeter still doesn't render — two REMAINING issues, both now measured:
 (1) `CAN_GRAPHICAL=1` is INTERMITTENT (~1-in-several boots; a race in card0
     coldplug tagging — most boots get =0).
 (2) gnome-shell (the greeter session) NEVER launches even when CanGraphical=1;
     gdm starts but forks no greeter. Plus NAMESPACE failures (accounts-daemon:
     `Failed to set up mount namespacing: /run/systemd/seats: No such file or
     directory` — for a path that DOES exist; smells like ANOTHER mount-ns
     visibility bug, same class as the mnt_root fix), missing `/usr/bin/plymouth`
     (non-fatal), and a missing `path_id` udev builtin (71-seat.rules:75).
Boot is also ~4.5 min now (udevd does real coldplug work — each device slow).

## Fixes landed this session (branch B318, PR #2338, all pushed)
- eb225e9a fix(kernfs): implement `rename` -> /dev (devtmpfs) supports udevd's
  atomic symlink-via-rename; udevd completes device workers -> master-of-seat
  tag -> **CAN_GRAPHICAL=1**.  <- the breakthrough
- 6caec86e fix(sysfs): block/input `uevent` WRITABLE + emit -> coldplug no longer
  EROFS; udevd receives device uevents.
- 21b4368e fix(sysfs): drm device_add uevent DEVPATH -> devices/virtual/drm/<card>
- 3a477d2b fix(vfs): identify a mount by `mnt_root` not `sb.s_root`  <- seat0
- 8e81fd93 fix(vfs): d_drop must not unhash a mounted dentry (D_MOUNTED guard)
- 18200270 fix(sysfs): /sys/dev/char/226:0 -> devices/virtual/drm/card0
- crates/kernel/vfs/tests/greeter_sysfs_after_pivot.rs — 5 hosted tests (pass).

## NEXT frontier — greeter session doesn't launch  [START HERE]
1. gnome-shell never spawns. Even in a CAN_GRAPHICAL=1 boot, gdm starts but
   forks no greeter (`grep gnome-shell` = 0). Measure: does gdm try to exec
   gnome-shell / gdm-session-worker / Xorg and fail? (unconditional execve-ENOENT
   trace at 059_execve.rs:75 — was used this session, gated behind debug-boot).
   STRONG candidate: the NAMESPACE failures. `/run/systemd/seats: No such file or
   directory` for a path that DOES exist (seat0 is created) => the service's
   sandbox mount-ns can't SEE it. Same class as the /sys mnt_root bug just fixed.
   Measure: does `/run/systemd/seats` resolve in the failing service's ns vs
   globally? (fsid + exe probe, the method that cracked /sys). If it's a ns
   visibility bug, fixing it likely unblocks BOTH accounts-daemon AND the greeter.
2. CanGraphical intermittent. card0's coldplug tag is racy — measure across N
   boots whether `/run/udev/tags/master-of-seat/c226:0` is written each time.
3. Image/userspace: missing `/usr/bin/plymouth`, missing `path_id` udev builtin.

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
