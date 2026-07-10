# Handoff — BREAKTHROUGH: live-gnome boots past the userdb stall to graphical.target

Main = `e124a3f1`. Goals 1+2 done. **Goal 3 unblocked: the ~240s userdb stall is FIXED
and the system now BOOTS to graphical.target in ~50s** (was never reaching sysinit).

## THE FIX (this session) — userdb stall root cause + resolution
- Root cause (proven over many traces): NOT a kernel bug. The nsswitch
  `group: files [SUCCESS=merge] systemd` fired a systemd-userdb GetMemberships
  merge query per device-node group; the systemd-userwork worker held each
  connection for its `CONNECTION_IDLE_USEC=15s` keep-alive → ~15s × ~17 groups
  ≈ 240s → `systemd-tmpfiles-setup-dev-early` never finished → no sysinit.target.
  Every kernel theory (idle-halt ×4, TSC-deadline timer, fbcon submit_one spin)
  was disproven — the 15s floor never moved. See [[desktop-blocker-tmpfiles-userdbd]].
- FIX applied in **../images** (NOT the kernel): dropped `[SUCCESS=merge]` →
  `group: files systemd` on BOTH lite + gnome trees
  (`build/{lite,gnome}-x86_64-root/etc/authselect/nsswitch.conf`), re-packed both
  images inside `unshare --user --map-root-user --map-auto` (mkfs.ext4 -O ^has_journal
  -d), and repointed `output/live-gnome-x86_64-root.img -> gnome-x86_64-root.img`
  (was → lite, which has no gdm/gnome-shell). Backups: `out/*.img.premerge.bak`.
  It's a valid minimal-Fedora config, functionally a no-op for our groups (they have
  no extra systemd members); the user asked "do we even need this" — we don't.
- RESULT (boot-verified, qemu MCP KVM): lite image → graphical.target + getty in 50s.
  gnome image → reaches **gdm.service / GNOME Display Manager starting @58s**, all
  targets through graphical.target. `Startup finished ... = 50.087s`.

## NEXT BLOCKER (freshly exposed, precisely located) — mkdir → EIO in service setup
On the gnome image, ~9 services fail identically: **"Failed to spawn 'start' task:
Input/output error"** (ERRNO=5). Traced to: `[NAMEI] mkdir path="…" err=5` from
`sys_mkdirat` (258_mkdirat.rs:49) where `pino.mkdir` returns `VfsError::Eio` — the
PARENT resolves fine, the BACKEND mkdir returns EIO. Hits BOTH
`/var/tmp/systemd-private-<id>-<svc>-<rand>` (ext4) AND `/run/udev` (tmpfs), only
during systemd's mount-namespace / sandbox setup (PrivateTmp/ProtectSystem). Both-fs
→ NOT the backing fs; suspect the CLONE_NEWNS mount-namespace clone leaving the target
mount in a state whose backend mkdir returns EIO. Affected: dbus-broker, systemd-
logind, systemd-resolved, systemd-udevd, rtkit, upower, switcheroo-control. gdm/gnome
need dbus + logind → blocked here. tmpfs mkdir = fs/src/tmpfs/dir.rs:117 (doesn't
return Eio itself → the Eio is upstream of the backend, likely the mount cross / clone).

## First commands next session
1. `cd /home/nd/oxide/kernel && git log --oneline -3`  # main @ e124a3f1
2. Repro: `mcp__qemu__qemu_start arch=x86_64 features=debug-boot accel=kvm smp=2 mem=4G rebuild_rootfs=true`
   → run_until 'gdm|Failed to spawn' → the mkdir-EIO fires ~50s.
3. Find why `pino.mkdir` → Eio for a mkdir inside a CLONE_NEWNS child on both tmpfs
   + ext4. Trace: does the parent inode belong to a cloned mount? Is the write going
   to a detached/broken cloned mount? Check clone_tree + the mount the child's
   /var/tmp + /run resolve to. A hosted mount-ns-clone + mkdir test would nail it.

## Gotchas
- NEVER `git add -A`. ext4 = iterate hosted + e2fsck [[ext4-work-no-booting]].
- nss change is in ../images (config, not kernel); backups at out/*.img.premerge.bak.
- Merged this session: B703 (dcache neg-dentry), B704 (pl011 baud), B705 (fbcon bulk-copy).
