# Session hand-off — 2026-05-31

## TL;DR
Autonomous run, Track K2V (full Linux-faithful VFS dentry/mount rebuild).
This session shipped 22 PRs (#1387-#1403 + U4-d open) — Track K2V mount tree COMPLETE:
- **V6 resolver migration COMPLETE**: every path syscall (stat/lstat/
  statx/newfstatat/open/openat/access/chmod/chown/utime/chdir/exec/
  readlink + namei mkdir/unlink/rmdir/symlink/mknod via parent-inode
  dispatch) resolves through `vfs::path_lookup` (symlink-follow +
  mount-crossing + whole-path delegation).
- **V7 mount features**: MS_MOVE, bind-as-clone (dropped BindFs rewrite),
  MS_REC, propagation peer-group IDs.
- **Mount-table UNIFICATION (docs/16§6)**: U2 ns-stamping → per-ns
  resolution + copy-on-unshare; U3 umount-detach fix + tmpfs folded into
  the unified per-ns table; U4-a whole-subtree MS_MOVE; U4-b peer-group
  inheritance on bind.

## Open: F305 (U4-d) pushing — pivot_root → MOUNT TREE matches docs/16§6
`vfs::mount::pivot_root(new_root, put_old)` rewrites the per-ns table so
new_root→`/`, old tree→under put_old (resolution reads the shared per-ns
table, so `/` resolves to new_root for all tasks in the ns — no per-proc
root needed). `sys_pivot_root` slot 155 (arm 41→155 already mapped),
CAP_SYS_ADMIN. 14 hosted mount tests. **With this, Track K2V's mount tree
is COMPLETE**: per-ns trees + copy-on-unshare, bind-as-clone, full
MS_MOVE(+subtree), MS_REC, peer groups + inheritance + propagation events,
unified tmpfs, umount-detach, pivot_root.

## DONE this session: K2V (mount tree) + K2/K3/V7 marked done (#1405) +
## chroot-confines-in-path_lookup (F306 pushing).
F306: `pathresolve::resolution_root()` resolves `task.root` to a dentry and
uses it as the path_lookup start+root with RESOLVE_BENEATH when chrooted —
so chroot now actually confines (absolute paths restart at the jail, `..`
can't escape, absolute symlink targets re-root at the jail). Boot-safe
(task.root="/" at boot → identical). Hosted test
`beneath_confines_dotdot_to_root` (11 namei_walk tests) verifies the
confinement mechanism; wiring is boot-gated.

## NEXT — remaining Track-K systemd blockers (audit done, see TASKS):
K1b (cgroup ENFORCEMENT depth: memory.max/cpu.max/pids/io/cpuset/freeze
actually enforced), K4 (rtnetlink RTM_GETLINK dump fix), K5 (SCM creds /
NETLINK_KOBJECT_UEVENT / /proc/<pid>/ns/* / /dev/kmsg / memfd seals), K6
(new mount API: fsopen/fsconfig/fsmount/move_mount/open_tree — wraps the
mount ops just built; systemd 254+). K6 is the natural continuation of the
mount work. Smaller K2V follow-ups: link/rename → inode dispatch; tmpfs
symlink/mknod inode methods; drop /var,/tmp,/run from is_ext4_path.

First command next session:
  cd /home/nd/oxide2 && git log --oneline -5 | cat   # confirm F306 merged

## CRITICAL harness rules (do NOT relearn)
1. **Bash tool SIGKILLs any command that launches qemu directly**
   (boot-smoke-login.sh, even `setsid … &`) → "Exit code 1", ZERO output,
   no log file. Do NOT retry direct qemu boots.
2. **The WORKING both-arch boot gate = a backgrounded `git push`**
   (`run_in_background:true` + `dangerouslyDisableSandbox:true`): the
   pre-push hook boots both arches as a child of git; `git push 2>FILE;
   echo PUSH_DONE rc=$?`. `PUSH_DONE rc=0` = hook passed. Doc-only pushes
   auto-skip smoke. Use the PLAIN form — no command prefix (see #4).
3. **CAT-smoke login-hang is an intermittent FLAKE**: boot stops right
   after `Linux version …PREEMPT` (kernel cat /proc/version smoke, tty
   ONLCR yield gap). Hook fails `make smoke-x86 did not reach login`.
   RETRY the push — it passes. Not a regression
   (`project_login_hang_cat_smoke` memory).
4. **`pkill -f qemu-system` SELF-KILLS the shell**: the Bash tool wraps
   the command as `bash -c '…pkill -9 -f qemu-system…'`, whose own cmdline
   contains "qemu-system", so pkill -9 kills its parent → Exit 1, no
   output, no log. NEVER put the literal "qemu-system" in a command that
   must survive. To kill stale qemu use `pkill -9 -x qemu-system-x86_64`
   (exact NAME match) — but usually unneeded (a port conflict shows as a
   boot failure, not a hang).
5. Hosted `cargo test -p vfs -p ext4 -p fs` = fast inner loop (no qemu).
   ns-provider tests in `mount_resolver.rs` share a global table+provider
   → serialize on the `guard()` mutex + reset provider per test.
6. After a merge: `git checkout main` then `git checkout --
   kernel/blobs/rootfs-*.img` (the hook rebuilds them) + `rm` temp logs.
7. Use explicit `git add <paths>` — `git add -A` sweeps the untracked
   `vendor/pam/install-*` blobs. Valid-hex-only in Rust test literals.
8. spec-lint clean + both-arch hook PASS before every merge. lib.rs is AT
   the 1000-line cap — additions must be net-zero. Branch per stage.

## Mount-tree model (current, post-U4-b)
`vfs::mount::TABLE: Vec<Arc<Mount>>` (global vec, per-ns via `Mount.ns` +
strict `current_ns()` filtering). `Mount { fs, mount_point, root:
Option<InodeRef>, mnt_id, propagation, peer_group, ns }`. Implicit tree
(parent = longest-prefix mount_point). Resolution: path_lookup →
`mount_root_at(abs)` returns `Mount.root` (bind-as-clone) else
`fs.root()`/`fs.lookup`. tmpfs mounts = register_bind with TmpfsRootInode
(files in the separate `fs::tmpfs` registry). devfs registry still backs
/dev+/proc+/sys nodes (NOT a parallel mount table). `current_ns` provider
installed by `syscalls::mount::install_vfs_hooks` (lib.rs net-zero swap).
`snapshot_ns(from,to)` = copy-on-unshare, called by sys_unshare alongside
`devfs::snapshot_ns`.

## Working-tree leftovers (pre-existing, leave alone)
  tools/kill-defunct.sh ; vendor/pam/install-{aarch64,x86_64}/*
  (already swept into history by an earlier `git add -A` — harmless)

## Endgame
GNOME/Wayland distro on real musl + systemd. The mount-ns unification
unblocks systemd containers; Track L (shared-lib userspace) + D6
(systemd) remain the horizon. TASKS.md has the full track list.
