# state.md — session hand-off

## Headline
Branch **F649-vfs-object-model** (off `main` via F648 checkpoint `8eca76b8`). Goal: make the **VFS 100% Linux-compliant** (zero string-path lookups) and get a **bootable GNOME live** system. Full plan + 612-item audit ledger in `/home/nd/oxide/fix.md` (live WP tracker at top). Driven by a self-pacing `/loop` (dynamic ScheduleWakeup; wakes on background-workflow completions).

## Done & committed on F649 (each WP a commit; NO Co-Authored-By — repo CI rule; counters in metadata/index.md, F next=650)
- `099d16ca` WP1 — Linux object model: `superblock.rs` (struct super_block: s_root dentry, s_op, s_type, magic, dev, inode cache), `dcache.rs` (fs/dcache.c prims d_alloc/d_lookup/d_instantiate/d_add/dget/dput/d_move, real negative dentries, (parent,name)-keyed), Dentry.d_sb + d_flags, Inode.i_sb(). namei walks via d_lookup→i_op->lookup→d_add.
- `6326681e` WP2 — every fs (ext4/tmpfs/devfs/sysfs/procfs/cgroup/tracefs/debugfs/BindFs) SuperBlock-owned + per-component lookup; DELETED whole-path FileSystem::lookup (all 8) + namei whole-path delegate + install_open abspath + Dentry::absolute_path.
- `ac94bb4f` WP4 — mount engine re-seated on Arc<Dentry> (register/move_mount/pivot_root take caller's walked dentry, Linux mnt_set_mountpoint); DELETED record_dentry/DENTRY_RESOLVER/resolve_dentry/forget_path/rewire_all_crossings. **Acceptance grep EMPTY — zero path→dentry resolver anywhere.** Boot-order fix (cgroup after /sys, /dev/shm underlay).
- `34565349` exec — execve/execveat of a /proc/self/fd memfd read the fd (Linux do_execveat_common), not a path. sd-executor spawns ("Failed to spawn" 50→0).
- `29f5db2b` mount — engine-internal descend() now CROSSES mounts like namei (a WP4 regression); fixed udevd NAMESPACE/domainname/EINVAL/226.

All committed work: vfs 91 + net 232 hosted tests green, x86_64 + aarch64 build green.

## Boot status
F649 **reaches graphical.target** (smoke boot, "Startup finished 50.2s") — the clean VFS rebuild ELIMINATED the old deterministic COW/futex generator wedge. BUT boot is **non-deterministic**: a fork-COW page-refcount **under-count** randomly corrupts one process's shared page each boot → that process SEGVs (seen: lvm2-monitor / tmpfiles-setup-dev-early / initctl / udev-load-credentials / debugfs-mount-helper — different each boot) → usually stalls at getty; occasionally misses and reaches graphical. Confirmed via 4-boot determinism measurement (oxide-images/output/live-gnome-det-3.log, det-4.log).

## In flight
- **wgh6x888l** (COW refcount hunt): hosted cargo-test harness asserting `frame refcount == live mapping count` across 100k+ randomized fork/COW-write/exit seqs to catch the under-count deterministically → fix at root → verify hosted + 4-boot loop (goal 4/4 graphical, 0 SEGV). Editing mm-vmm/mm-pmm. THE gating blocker for a stable bootable GNOME.

## Open (after COW fix), priority order
1. COW page-refcount under-count (in flight) — stable-boot blocker.
2. Remaining FS-compliance WPs for true 100%: WP3 namei (RCU walk, d_hash/d_compare, LOOKUP_ flags, symlink/ELOOP), WP5 struct file = f_path{vfsmount,dentry}, WP7 syscall surface (57 items: stat/statx/open/getdents/xattr exact errno + AT_*/O_*).
3. Deferred FS items (from WP2/udevd passes, NOT blind-shipped): debug/tracing mount 'protocol' = need mount-change notification (libmount POLLPRI on /proc/self/mountinfo + a vfs mount-generation counter); reap a ns-child's per-ns mount table on exit (2nd-attempt MS_MOVE/pivot EINVAL).
4. Confirm GNOME actually starts (gdm/gnome-shell) once boot is reliable.

## First command next session
```
cd /home/nd/oxide/kernel && git branch --show-current   # expect F649-vfs-object-model
git log --oneline -6
# check the in-flight COW hunt result, commit its fix on F649, update /home/nd/oxide/fix.md
```

## Gotchas
- Repo is /home/nd/oxide/**kernel** (parent /home/nd/oxide is NOT a git repo; fix.md/now.md live there; oxide-images/ holds boot logs + runboot.sh).
- NO Co-Authored-By on commits (CI lint rejects). Author = Chris Watkins <chris@watkinslabs.com>.
- Boot verify: `cd oxide-images; cargo run -q -p imagectl -- build-boot --profile live-gnome --arch x86_64; timeout -k 10s 150s ./runboot.sh 135 <log>`. The `-k` is required (QEMU ignores SIGTERM). debug-syscall/debug-mnt features can trigger the COW wedge — use default build for boot verify.
- Acceptance invariant (keep green): `grep -rnE 'record_dentry|DENTRY_RESOLVER|resolve_dentry|forget_path|fn lookup\(&self, path: ?&str' crates/kernel` must be EMPTY.

## Prior session work (glibc 197/197) — superseded by this branch's VFS rebuild; see git history on main.
