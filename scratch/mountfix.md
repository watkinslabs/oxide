# mountfix — new mounts invisible in /proc/self/mountinfo (wholesale)

Status: OPEN — needs one instrumented boot to pin the failing link. Branch: UNCLAIMED.
Severity: HIGH (blocks full systemd boot / login / gnome). NOT a socket-lane regression.

## Symptom

Every systemd `.mount` unit fails identically:

```
sys-kernel-debug.mount:  Mount process finished, but there is no mount.   → result 'protocol'
sys-kernel-tracing.mount: Mount process finished, but there is no mount.  → result 'protocol'
tmp.mount:               Mount process finished, but there is no mount.   → result 'protocol'
sys-kernel-config.mount: Mount process finished, but there is no mount.   → result 'protocol'
```

Evidence: `boot.txt` (debug-boot x86_64, captured 06:34 — PREDATES the B779 socket
lane, i.e. this is `main`). Grep facts:
- **ZERO** `.mount` units succeed the whole boot — not one `Mounted X` line.
- `boot.txt:1920,1992,2064,3612` = the four "there is no mount" lines.
- `boot.txt:1942,2014,2086,3634` = matching "Failed to mount …".

`result 'protocol'` in systemd = the mount helper exited **0** (so `mount(2)` returned
success) but systemd re-read `/proc/self/mountinfo` and did **not** find the new mount.
So: mount(2) returns 0, superblock is grafted, but the entry never renders in
`/proc/self/mountinfo` for pid 1.

Not fstype-specific: tmpfs is fully supported (`tmpfs-smoke: ok` at boot) yet `tmp.mount`
fails the same way. This is a **mount-visibility** bug, not a missing-filesystem bug.

## Scope / provenance

- Pre-existing on `main`. `boot.txt` mtime 06:34; socket claim commit `878aa617` is 06:35.
  The socket-syscall corrections did NOT cause this.
- Because every `.mount` that systemd *verifies* fails, boot stalls out in early
  bringup and never reaches multi-user/graphical → "no login, no gnome".

## Code chain (all verified correct by static reading — the bug is a RUNTIME value)

1. `mount(2)` slot 165 — `crates/kernel/syscalls/src/165_mount.rs:274`
   new-fstype path → `mount_fstype_at(...)`.
2. `mount_fstype_at` — `crates/kernel/syscalls/src/fsmount_common/mount_ops.rs:17`
   `get_fs(fstype)` → Some for tmpfs/debugfs/tracefs/configfs (all registered in
   `fsmount_common/registry.rs:96,110,113,126`) → `graft_mount` → returns 0.
3. graft — `crates/kernel/vfs/src/mount/attach.rs:55 graft_realized`
   tags the new `Mount` with `ns = current_ns()`, inserts into global `MOUNTS`
   (`model.rs:148`), `bump_gen(ns)`.
4. reader — `crates/kernel/procfs/src/mounts.rs:133 build_mountinfo`
   → `vfs::mount::snapshot_ns_view(task_mount_ns(pid1))`
   → `mounts_in_ns(ns)` = `MOUNTS.filter(|m| m.ns == ns)` (`graph.rs:444`)
   → each mount `project_path_under_root(mp, root_prefix)` (`graph.rs:173`).

Every link is individually correct on paper, yet the rendered mountinfo is empty of the
new mounts. Therefore one link has a **runtime value** that differs from the static
reading. Prime suspect = the `ns` id (step 3 vs step 4).

## Ruled OUT (do not re-investigate)

- Missing filesystem types — all four are registered (`registry.rs`).
- fork/clone losing the namespace — `056_clone.rs:215` copies parent's `mount_ns`
  (alongside ipc/net/user/cgroup at :209–218).
- The graft's ns tag — `attach.rs:57` uses `current_ns()`, inserts into global MOUNTS.
- ns membership filter shape — `mounts_in_ns` filter is a plain `m.ns == ns`.
- root projection for pid 1 — pid1 root is `/`, so `current_root_prefix`→None and
  `project_path_under_root(path, None)` is identity (`graph.rs:174`). It does NOT drop
  mounts for pid 1.

## Prime suspect (rank 1): ns-id mismatch between the mount helper and pid 1

`current_ns()` (`crates/kernel/vfs/src/mntns.rs:376`) returns `f()` where `f` reads the
current task's `mount_ns`, **or `0` if no provider is installed**. Default task
`mount_ns = AtomicU64::new(0)` (`sched/src/task/methods.rs:231`).

systemd performs each `.mount` from a **forked helper child**, then pid 1 reads
`/proc/self/mountinfo`. If the helper grafts under an ns id != the id pid 1 reads with,
the mount is filtered out at `mounts_in_ns`. Two concrete ways this happens:
  (a) the helper is spawned via a path that does NOT run `056_clone.rs:215` (posix_spawn /
      vfork / kernel-spawn variant) → its `mount_ns` stays the default `0`, mount grafts
      into ns 0, pid 1 (nonzero ns) never sees it; or
  (b) pid 1 itself vs. the helper disagree on the ns id (init established a nonzero ns the
      helper didn't inherit).

## Suspect rank 2: rendered mountpoint path mismatch

`m.mount_point_str()` / `rendered_path_for` (attach.rs:88) renders the wrong string for a
mount grafted OVER a dentry that is itself inside another mount (3 of 4 failures are under
the `/sys` sysfs mount: `/sys/kernel/{debug,tracing,config}`). If the rendered path is
empty or not the exact `/sys/kernel/debug` systemd expects, systemd declares "no mount".
Lower rank because `/tmp` (on the ext4 root, shallow) fails too.

## DECISIVE experiment (one warm qemu-MCP boot; do NOT loop boots — CLAUDE.md)

Build with the existing trace features (no new code needed for the first pass):
`--features "debug-boot,debug-mount,debug-mnt"`.

1. Boot to just after systemd starts the first `.mount` (break/inspect via qemu MCP, or
   let it run and capture serial).
2. Correlate the `[MNTCREATE] syscall=mount … target=/tmp` line (165_mount.rs:57) and the
   `[graft] mnt_id=… ns=…` line (`attach.rs:76,94` via `mntcreate_log`) — record the **ns
   id** the tmpfs mount grafts under.
3. Read pid 1's ns: add/confirm a one-shot klog of `task_mount_ns(1)` at
   `procfs/src/mounts.rs:133 build_mountinfo` (dump `ns` + resulting `mounts.len()`).
4. Compare. If graft-ns != mountinfo-ns → **suspect 1 confirmed** (fix the helper spawn
   path to inherit `mount_ns`, or make `current_ns()` never fall back to 0 for a real
   task). If ns matches but the mount is absent / rendered at the wrong path → **suspect 2**
   (fix `rendered_path_for`/`mount_point_str` for over-a-mount grafts).

If a targeted trace is preferred over reading debug-mount output: add a single klog in
`graft_realized` (attach.rs:55) printing `mnt_id`, `ns`, rendered path, and in
`build_mountinfo` printing reader `ns` + `mounts.len()` — one boot, then remove.

## Linux-shape note

Real Linux: `mount(2)` in a forked child that shares the mount namespace is immediately
visible in the parent's `/proc/self/mountinfo` (same `struct mnt_namespace`). systemd
relies on this + `poll(POLLPRI)` on the mountinfo fd. Our per-ns id model must guarantee a
plain fork shares the SAME `mount_ns` id end-to-end (clone does at :215 — verify the
actual helper-spawn path exercises it), and `current_ns()` must never silently return 0
for a live task.

## Fix ownership

Mount subsystem (`crates/kernel/vfs/src/mount/**` + `crates/kernel/syscalls/src/*mount*`
+ spawn path in `crates/kernel/syscalls/src/056_clone.rs` / execve). One lane, one agent —
grep `git worktree list` + `git branch -a` for an existing mount lane before claiming
(CLAUDE.md "Claim work before starting"). Gate the fix with a hosted or single-boot check
that `/proc/self/mountinfo` shows a child-forked tmpfs mount at `/tmp`.
