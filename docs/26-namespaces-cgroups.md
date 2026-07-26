# 26 Namespaces + cgroup v2

FROZEN 2026-05-02. Dep:`01`,`02`,`06`,`13`,`16`,`19`,`25`,`27`. Provides:`15` (`unshare`,`setns`,`clone3` ns flags), containers.

## Revision 2026-07-26 (R84)

- Changed: §2 invariant 6 ("every uid/gid translated via current task's
  user-ns map at every credential check") now has a real engine.
  `/proc/<pid>/{uid_map,gid_map,setgroups}` were cosmetic `SysctlInode`
  byte slots seeded with a fabricated `"0 0 4294967295"` identity string
  for EVERY namespace (including non-init) and accepted any write
  verbatim with no parse/validate/translate step — `unshare(CLONE_NEWUSER)`
  had no actual UID/GID isolation.
- Added: `crates/kernel/user-namespace` canonical id-map engine keyed by
  namespace identity (same shape as `crates/kernel/time-namespace`):
  up to `UID_GID_MAP_MAX_EXTENTS` (340) `<ns_id> <host_id> <count>`
  extents, Linux `mappings_overlap`-equivalent overlap/range validation,
  write-once enforcement, the unprivileged single-own-id fallback, the
  `setgroups=deny`-before-unprivileged-`gid_map`-write interlock
  (CVE-2014-8989) with the one-way `deny` lock once `gid_map` is
  populated, and `ns_id<->host_id` translation with `OVERFLOW_UID`/
  `OVERFLOW_GID` (65534) fallback. Bridged as `nscg::user_ns`.
- Changed: procfs `uid_map`/`gid_map`/`setgroups` are real `FileOps` over
  the engine: reads render the current map (empty until written; the
  initial user namespace alone reports the fixed full-range identity
  extent Linux seeds it with at boot); writes parse+validate+apply with
  Linux errno semantics. The capability check for `uid_map`/`gid_map`
  is `ns_capable(target->parent, CAP_SETUID|CAP_SETGID)`; `setgroups`
  is `ns_capable(target, CAP_SYS_ADMIN)` (the TARGET ns itself, not its
  parent) per Linux `proc_setgroups_write`.
- Known gap (not closed this revision): credential-translation call
  sites that must cross the ns boundary using this engine — `getuid`
  family (ns-relative view of a host id held in `Task.creds`), `stat`/
  `chown`-family owner munging, `setresuid`/`setresgid` bound checks
  against a ns-relative argument, and `/proc` cross-ns visibility —
  still operate directly on host ids with no translation step. The
  engine and procfs views are correct and complete; wiring translation
  into those call sites is tracked as follow-up work, not silently
  dropped.
- Affected code: `crates/kernel/user-namespace` (new), `crates/kernel/nscg`
  (`user_ns` bridge module, `has_cap_in_parent`-style ancestry check reused
  from `proc_ns::user_ns_is_ancestor`), `crates/kernel/procfs/src/userns_idmap.rs`
  (new, replaces the `pc_idmap`/`pc_setgroups` `SysctlInode` stubs in
  `live/pid_dir.rs`).
- Test contract change: §8 gains uid/gid map round-trip, overlap
  rejection, write-once, unprivileged-own-id, setgroups interlock, and
  boundary/unmapped-id translation coverage (`user-namespace` +
  `procfs::userns_idmap` hosted suites).

## Revision 2026-07-14 (R83)

- Changed: §2 live tasks belong to one namespace of each kind; exit releases
  namespace membership before zombie publication, so pidfds may retain process
  identity without retaining namespace membership.
- Changed: §2 namespace lifetime includes every durable owner: live tasks,
  namespace fds, sockets, and subsystem objects with asynchronous work.
- Affected code: `crates/kernel/network-namespace`, `sched`, `nscg`, `net`,
  `netlink`, `procfs`, and namespace syscall work functions.
- Test contract change: exit/pidfd, nsfd, passed-socket, clone, setns, and final
  owner-drop races must prove no resurrection or premature teardown.

## Revision 2026-06-03 (R79)

- Added: §4.1 cgroup-v2 directory lifecycle + the mandatory
  `cgroup.events` inotify `IN_MODIFY`-on-transition contract
  (Linux `cgroup_file_notify`). Userspace managers (systemd) drive
  empty-cgroup restart/GC off this watch; without it an emptied
  service cgroup is rmdir'd and never re-realized on restart, so the
  restarted unit writes to a removed node (ENOENT) and is killed.
- Changed: `cgroup.events` row now records both `populated` and
  `frozen` fields (impl emitted `frozen` already; spec omitted it).
- Removed: stale "cgroup v2 hierarchy walker tracked as later
  phase" deferral notes (R02/R03) — the unified tree, controllers,
  and scope membership are implemented (`crates/kernel/cgroup`).
  CLONE_NEWCGROUP id-stamping vs hierarchy-view scope still PARTIAL
  per the per-bit table; the tree itself is no longer deferred.
- Affected code: `crates/kernel/cgroup` (`NOTIFY_HOOK` →
  `fs::inotify` path-fire), `crates/kernel/fs/src/inotify.rs`.

## Revision 2026-05-09 (R03)

- Changed: pinned the precise enforcement state of `unshare(2)` per
  CLONE_NEW* bit. Previously the spec said "containers" without
  specifying which ns flags isolate vs which only update
  membership ids. Per-bit truth:
    - **CLONE_NEWUTS**  REAL — per-task `uts_hostname` snapshot;
      `uname()`/`sethostname()` reads/writes the per-task slot.
    - **CLONE_NEWIPC**  REAL — fresh `ipc_ns` id; SysV shm/sem/msg
      and POSIX MQ stores are tagged-by-ns and lookup uses the
      caller's id (init-NS fallback).
    - **CLONE_NEWNET**  REAL — fresh `net_ns` id; `register_in_ns`/
      `lookup_name_in_ns` on the netdev registry; AF_INET / AF_UNIX
      sockets bind into the caller's net_ns.
    - **CLONE_NEWUSER** REAL — fresh `user_ns` id + parent recorded
      in the global registry; `has_cap_for(target_ns, cap)` walks
      the ancestor chain (per docs/27 R01).
    - **CLONE_NEWNS**   REAL — fresh `mount_ns` id; `devfs::snapshot_ns`
      copies the parent's NS-tagged mount entries into the new id;
      mount lookups try caller's mount_ns first, fall back to ns=0
      (per docs/16 R01).
    - **CLONE_NEWPID**  REAL (deferred-allocate) — sets
      `unshare_pid_pending`; the next `fork()` allocates a fresh
      pid_ns and gives the child vpid=1; pid translation across
      namespaces uses `registry::lookup_in_ns`.
    - **CLONE_NEWCGROUP** PARTIAL — sets a fresh `cgroup_ns` id; the
      unified cgroup-v2 tree (controllers, hierarchy, scope
      membership) IS wired (`crates/kernel/cgroup`), but the
      ns-relative `/proc/<pid>/cgroup` root-rebasing for a fresh
      cgroup_ns is not yet applied — paths still report root-relative.
- Why: g.md flagged "namespace partial enforcement under unshare"
  as a Linux-conformance hazard. Userspace runtimes (systemd,
  unshare(1), bwrap, runc) check membership ids AND expect the
  isolation behavior to follow; without per-bit truth the spec
  read as "all ns work" while CGROUP only works for id stamping.
- Affected code: `kernel/src/syscall_glue_signal.rs::kernel_sys_unshare`
  (the per-bit allocate + scope path).

## Revision 2026-05-09 (R02)

- Changed: `crates/nscg` is now the real owner of `NsInode`,
  `setns_apply`, `has_cap_for`, and the user-NS parent registry.
  Per-task ns id slots stay on `sched::Task` (uts/ipc/net/pid/
  user/cgroup/mount); the crate provides the inode-side bridge.
- Wiring: `kernel::dev_proc_ns` is a `pub use nscg::proc_ns`
  re-export so existing call sites stay stable. `kernel_main`
  calls `nscg::init()` at boot ready.

## Revision 2026-05-09 (R01)

- Changed: pinned the setns/NsInode contract. `/proc/<pid>/ns/<type>`
  lookup returns a real `NsInode { kind: NsKind, id: u64 }` whose
  open(2) yields a fd. setns(fd, nstype) downcasts the fd's inode via
  `Inode::as_any` (per `16§5`), validates `kind` matches `nstype` (or
  nstype==0 to accept any), then writes the matching ns id into the
  caller's per-task slot (uts/ipc/net/pid/user/cgroup/mount).
- Why: F100/F101/F105/F106/F107 added the per-task ns id slots and
  F112 made the readlink dynamic, but setns was still silent-0 — the
  fd argument went un-inspected. Without an NsInode, lsns / nsenter /
  unshare-rejoin patterns silently no-op'd.
- Affected code: `kernel/src/dev_proc_ns.rs` (new — NsInode + lookup);
  `kernel/src/syscall_glue_signal.rs` (kernel_sys_setns rewrite);
  `kernel/src/procfs.rs` (/proc/<pid>/ns/<type> directory inode arm).
- Test contract change: §6 acceptance gains a setns smoke — open
  /proc/self/ns/uts in a CLONE_NEWUTS-unshared child; setns from the
  parent; verify the parent's uts_hostname slot now matches.

## 1 Purpose

Namespaces (mnt, pid, net, uts, ipc, user, cgroup, time) and cgroup v2 unified hierarchy.

## 2 Invariants (frozen)

1. Every live task belongs to exactly one of each namespace kind. Inheritance: `clone3` without `CLONE_NEW*` shares parent's; with → new instance under parent's user-ns ownership. Exit releases membership before zombie publication; a retained dead task has no namespace set.
2. Namespace lifetime: `Arc`-counted; freed after the last durable owner, including live tasks, `/proc/<pid>/ns/<kind>` fds, sockets, and asynchronous subsystem work, is gone.
3. Cgroup v2: every task in exactly one cgroup. Move via writing tid to `cgroup.procs`/`cgroup.threads`.
4. Cgroup v2 single hierarchy mounted at `/sys/fs/cgroup`. No v1 mounted, ever.
5. Cgroup controllers attached to a cgroup ⇒ all descendants must enable subset.
6. UID mapping: every uid/gid translated via current task's user-ns map at every credential check.

## 3 Namespace kinds

### 3.1 mnt

Per-ns mount table (per `16§7`). Operations: `mount`,`umount2`,`pivot_root`,new mount API. Propagation: shared/private/slave/unbindable.

### 3.2 pid

Per-ns pid allocator. PID 1 within a pidns is special: signal-default-ignore for many, reaper for orphans, kills the ns when it dies.

### 3.3 net

Per-ns: routing tables, neigh caches, sockets-bound list, ifaces (added via `ip link set netns <ns>`), conntrack (when phase 39 adds).

### 3.4 uts

`hostname`, `domainname`. Two strings. Trivial.

### 3.5 ipc

Per-ns: AF_UNIX abstract namespace (path-bound is filesystem so mnt-ns), POSIX mq (deferred), futex namespace (futexes are AS-scoped, not ipc-ns scoped — per Linux).

### 3.6 user

Per-ns: uid/gid maps (mapping from container uid to "outer" uid). Capabilities apply within owner ns.

### 3.7 cgroup

Per-ns view of the cgroup hierarchy. `/proc/self/cgroup` shows path relative to ns root.

### 3.8 time

Per-ns CLOCK_MONOTONIC offset. `CLOCK_REALTIME` not affected.

## 4 cgroup v2

Single tree. Each node is a directory in `/sys/fs/cgroup/`. Files per node:

| File | Meaning |
|---|---|
| `cgroup.procs` | tids in this cgroup; write to move |
| `cgroup.threads` | thread granularity |
| `cgroup.controllers` | available controllers |
| `cgroup.subtree_control` | controllers enabled for children (write to enable/disable) |
| `cgroup.events` | `populated 0\|1` + `frozen 0\|1`; **inotify `IN_MODIFY` fires on every populated/frozen transition** (§4.1) |
| `cgroup.type` | `domain`,`threaded`,`domain threaded`,`domain invalid` |
| `cgroup.kill` | write 1 to SIGKILL all members |
| `cgroup.freeze` | freezer |
| `cpu.weight`,`cpu.max`,`cpu.stat` | cpu controller |
| `memory.{current,max,swap.max,events,stat,low,high,pressure}` | memory controller |
| `io.{stat,max,weight,latency}` | io controller |
| `pids.{current,max,events}` | pids controller |
| `cpuset.{cpus,mems}` | cpu/numa pinning |
| `hugetlb.<size>.{current,max}` | hugetlb (later phase) |

Controllers now: cpu, memory, io, pids, cpuset. (hugetlb, rdma, misc tracked as later phases.)

### 4.1 Lifecycle + `cgroup.events` notification (R79)

Directory lifecycle:

| Op | Effect | Errors |
|---|---|---|
| `mkdir <dir>` | create node; child `cgroup.controllers` = parent `subtree_control`; register dir + interface files in the unified mount | parent gone → ENOENT |
| `rmdir <dir>` | remove node + unregister its dir/files; full subtree removed atomically (no stale dirent: post-rmdir `lookup`→ENOENT, parent `readdir` omits it) | non-empty (live procs **or** child dirs) → ENOTEMPTY |
| last member exits / migrates out | node stays; `populated`→0 | — |

`cgroup.events` change-notification (Linux `cgroup_file_notify`):

- A watcher (`inotify_add_watch` on `<cg>/cgroup.events`, `IN_MODIFY`) is the **canonical empty-cgroup signal**. systemd's service state machine drives restart/GC off this event, not off SIGCHLD alone.
- `IN_MODIFY` MUST fire on the `cgroup.events` inode whenever:
  - `populated` flips 0↔1 — i.e. the node's subtree process count crosses zero. Process exit (`on_exit`), `cgroup.procs`/`cgroup.threads` migration (source **and** destination), and `cgroup.kill` all qualify.
  - `frozen` flips 0↔1 via `cgroup.freeze`.
- Propagation: `populated` reflects the **subtree** count, so a transition notifies the affected node **and every ancestor up to the root** whose aggregate count crossed zero.
- Absent this notification, a userspace manager that rmdir's an emptied cgroup never re-realizes it on restart → writes to the removed node return ENOENT → the restarted service is killed. The notification is mandatory, not advisory.

## 5 Public ifc

```rust
pub fn unshare(flags:u64) -> KR<()>;
pub fn setns(fd:RawFd, nstype:u32) -> KR<()>;
pub fn clone3_with(args:&CloneArgs) -> KR<Tid>;     // delegates per `13`

pub fn cg_create(path:&str) -> KR<()>;
pub fn cg_attach_task(path:&str, tid:Tid) -> KR<()>;
pub fn cg_set(path:&str, file:&str, val:&str) -> KR<()>;
pub fn cg_get(path:&str, file:&str) -> KR<String>;
```

## 6 Concurrency

- Per-ns spinlock for ns table mutations.
- Cgroup hierarchy: tree-rwlock for structural changes; per-cgroup spinlock for `cgroup.procs` writes.
- RCU for read-mostly traversals (`cgroup.controllers`).
- Lock order: `MountTable` < `Net` < `Cgroup` < `Inode`.

## 7 Perf budget

| Op | p99 |
|---|---|
| `unshare(CLONE_NEWNET)` | ≤ 50 µs |
| Cgroup attach (write `cgroup.procs`) | ≤ 30 µs |
| CPU controller charge per tick | ≤ 100 cy |
| Memory controller charge per page | ≤ 200 cy |

## 8 Test contract (frozen)

- Create each ns kind via `unshare`; verify `/proc/<pid>/ns/<kind>` differs from parent.
- `setns` re-enters; verify.
- pid-ns reaper: kill PID 1 of a pidns; all descendants signaled.
- user-ns mapping: rootless task in user-ns sees uid 0 internally, mapped to nonzero outside.
- Cgroup: create cgroup, set `memory.max=1MB`, run a task, verify OOM-kill at limit.
- Cgroup `cpu.weight` proportional sharing: 2 cgroups @100, @200; verify ~1:2 CPU split under contention.
- runc-equivalent shape: spawn a container with all namespaces + cgroup limits + seccomp filter (once BPF lands in phase 23); verify process runs and exits cleanly.
- Coverage ≥85%.

## 9 Failure modes

- `unshare(CLONE_NEWUSER)` from non-root in some configs: EPERM unless `unprivileged_userns_clone=1` (sysctl, default 1 per `03§8`).
- Move task into cgroup that lacks needed controller: ENOSPC.
- Memory cgroup limit hit: OOM kill within cgroup (not system-wide).

## 10 Debug

`debug-cgroup`: per-cgroup charge/uncharge trace; ns lifetime track.

## 11 Cross-spec

`13` (CFS+RT honor cpu.weight, cpu.max), `27` (capabilities scoped to user-ns), `15` (syscalls), `19` (sysfs `/sys/fs/cgroup/`).
