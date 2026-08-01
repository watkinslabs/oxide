# 26 Namespaces + cgroup v2

FROZEN 2026-05-02. Dep:`01`,`02`,`06`,`13`,`16`,`19`,`25`,`27`. Provides:`15` (`unshare`,`setns`,`clone3` ns flags), containers.

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

Id-map engine, keyed by namespace identity, backing `/proc/<pid>/{uid_map,gid_map,setgroups}`:

| Rule | Contract |
|---|---|
| Extent form | `<ns_id> <host_id> <count>` lines, ≤ `UID_GID_MAP_MAX_EXTENTS` (340) |
| Validation | overlap + range rejection (Linux `mappings_overlap`), write-once per map |
| Unprivileged write | single extent mapping the writer's own id only |
| `setgroups` interlock | `deny` required before an unprivileged `gid_map` write; once `gid_map` is populated the `deny` lock is one-way (CVE-2014-8989) |
| Unmapped id | translates to `OVERFLOW_UID`/`OVERFLOW_GID` (65534) |
| Read view | rendered current map; empty until written — the initial user ns alone reports the full-range identity extent Linux seeds at boot |
| Capability | `uid_map`/`gid_map`: `ns_capable(target->parent, CAP_SETUID\|CAP_SETGID)`; `setgroups`: `ns_capable(target, CAP_SYS_ADMIN)` — the target ns itself, not its parent |

Capability scoping: a cap bit authorizes an operation on `target_ns` only when `target_ns` is the caller's user-ns or a descendant of it; each user-ns records its parent at creation, and the check walks the ancestor chain (`27§4`).

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

### 4.1 Lifecycle + `cgroup.events` notification

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

`/proc/<pid>/ns/<kind>` lookup yields an `NsInode { kind, id }` whose `open(2)` gives an fd. `setns(fd, nstype)` downcasts that inode (`16§2`), requires `kind == nstype` (`nstype == 0` accepts any), then installs the id into the caller's matching per-task slot. A non-ns fd is `EINVAL`.

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
