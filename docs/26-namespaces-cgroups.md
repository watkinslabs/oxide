# 26 Namespaces + cgroup v2

FROZEN 2026-05-02. Dep:`01`,`02`,`06`,`13`,`16`,`19`,`25`,`27`. Provides:`15` (`unshare`,`setns`,`clone3` ns flags), containers.
## 1 Purpose

Namespaces (mnt, pid, net, uts, ipc, user, cgroup, time) and cgroup v2 unified hierarchy.

## 2 Invariants (frozen)

1. Every task belongs to exactly one of each namespace kind. Inheritance: `clone3` without `CLONE_NEW*` shares parent's; with → new instance under parent's user-ns ownership.
2. Namespace lifetime: `Arc`-counted; freed when last task and last `/proc/<pid>/ns/<kind>` fd both gone.
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

Per-ns: routing tables, neigh caches, sockets-bound list, ifaces (added via `ip link set netns <ns>`), conntrack (when v2 adds).

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
| `cgroup.events` | `populated` 0/1 |
| `cgroup.type` | `domain`,`threaded`,`domain threaded`,`domain invalid` |
| `cgroup.kill` | write 1 to SIGKILL all members |
| `cgroup.freeze` | freezer |
| `cpu.weight`,`cpu.max`,`cpu.stat` | cpu controller |
| `memory.{current,max,swap.max,events,stat,low,high,pressure}` | memory controller |
| `io.{stat,max,weight,latency}` | io controller |
| `pids.{current,max,events}` | pids controller |
| `cpuset.{cpus,mems}` | cpu/numa pinning |
| `hugetlb.<size>.{current,max}` | hugetlb (v2) |

Controllers in v1: cpu, memory, io, pids, cpuset. (hugetlb v2; rdma/misc v2.)

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
- runc-equivalent shape: spawn a container with all namespaces + cgroup limits + seccomp filter (when BPF v2); verify process runs and exits cleanly.
- Coverage ≥85%.

## 9 Failure modes

- `unshare(CLONE_NEWUSER)` from non-root in some configs: EPERM unless `unprivileged_userns_clone=1` (sysctl, default 1 per `03§8`).
- Move task into cgroup that lacks needed controller: ENOSPC.
- Memory cgroup limit hit: OOM kill within cgroup (not system-wide).

## 10 Debug

`debug-cgroup`: per-cgroup charge/uncharge trace; ns lifetime track.

## 11 Cross-spec

`13` (CFS+RT honor cpu.weight, cpu.max), `27` (capabilities scoped to user-ns), `15` (syscalls), `19` (sysfs `/sys/fs/cgroup/`).

