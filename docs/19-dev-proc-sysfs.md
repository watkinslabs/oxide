# 19 dev/proc/sysfs

Status: DRAFT 2026-05-02
Depends on: `01`,`02`,`06`,`16`,`18`,`35`.
Provides to: every userspace tool that introspects (`ps`,`top`,`free`,`udev`,`mount`,`lsmod`,...).

## 1 Purpose

Three pseudo-FSes that present kernel state as a tree of files. Surface defined by Linux compatibility (per `03§5.1–5.3`).

## 2 Invariants (frozen)

1. `/proc/<pid>/` exists ⇔ task with that pid is alive (or a zombie awaiting reap).
2. `/sys/class/<class>/<name>` is a symlink into `/sys/devices/...` for the canonical device path.
3. Every `/dev/<n>` node corresponds to a device registered with `Drv` (`35`); unregister removes node.
4. Reads from `/proc` and `/sys` files: data snapshot taken at first `read`; consistent across the read sequence (until next `open`).
5. No file in `/proc`,`/sys`,`/dev` ever returns size > emitted bytes (i.e., `stat.st_size` matches actual content for variable files: 0).
6. Permissions: `/proc/<pid>/*` follow Linux's `hidepid` defaults; `/sys` defaults `r--r--r--` for read, `rw-------` for writable; `/dev` per device.

## 3 Public ifc

```rust
pub struct ProcFile { name:&'static str, ops:&'static dyn ProcOps }
pub trait ProcOps { fn read(&self, ctx:&ReadCtx) -> KR<Vec<u8>>; fn write(&self, ctx:&WriteCtx, buf:&[u8]) -> KR<usize>; fn poll(&self) -> PollMask; }

pub fn proc_register(parent:&str, file:ProcFile) -> KR<()>;
pub fn proc_unregister(parent:&str, name:&str);

pub struct KObj { parent:Option<&KObj>, name:&'static str, attrs:&[KAttr], release:Option<fn(&KObj)> }
pub struct KAttr { name:&'static str, mode:FileMode, show:fn(&KObj)->Vec<u8>, store:Option<fn(&KObj,&[u8])->KR<usize>> }
pub fn sysfs_register(k:&'static KObj) -> KR<()>;

pub fn devfs_mknod(name:&str, mode:FileMode, dev:DevId, ops:Arc<dyn FileOps>) -> KR<()>;
```

## 4 procfs structure

Per-process (`/proc/<pid>/`,`/proc/self`,`/proc/thread-self`):

| Path | Source | Format |
|---|---|---|
| `cmdline` | task argv buffer | NUL-sep |
| `comm` | task name | string |
| `environ` | task envp buffer | NUL-sep |
| `exe` | task->exe inode | symlink |
| `cwd` | task->cwd dentry | symlink |
| `root` | task->root dentry | symlink |
| `fd/<n>` | task fdtable[n].dentry | symlink |
| `fdinfo/<n>` | fd flags + pos + per-fd metadata | text |
| `maps` | AS->vma walk | Linux maps fmt |
| `smaps` | AS->vma walk + PFN walk for RSS | Linux smaps fmt |
| `mem` | AS read/write (gated by ptrace cap) | binary |
| `stat` | sched + mm + sig stats | one line, 52 fields |
| `status` | human form of stat + caps + namespaces | key:val lines |
| `statm` | RSS/VSS pages | numbers |
| `mountinfo` | task->ns->mounts walk | Linux fmt |
| `mounts` | same, simpler | Linux fmt |
| `cgroup` | task->cgroup path | `0::/path` |
| `ns/<kind>` | task->ns handle | symlink with inode-only target |
| `oom_score`,`oom_score_adj` | OOM score | integer |
| `task/<tid>/...` | per-thread mirror | as above |

Global (`/proc/`):

| Path | Format |
|---|---|
| `cpuinfo` | per-cpu key:val |
| `meminfo` | mem stats key:val (kB) |
| `stat` | system counters (boot-rel) |
| `loadavg` | 5 numbers |
| `uptime` | secs.frac, idle |
| `version` | one line |
| `cmdline` | kernel cmdline |
| `mounts`,`filesystems`,`partitions`,`devices`,`modules` | as named |
| `kallsyms` | sym table; gated by `kptr_restrict` |
| `interrupts`,`softirqs` | per-cpu counters |
| `self`,`thread-self` | symlinks |
| `sys/...` | sysctl tree (sparse subset; see `27§sysctl`) |

## 5 sysfs structure

Object model: `KObj` tree with attributes. Linker-generated tables register class/bus drivers at boot.

| Path | Pop. by |
|---|---|
| `/sys/devices/` | `Drv` per device |
| `/sys/class/<class>/<name>` | symlinks (`block`,`net`,`tty`,`input`) |
| `/sys/block/<dev>/{size,queue/...,partition,...}` | block driver |
| `/sys/bus/{pci,usb,virtio}/...` | bus drivers |
| `/sys/firmware/{efi,acpi,devicetree}` | `33` |
| `/sys/kernel/...` | misc kernel-level |
| `/sys/module/<n>/{parameters/,sections/,refcnt}` | `18` |
| `/sys/fs/cgroup/...` | `26` (cgroup2 mount) |

Attributes: `show()` for read, `store()` for write. One attr = one file. Read returns `show()` snapshot. Write calls `store()` with raw bytes; up to attr to parse.

## 6 devfs (devtmpfs)

Auto-populated by kernel as drivers register devices (`Drv` `35`). Userspace `udev`-equivalent (we don't ship udev; we fully populate from kernel) layers symlinks via writing to `/dev/disk/by-*/`,`/dev/serial/by-*/` from initramfs.

Mandatory nodes per `03§5.1`. Permissions per device: char-misc default `0666` for `null/zero/full/random/urandom`, `0666` for `tty/ptmx`, `0644` for `kmsg` write/`0440` read. Adjusted by initramfs script if needed.

Denied nodes: `/dev/mem`,`/dev/kmem`,`/dev/port` — `mknod` rejected, `open` returns EPERM if synthesized.

## 7 Concurrency

- procfs read: snapshot under per-source lock; emit. RCU walk for task-list-derived files.
- sysfs `show`/`store`: serialized per-attr by attr-level mutex; parent KObj read-locked.
- devfs registration: per-class mutex.
- All path lookups go through VFS dentry cache (`16`).

## 8 Perf budget

| Op | p99 |
|---|---|
| `cat /proc/self/stat` | ≤ 5 µs |
| `cat /proc/meminfo` | ≤ 10 µs |
| `cat /sys/class/net/lo/operstate` | ≤ 3 µs |
| Path lookup `/proc/1234/maps` | ≤ 3 µs cached |

procfs is not on hot paths; budgets are loose.

## 9 Test contract (frozen)

- Build a fixture: spawn 8 tasks, each opens 4 files, mmaps anon, sleeps. Read every `/proc/<pid>/*` file from another task; assert no panics, all files parse with regex matching Linux's format.
- Run `busybox ps`,`top`,`free`,`uptime`,`mount`,`lsmod`. Each must produce well-formed output (validated by output-comparison against expected substrings, not byte-for-byte).
- Run `udevadm trigger` equivalent (we have our own minimal initramfs walker); assert `/dev/disk/by-*` symlinks present.
- Stress: 4 readers concurrently `find /proc -type f -exec cat {} +` while workload runs; zero panics, zero corrupt reads.
- Coverage ≥85% (lots of sparse pseudo-files; pure coverage less informative).

## 10 Failure modes

- procfs read of dead task: ESRCH or empty (per Linux for each file).
- sysfs store invalid value: EINVAL with no state change.
- devfs node open with no driver: ENXIO.

## 11 Debug

`debug-procfs`: log every open with path + caller pid+comm.

## 12 Cross-spec

`16` (mounted as a Filesystem), `26` (cgroup2 mount), `33` (firmware tables), `35` (driver registration), `18` (`/proc/modules`,`/sys/module/`).

## 13 Open Questions

- `/proc/sys/` (sysctl): generate from a single static schema in `27`, or per-domain? Lean: per-domain registration, central index.
- Hide-pid default: `0`,`1`,`2`? Lean: `0` for v1 (Linux default); userspace can tighten via `mount -o remount,hidepid=2`.
- `/proc/<pid>/io` (per-process I/O accounting): defer to v1.x.
- `/proc/<pid>/oom_score` formula: copy Linux's exactly. Lean: yes.
