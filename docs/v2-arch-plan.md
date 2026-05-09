# V2 architectural pieces — plan + spec deltas

DRAFT 2026-05-09. Dep:`00`,`02`,`MANIFEST`,`docs/v2/`.

Companion to `00-v2.md` and `kernel-audit.md`. v1 substrate work F89..F115
landed the small-PR-shaped v2-rollin items; everything left is an
architectural piece that needs spec revision before code per `02§1`
(spec-before-code).

## 1 Pieces (in landing order)

Each entry: what it is, what's blocked today, which spec gets the
R-revision, what the v1 implementation will look like.

### 1.1 Real PTRACE_SETREGS + PEEKUSER + per-arch frame writeback

**Today:** F115 reads regs from `task.kernel_stack - 0x80` (x86) /
`-0xD0` (aarch64). Writes (PTRACE_SETREGS) silent-0; PEEKUSER returns
EOPNOTSUPP. Tracer can read but not modify tracee state.

**v1 plan:** symmetric writeback to the same offsets. Add per-arch
HAL helper `user_regs_at_kstack(top: u64) -> *mut UserRegs` so the
syscall_glue layer doesn't hardcode offsets. PEEKUSER stays
EOPNOTSUPP for now (struct user is per-arch + extends past
saved-frame regs — fp/dr/segment regs that aren't on the stack).

**Spec:** `27-security.md` ptrace section — R-revision adding the
write-back contract. **Status:** FROZEN; needs R03 (R01/R02 already
exist).

**Code surface:** ~50 lines in `syscall_glue_signal.rs`.

### 1.2 Real setns + NsInode

**Today:** `setns(fd, nstype)` clears membership bits on the calling
task. Doesn't actually move into the NS represented by the fd.
F112 made `/proc/<pid>/ns/<type>` readlinks dynamic but the leaf
itself isn't an Inode.

**v1 plan:** new `NsInode { kind: NsKind, id: u64 }` registered at
`/proc/<pid>/ns/<type>` lookup time. open(path) yields a fd whose
File.inode is an NsInode. setns(fd, nstype) downcasts via
`Inode::as_any` (already supported), validates kind, writes
`task.<x>_ns = NsInode.id`.

**Spec:** `26-namespaces-cgroups.md` — R-revision for setns/Open
contract on /proc/<pid>/ns/<type> + the NsInode shape.
**Status:** FROZEN; first revision.

**Code surface:** ~80 lines: NsInode struct + procfs lookup arm +
setns rewrite.

### 1.3 USER NS cap scoping

**Today:** F92/F93/F95 cap-check via `cur.has_cap(CAP_X)` against
the global `cap_effective` mask. A non-init user_ns task with
CAP_FULL inside its NS can affect anything globally.

**v1 plan:** `has_cap_for(target_user_ns, cap)` helper. Returns
true if `cap_effective` has the bit AND
`(target_user_ns == cur.user_ns OR target_user_ns is descendant of
cur.user_ns OR cur is in init NS)`. Convert privileged sites: kill
(target's user_ns), mount (target mount_ns's owning user_ns),
ptrace (target's user_ns), CAP_NET_ADMIN ops (target's net_ns's
owning user_ns).

User-NS hierarchy: each user_ns records its parent at unshare time;
descendant check walks up.

**Spec:** `27-security.md` capabilities section — R-revision adding
per-NS scoping rule + `parent_user_ns` field. **Status:** FROZEN.

**Code surface:** ~150 lines: parent_user_ns field on Task, walker
helper, ~10 callsite conversions.

### 1.4 Real mount(2) per-NS table + bind mounts

**Today:** F110 mount(tmpfs) registers the new inode in the GLOBAL
devfs registry. All mount_ns ids see the same path — F107 substrate
unused.

**v1 plan:** per-NS mount table `BTreeMap<(mount_ns, path), Inode>`.
devfs::lookup consults `(cur.mount_ns, path)` first, falls back to
init-NS (mount_ns=0) entries. mount(2) writes to `(cur.mount_ns,
target)`. unshare(CLONE_NEWNS) snapshots parent's NS table into
the new id (copy-on-write).

Bind mounts: `mount("/src", "/dst", "none", MS_BIND, ...)` — looks
up source inode, registers it at dst path in caller's mount_ns.

**Spec:** `16-vfs.md` — mount-table section (probably exists; needs
R-revision pinning per-NS shape). `26§4` namespace section ditto.

**Code surface:** ~200 lines: per-NS table data structure, lookup
plumbing, snapshot at unshare, MS_BIND handling.

### 1.5 AF_UNIX message framing + SCM_CREDS + SCM_RIGHTS

**Today:** AF_UNIX SOCK_STREAM byte-stream only. cmsg ignored on
both send + recv. SO_PEERCRED returns connect-time creds (real per
F66). SOCK_DGRAM not admitted.

**v1 plan:** parallel `UnixDgramQueue: VecDeque<UnixMsg>` where
UnixMsg = `{ payload: Vec<u8>, cmsgs: Vec<Cmsg> }`. SOCK_DGRAM
admitted via `(AF_UNIX, SOCK_DGRAM)`. sendmsg parses msg_control;
recvmsg writes back any per-message cmsgs.

For SOCK_STREAM with SCM_RIGHTS: track per-position cmsgs in a
side channel (Linux pattern). Receiver getting fds: dup each into
its fd_table at recvmsg time.

**Spec:** `24-ipc.md` AF_UNIX section — R-revision for SCM cmsg +
SOCK_DGRAM. **Status:** FROZEN.

**Code surface:** ~250 lines: UnixDgramQueue + Cmsg struct + cmsg
parse/write + fd dup-into-table at recv.

### 1.6 Dentry layer + IN_CREATE/IN_DELETE/IN_MOVED inotify

**Today:** flat devfs registry — no real directory inodes. Inotify
on /dev as a directory can't fire IN_CREATE because there's no
parent-dir watch concept.

**v1 plan:** per-directory `DentryInode { children: BTreeMap<String,
InodeRef> }`. devfs::register splits path into (parent, leaf), walks
to parent dentry, inserts. unregister removes. Both fire dentry-
mutation hooks (`vfs::set_dirent_hook(fn(parent_inode, name, kind))`)
for inotify.

Inotify watches on a directory now fire IN_CREATE/IN_DELETE with
the new dirent name in the event's name tail.

**Spec:** `16-vfs.md` dentry section — R-revision pinning the tree
shape + dirent hook. `19-dev-proc-sysfs.md` — note that devfs
backs onto the dentry layer instead of a flat string registry.

**Code surface:** ~400 lines (touches devfs, procfs, inotify,
several callsites).

### 1.7 BPF subset (cBPF interpreter + admin syscall + fd-typed prog)

**Today:** seccomp uses cBPF interpreter (real). Standalone
`bpf(2)` syscall returns ENOSYS or fakes a fd via memfd_create.
No prog admit, no maps, no helpers.

**v1 plan:** narrow cBPF-only bpf(2): BPF_PROG_LOAD admits + stores
the cBPF instructions in a BpfProgInode; BPF_MAP_CREATE creates a
BpfMapInode (hash map, byte-keyed). Helper functions: get_pid,
get_uid, log to klog. No verifier yet — all programs run; if they
crash the kernel, that's the unverified-bpf bug. Restrict to
CAP_BPF callers.

**Spec:** `27-security.md` BPF section — R-revision for v1 cBPF
admit + map types.

**Code surface:** ~300 lines: BpfProgInode + BpfMapInode + 3-4 op
handlers in bpf(2).

### 1.8 tracefs + ftrace static tracepoints

**Today:** klog ring + perf_event_open exist. No tracepoints
infrastructure. /sys/kernel/tracing not registered.

**v1 plan:** tracefs registered at /sys/kernel/tracing. Static
tracepoints embedded at sched_switch + sys_enter + sys_exit
sites — recorded into a per-CPU ring buffer. /sys/kernel/tracing/
{available_events, enable, trace, trace_pipe} as static or
dynamic inodes.

**Spec:** `37-observability.md` ftrace section — R-revision.
**Status:** FROZEN.

**Code surface:** ~500 lines: tracefs, tracepoint macro, ring
buffer per CPU, control-file inodes.

### 1.9 DRM/KMS + virtio-gpu + evdev

**Today:** `dev_drm.rs` has DRM_IOCTL_VERSION + capability ioctls.
No real CRTC/connector/framebuffer; no virtio-gpu device probe;
no evdev /dev/input/eventN.

**v1 plan:**
  - virtio-gpu PCI driver in `crates/virtio` (separate from
    virtio-net): DRIVER_OK, queue setup, RESOURCE_CREATE_2D,
    TRANSFER_TO_HOST_2D, RESOURCE_FLUSH.
  - DRM ioctls: MODE_GETRESOURCES, GETCONNECTOR, GETENCODER,
    CREATE_DUMB, MAP_DUMB, GETFB, ADDFB2, SETCRTC.
  - evdev: virtio-input PCI driver; /dev/input/event0..N inodes
    with EVIOC* ioctls for keyboard + mouse.

**Spec:** `35-drivers.md` — new sections for virtio-gpu and
virtio-input. `19-dev-proc-sysfs.md` — /dev/input/* registration.

**Code surface:** ~1500 lines (this is the largest piece).

## 2 Landing order

Spec-discipline says no code while DRAFT. Order is:
1. Each spec gets its R-revision and lands as a D-PR.
2. Code PR lands after the corresponding spec is committed.

Sequence (smallest substrate first, then dependents):

1. R-PR for `27` ptrace + cap-scoping (1.1 + 1.3).
2. F-PR for 1.1 (PTRACE_SETREGS).
3. R-PR for `26` setns + NsInode (1.2).
4. F-PR for 1.2 (setns).
5. R-PR for `16` per-NS mount table + dentry tree (1.4 + 1.6).
6. F-PR for 1.4 (per-NS mount table — uses dentry tree).
7. F-PR for 1.6 (dentry tree + inotify dentry hooks).
8. F-PR for 1.3 (USER NS cap scoping — depends on `27` revision).
9. R-PR for `24` AF_UNIX SCM (1.5).
10. F-PR for 1.5 (AF_UNIX SCM_CREDS + SCM_RIGHTS + DGRAM).
11. R-PR for `27` BPF + `37` ftrace (1.7 + 1.8).
12. F-PR for 1.7 (BPF subset).
13. F-PR for 1.8 (tracefs).
14. R-PR for `35` virtio-gpu + virtio-input (1.9).
15. F-PR for 1.9 (DRM/KMS + virtio-gpu + evdev).

Each F-PR may further split into 2-3 commits when natural.

## 3 What this delivers when done

- v2 phase 21 namespaces: USER NS cap scoping, mount NS real, setns honest.
- v2 phase 22: ptrace GETREGS+SETREGS round-trip; gdb attach + step.
- v2 phase 24: AF_UNIX SCM_CREDS/SCM_RIGHTS/DGRAM — systemd, dbus, sshd unblocked.
- v2 phase 26: file caps + ACL substrate (storage already F90/F103; access checks ride 1.4 dentry tree).
- v2 phase 27: fanotify + recursive inotify with dentry-mutation events.
- v2 phase 29: real mount(2) with per-NS visibility + bind mounts.
- v2 phase 30: tracefs + ftrace static tracepoints + perf hookup.
- v2 phase 32: DRM/KMS + virtio-gpu + evdev — gates Wayland/GNOME ladder.
- v2 phase 24 BPF: cBPF programs + maps from userspace.

After 1.1..1.9 ship, the v2 kernel-parity track is substantively
complete. v2.x desktop work (Wayland/GNOME/USB/ACPI runtime/etc.)
remains.

## 4 Out of scope here

Per user direction "binaries and user space shit is not the kernel":
phases 33-37 (ld-musl, libc/NSS/PAM, system manager, package manager,
TTY+login) are NOT covered here. Those are userspace and ride
separately.

## 5 Cross-references

`00§3.2` (v2 phase ladder); `00-v2.md§3` (v2-local mirror);
`02§3` (R-revision protocol on FROZEN specs); `kernel-audit.md`
(F89..F115 progress).
