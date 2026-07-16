# Magic-number and GNOME boot audit

Scope: `crates/arch`, `crates/drivers`, `crates/kernel`, and `crates/user` on
`main` at `ba25e43f3`; live-GNOME evidence through 2026-07-16.

## Work ledger

| Status | Branch | Work item |
|---|---|---|
| DONE | B890-signal-contract | Replace raw signal values and ranges with the canonical `sched::Signum` contract. |
| DONE | B889-errno-contract | Replace raw errno returns in kernel compatibility paths. |
| DONE | B888-magic-abi | Replace the raw x86 arch-prctl syscall and operation values. |
| DONE | B892-page-alignment | Consolidate page geometry in the VMM and mprotect/mremap admission paths. |
| DONE | B893-block-major-uapi | Centralize Linux block majors in the block registry and consume them from `/proc/devices`. |
| OPEN | unclaimed | Move device, protocol, IRQ, and synthetic inode IDs into `ids.rs`, `uapi.rs`, `wire.rs`, or `layout.rs`. |
| OPEN | unclaimed | Expand `code/magic-errno` into context-aware ABI and semantic-literal lints. |
| OPEN | unclaimed | Reproduce and isolate PID 1's D-Bus listening-fd `EBADF` after broker exit. |
| OPEN | unclaimed | Isolate the live `/run/udev/data/c226:0` loss across mount-namespace views. |
| OPEN | unclaimed | Isolate the netlink uevent listener registry across parallel hosted tests. |
| OPEN | unclaimed | Fix read-only-mount handling for writes to special device files. |
| OPEN | unclaimed | Restore loopback discovery and verify the GDM/VT path after the udev seat gate. |

## Audit boundary

`07§5` forbids bare errno, open/mmap/socket flags, signal numbers, syscall slots,
permissions, page geometry, device numbers, protocol values, IDs, and timeouts in
logic. Zero, one, tiny indexes, counts with an obvious local meaning, tests, and
the defining constant itself are not findings.

The inventory is a heuristic source sweep, not an AST proof. Generated/vendor
sources and C probes are excluded. Test paths, comments, and constant declarations
are excluded where the search can distinguish them. Counts are therefore backlog
size indicators, not CI-stable metrics.

## Findings

| Priority | Class | Evidence | Risk |
|---|---|---|---|
| P0 | Signals | The identified raw-signal sites now use `sched::Signum` or shared real-time helpers; the final SIGWINCH bit sites are resolved in B891. | Wrong disposition, wakeup, ptrace stop, or fatal delivery. |
| P0 | Errno/syscall ABI | The 16 raw negative-result lines and ldso raw x86 syscall identified by this audit are resolved by B888/B889; continue scanning new ABI bridges. | Wrong ABI value and architecture drift. |
| P1 | Synthetic inode IDs | 27 inline `InodeBuilder` hex bases; ownership is not centralized. | Object-identity aliasing within a pseudo-filesystem. |
| P1 | Permissions | About 195 non-test inline octal lines across 91 files. | Mode drift and inconsistent policy. |
| P1 | Page geometry | About 406 non-test inline `4096`/`0xfff`/`0x1000` lines across 152 files. | Alignment and page-size assumptions diverge. |
| P1 | Hardware/protocol IDs | Raw IRQ vectors, exception classes, EtherTypes, device majors, PS/2 bytes, and VT control bytes remain in dispatch logic. | Cross-arch and wire-contract drift. |
| P2 | Fixed buffers/limits | About 64 non-test fixed-buffer lines across 42 files. | Truncation or silent behavior changes when limits evolve. |

### Raw signal values

The repository already has canonical `sched::Signum`, `Signum::bit()`,
`is_unblockable()`, and default-action helpers. The following call sites bypass
them:

| File | Raw value | Meaning |
|---|---:|---|
| `crates/kernel/syscalls/src/signal_common.rs:28` | 18 | `SIGCONT` permission exception. |
| `crates/kernel/syscalls/src/062_kill.rs:45,88,109` | 18 | `SIGCONT` wakes stopped tasks. |
| `crates/kernel/syscalls/src/234_tgkill.rs:64` | 18 | Same wake path. |
| `crates/kernel/syscalls/src/424_pidfd_send_signal.rs:76` | 18 | Same wake path. |
| `crates/kernel/syscalls/src/101_ptrace.rs:367` | 19 | Stores `SIGSTOP`. |
| `crates/kernel/syscalls/src/dispatch/ptrace.rs:15` | 5 | Delivers `SIGTRAP`. |
| `crates/kernel/syscalls/src/dispatch/core.rs:95` | 19–22 | Stop-signal classification. |
| `crates/kernel/security/src/seccomp.rs:296,300` | 9, 31 | Sets `SIGKILL` and `SIGSYS` bits manually. |
| `crates/kernel/mm-pmm/src/user_as/signal.rs:50` | 11 | Fetches the `SIGSEGV` action. |
| `crates/kernel/smoke/src/elf.rs:57` | 11 | Terminates with `SIGSEGV`. |
| `crates/kernel/sched/src/live/stop.rs:25` | 19 | Stops until `SIGCONT`. |
| `crates/kernel/sched/src/sigqueue.rs:17,36` | 33 | RT queue base. |

The `33..=64` range also appears in scheduler, signalfd, and syscall logic.
Add named RT bounds/index helpers beside `Signum`; do not replace these with
scattered local constants.

### Raw errno and syscall values

| File | Finding | Replacement owner |
|---|---|---|
| `crates/kernel/netlink/src/rtnetlink/route_ops.rs:295-296` | `-2` and `-22` map route errors. | `Errno::Enoent` and `Errno::Einval`. |
| `crates/kernel/modules/src/linux_string/match_parser.rs:54-68` | Repeated `-22`. | Linux-compat errno helper backed by `Errno`. |
| `crates/kernel/modules/src/linux_string/cstr.rs:166` | Raw `-7`. | `Errno::E2big`. |
| `crates/kernel/modules/src/linux_debugfs_extra.rs:143-217` | Repeated `-22`. | Same typed errno bridge. |
| `crates/user/ldso/src/syscall.rs:84` | Raw x86 `arch_prctl` syscall and operation values. | Named `nr::ARCH_PRCTL` and `nr::ARCH_SET_FS`, matching the existing arch UAPI contract. |

Negative values used as private parser sentinels in glibc are not errno findings
unless they cross a syscall/C ABI boundary.

### Page geometry, modes, and limits

High-risk page literals are in MM and syscall admission paths, including
`mm-vmm/src/address_space.rs`, `mm-vmm/src/tree.rs`, `mm-vmm/src/address_space/*`,
`syscalls/src/010_mprotect.rs`, `025_mremap.rs`, `462_mseal.rs`, `vdso.rs`,
`userbuf.rs`, and `mount_common.rs`. These must use the architecture/VMM page
contract, not per-file `0xfff` masks.

Inline permissions are widespread in procfs, devpts, cgroupfs, tmpfs, console,
devfs, and syscall code. Constants should describe semantics (`PROC_RO_MODE`,
`DEVPTS_SLAVE_MODE`, `TMPFS_ROOT_MODE`, `MODE_PERM_MASK`) in owning `uapi.rs`,
`flags.rs`, or `limits.rs`; a global dumping-ground constant module would violate
the ownership rule.

Fixed buffers deserve conversion only when the number expresses a contract.
Examples are the 4 KiB path/xfer buffers in `sched/src/xfer.rs`, DNS buffers in
glibc resolver code, 304-byte autofs packets, and staged sound buffers. Local
formatting scratch space with a proven bound is lower priority.

### IDs, wire values, and layouts

| File | Finding | Owner |
|---|---|---|
| `crates/kernel/procfs/src/devices.rs:19-21` | Raw majors 8, 254, 259 in dispatch. | Block-device `ids.rs`/UAPI. |
| `crates/drivers/drv-virtio-net/src/modern/rx.rs:173-214` | Raw ARP/IPv4/IPv6 EtherTypes. | Network wire constants. |
| `crates/arch/hal-x86_64/src/irq.rs:261-268` | Raw IRQ vectors `0x50..0x57`. | x86 IRQ vector IDs. |
| `crates/arch/hal-aarch64/src/fault.rs:118-137` | Raw ESR exception classes. | AArch64 exception IDs. |
| `crates/drivers/drv-ps2-keyboard/src/scancode.rs:72-82` | Raw prefix/ACK/error bytes. | PS/2 wire constants. |
| `crates/kernel/vt/src/emulator/parser.rs` | Raw ECMA-48/C0/C1 bytes. | VT parser wire constants. |
| `crates/kernel/ext4/src/xattr.rs:61-63` | Raw xattr namespace indices. | ext4 on-disk UAPI. |
| `crates/kernel/syscalls/src/179_quotactl_xfs/*` | Repeated `0x51544154`, `0x5806`, and 4096 in fixtures/helpers. | XFS quota UAPI/layout. |

Protocol parser tables may remain numeric only in one named table that is itself
the canonical wire definition. Numeric arms spread through operational logic are
findings.

### Synthetic-inode ownership correction

The earlier sweep called `0x3000_1C00` in
`crates/kernel/procfs/src/live/self_files.rs:339` and
`crates/kernel/procfs/src/syscpu.rs:113` a collision. That is not a Linux-visible
collision: `/proc/sys/kernel/hostname` is on procfs (`PROCFS_FSID`), while
`/sys/devices/system/cpu` is on sysfs (`SYSFS_FSID`); inode numbers are scoped by
superblock. The finding is reclassified as an ownership/readability concern,
not a correctness bug. Do not invent a cross-filesystem global inode allocator.

### Lint gap

`tools/spec-lint/src/code_lint.rs:102-135` only detects a bare literal assigned
to identifiers ending `_eno`, `_errno`, `_signo`, or `_slot`. It cannot detect
raw comparisons, match arms, bit positions, return values, syscall calls,
permissions, page masks, or IDs. The clean path is several narrow context-aware
lints with explicit definition/test exemptions; one broad integer regex would
produce unusable noise.

The focused netlink uevent suite also exposes test isolation debt: the default
parallel runner fails 2/4 because concurrent cases share `UEVENT_LISTENERS` and
observe two recipients where one is expected. The same four tests pass with
`--test-threads=1`. This does not prove a production transport bug, but a global
listener fixture that only passes serialized can hide lifecycle defects.

## GNOME boot analysis

### Fresh current-head result

An isolated x86 boot of audited HEAD, with a freshly built kernel and
`debug-udevdb,debug-uevent,debug-mnt`, reaches a new earlier failure at guest
time 154 seconds:

1. `dbus-broker.service` starts at 89.112 seconds, then exits with status 1 at
   153.870 seconds.
2. PID 1 tries to watch the socket unit's listening descriptors and reports
   `dbus.socket: Failed to watch listening fds: Bad file descriptor` (`EBADF`).
3. The socket unit fails with result `resources`.
4. systemd then asserts `close_nointr(fd) != -EBADF` in `safe_close()`, catches
   `SIGABRT`, and freezes PID 1 at 154.511 seconds.

This is the current first wall. The kernel has invalidated or lost a descriptor
that PID 1 still believes it owns, or exposed behavior that makes systemd close
that descriptor twice. The trace does not yet distinguish fd-table slot loss,
incorrect fork/exec/`CLONE_FILES` separation, premature last-file release, or an
earlier erroneous close/reuse. `056_clone.rs` and `vfs::FdTable::fork_clone()`
do implement the expected copied-table/shared-file-description shape, so changing
that path without a causal reproducer would be speculation.

The next test should model socket activation directly: PID 1 owns a listening
socket, forks and execs a broker with the inherited descriptor, the broker exits,
and the parent must still be able to poll, close, and restart from its copy. Trace
`(pid,tgid,fd,fdtable identity,Arc<File> identity,close/dup/exec/release)` for that
one socket through the failure.

### Persistent downstream seat failure

The same fresh boot also proves the udev failure remains after the D-Bus wall is
removed. Udev successfully renames the database record into
`/run/udev/data/c226:0` twice (58.179 and 58.694 seconds) and creates
`/run/udev/tags/master-of-seat/c226:0` from mount namespace 10. Later, logind in
mount namespaces 17 and 19 resolves the DRM sysfs device and the surviving tag
directory but gets `ENOENT` for the database record at 142.483--153.934 seconds.

That is stronger than a missing-event hypothesis: the record is published, then
is absent from later task views. The leading boundary is mount/root identity
drift, private `/run` visibility, subtree replacement, or an unobserved deletion.

### Earlier observed GDM frontier

The user-owned July 15 capture reaches `graphical.target` in 38.851 seconds and
starts `gdm.service`. Journald, dynamic linking, GDM packaging, and basic DRM
publication are no longer the first wall in that capture.

The failure chain is:

1. Virtio-GPU enables a 640x480 scanout and publishes `card0`.
2. logind resolves `/sys/dev/char/226:0`, `/sys/class/drm/card0`, the parented
   DRM `uevent`, and the `subsystem` symlink.
3. logind opens `/run/udev/data/c226:0` and gets `ENOENT`.
4. No `New seat seat0` or `CAN_GRAPHICAL=1` evidence appears.
5. GDM logs `Failed to query CanGraphical information for seat seat0`.
6. No `gdm-session-worker`, `gnome-session`, Mutter, or `gnome-shell` starts
   during the remaining capture.

This matches the contract in `60§2`: without the DRM udev database record and
`master-of-seat` state, logind cannot expose a graphical seat and GDM will not
spawn the greeter. DRM ioctl completeness is downstream of this gate.

### Strongest root-cause boundary

Both the fresh boot and earlier instrumented evidence record
`/run/udev/data/c226:0` being created twice, then becoming invisible while
`/run/udev/tags/master-of-seat` remains.
The hosted `udev_runtime_mounts` and `fs_syscall_model` tests preserve the record
across modeled udev/logind namespaces. Therefore the leading fault class is not
basic tmpfs create/rename or the DRM sysfs shape. It is one of:

| Rank | Hypothesis | Decisive evidence needed |
|---:|---|---|
| 1 | Live task root/cwd/mount identity drifts from the namespace used by the udev writer. | Log writer and logind `(pid,mnt_ns,mnt_id,root_id,path)` at create/rename/open. |
| 2 | A live cleanup path unlinks the database record or replaces `/run/udev/data`. | Trace `unlinkat`, `rmdir`, `renameat2`, mount, move-mount, and detach on `/run/udev`. |
| 3 | Udev writes a private `/run` view not shared with logind. | Record the exact `VfsMount`/superblock identity at write and read. |
| 4 | Raw/cooked uevent loss prevents a stable database record. | Trace group-1 delivery, worker completion, cooked group-2 rebroadcast, and reach counts. |

Do not begin with Mutter, Mesa, or additional DRM ioctls. They are not reached.

### Secondary kernel blockers already visible

`crates/kernel/vfs/src/file/io.rs:129-139` rejects every write when the containing
mount has `MNT_RDONLY`. Both captures prove special-device writes return `EROFS`
inside private read-only device mounts; the fresh boot shows `/dev/kmsg` failing
with mount flags `0x60`, and the earlier capture shows `/dev/null` with `0x41`
while its superblock remains writable. Linux read-only mounts prohibit filesystem
mutation, not I/O through character devices.
The VFS gate must exempt special-device I/O or move write-protection to regular
filesystem mutation paths. This will affect sandboxed desktop services even after
the seat gate clears.

The same capture reports loopback setup `ENODEV` for several services. Networking
does not explain the missing graphical seat, but GNOME user services will assume
working loopback after the greeter starts.

`/dev/tty0` also returns `ENXIO` early. Re-test it after the seat fix because GDM,
logind, and Mutter later depend on VT/session device semantics.

### Evidence caveat

The main-tree `boot.txt` capture is user-owned and uncommitted. Its mtime is
2026-07-15 08:35 EDT, while audited `main` is from 17:41 EDT and includes later
mount-namespace ownership changes. `target/artifacts/x86_64/kernel.elf` is older
still (2026-07-13). Per the stale-artifact rule, this capture identifies the last
observed GDM frontier but cannot prove current `main` still fails identically.
The fresh worktree boot is current-head evidence: it confirms the downstream
udev-record disappearance and read-only special-device bug, but PID 1 freezes on
the earlier D-Bus descriptor failure before GDM can start.

### Next proof sequence

1. Reproduce the D-Bus socket-unit `EBADF` with focused fd identity/lifetime
   tracing and add the socket-activation hosted test described above.
2. After PID 1 survives broker failure/restart, require one capture to show DRM
   raw uevent, udev worker database rename, tag creation, cooked rebroadcast,
   logind database open, and GDM result.
3. Add targeted deletion and mount/root/superblock identity tracing for
   `/run/udev/data/c226:0`, then create a deterministic hosted reproducer before
   changing mount/VFS code.
4. Fix the special-device read-only-mount bug independently with a hosted
   char-device-on-RO-mount test.
5. Re-run both architectures through the userspace-seat gate, then resume at the
   first real GDM worker/Mutter failure.

## Verification

| Check | Result |
|---|---|
| `cargo test -q -p fs --test udev_runtime_mounts -- --nocapture` | PASS, 3/3. |
| `cargo test -q -p fs --test fs_syscall_model -- --nocapture` | PASS, 1/1. |
| `cargo test -q -p netlink uevent -- --nocapture` | FAIL, 2/4 from parallel shared-listener interference. |
| `cargo test -q -p netlink uevent -- --nocapture --test-threads=1` | PASS, 4/4. |
| `cargo run -q -p spec-lint -- length .` | PASS. |
| `cargo check -q -p modules -p netlink` | PASS (existing cfg/unused warnings only). |
| `cargo check -q -p sched -p syscalls -p security -p smoke` | PASS (existing cfg/unused warnings only). |
| Fresh isolated x86 boot, current HEAD, udev/uevent/mount tracing | FAIL: D-Bus listener `EBADF`, PID 1 abort/freeze; downstream udev-record loss confirmed. |
| `git diff --check` | PASS. |
