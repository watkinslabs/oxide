# Oxide Kernel Status

Code scan date: 2026-07-07. Source basis: `crates/**` and top-level build manifests only; this report does not use subsystem specs as evidence.

## Executive State

Oxide is past a boot-only skeleton. The tree contains a Rust kernel with active x86_64 and aarch64 boot/entry paths, PMM/VMM work, scheduler/process state, a broad Linux syscall router, VFS and multiple pseudo filesystems, ext4/tmpfs work, a reworked driver model, PCI/virtio devices, networking, tty/console, cgroups, security hooks, modules/Linux KPI pieces, and a Rust glibc-ABI userspace.

It is not Linux-complete. The main missing work is not one subsystem; it is semantic depth across Linux ABI compatibility, long-tail device classes, full memory-management policies, full networking/firewall behavior, complete module loading/KPI, complete systemd/udev/distro behavior, and conformance testing.

## How It Connects

| Layer | Code | Connection |
|---|---|---|
| Boot/arch | `crates/arch/boot-*`, `crates/arch/hal-*`, `crates/arch/kernel-bin-*` | Boot stubs build `BootInfo`, arch HAL installs page tables, traps, IRQ/syscall entry, timer, and context-switch machinery. |
| Kernel entry | `crates/kernel/kmain` | Wires clocks, VFS roots, device nodes, proc/sysfs hooks, network hooks, consoles, drivers, and smoke paths. |
| Syscall ABI | `crates/kernel/syscall`, `crates/kernel/syscalls` | HAL syscall assembly calls `syscalls::dispatch::oxide_syscall_dispatch`; it routes to per-subsystem handlers and falls back to the low-level `syscall` table. |
| Memory | `crates/kernel/mm-pmm`, `crates/kernel/mm-vmm`, `crates/shared/slab`, `crates/shared/kalloc` | PMM provides frame allocation/user address helpers; VMM owns address spaces, VMAs, faults, COW, rmap pieces, mmap/mprotect/munmap/mremap; slab/kalloc back kernel allocation. |
| Scheduling/process | `crates/kernel/sched`, `crates/kernel/ipc` | Tasks, run queues, CFS/RT shape, creds, timers, signals, futexes, wait queues, process groups/sessions, rlimits, pidfd, clone/exec/wait glue. |
| VFS/filesystems | `crates/kernel/vfs`, `crates/kernel/fs`, `crates/kernel/ext4`, `crates/kernel/devfs`, `crates/kernel/procfs`, `crates/kernel/sysfs`, `crates/kernel/kernfs`, `crates/kernel/devpts`, `crates/kernel/tracefs` | VFS object model, fd tables, mounts, dcache/namei, inode/file ops; ext4 and tmpfs data paths; dev/proc/sys/trace/devpts pseudo filesystems. |
| Block/storage | `crates/kernel/block`, `crates/drivers/drv-virtio-blk`, `crates/drivers/drv-nvme`, `crates/drivers/drv-ahci` | Block registry/page cache and disk stats connect storage drivers to ext4 and proc/sysfs. |
| Drivers | `crates/drivers/drv`, `pci`, `virtio`, `drv-*`, `drm`, `fbdev`, `fbcon`, `vt` | Driver core, PCI enumeration/resources, virtio transport, net/block/gpu/input/rng/vsock/sound devices, UART/serial/PS2, framebuffer/DRM/VT surfaces. |
| Networking | `crates/kernel/net`, `netlink`, `netfilter`, `drivers/drv-virtio-net` | Ethernet, loopback, virtio-net, IPv4/IPv6, ARP/NDP, ICMP, UDP/TCP, AF_UNIX, AF_PACKET, vsock, rtnetlink, sock_diag, nft/netfilter pieces. |
| TTY/console | `crates/kernel/tty`, `console`, `vt`, `vtconsole`, `serialtty`, `tty-integration`, `fbcon` | TTY core, PTY/devpts, serial tty, virtual terminals, framebuffer console, `/dev/console`, VT ioctls. |
| Security/isolation | `crates/kernel/security`, `cgroup`, `nscg` | Seccomp/cBPF, BPF interpreter/verifier pieces, Landlock, capabilities/creds, cgroup v2, UTS/proc namespace pieces. |
| Modules/KPI | `crates/kernel/modules` | ELF relocator, symbol table, module registry, and partial Linux KPI families for alloc, chrdev/block, device/devres, DMA, IRQ, PCI, netdev/skb, input, firmware, crypto, sync, time, PM, platform, USB, usercopy. |
| Userspace ABI | `crates/user/glibc`, `ldso`, `crt1`, `nss`, `pam`, `svc`, `rpm`, `pkg` | Rust glibc-ABI libc, dynamic loader pieces, startup objects, NSS/PAM parsers, service-unit parser/supervisor, RPM/package readers. |

## Present Systems

| Area | Code-observed status |
|---|---|
| Architectures | x86_64 and aarch64 boot/entry/HAL crates exist with syscall, fault, timer, MMU, signal, context, PCI, and interrupt code. |
| Syscalls | Active `oxide_syscall_dispatch` routes hundreds of Linux x86_64-numbered syscalls across files and subsystems. A mechanical code scan found one declared syscall constant not referenced by active code: `NR_LISTNS`/470. |
| Process model | Clone/fork/vfork/clone3, execve/execveat, exit/exit_group, wait4/waitid, pidfd, sessions, process groups, signals, timers, rseq, robust futex list, and scheduling calls are represented in active handlers. |
| Memory | Buddy PMM, page metadata, user address-space helpers, VMA tree, mmap/munmap/mprotect/mremap/brk/msync/mincore/madvise/mseal, COW, rmap, page-fault fill/write paths, and torture tests exist. |
| Files | Open/read/write/pread/pwrite/vector IO, stat/statx, chmod/chown, xattr, link/symlink/rename/unlink/mkdir/mknod, fsync/syncfs, fd table, poll/select/epoll, eventfd, signalfd, timerfd, inotify/fanotify, file handles, and modern mount API handlers exist. |
| Filesystems | ext4, tmpfs, devfs/devpts, procfs, sysfs, kernfs, tracefs, and FUSE-shaped code exist. ext4 has image tests for allocation, directories, extents, journaling, rename, xattr, e2fsck cleanliness, and rootfs walking. |
| IPC | Futex/futex2 wait/wake/requeue/waitv, pipes/FIFOs, eventfd, signal queues, SysV shm/msg/sem, POSIX mqueue, wait queues, and AF_UNIX code are present. |
| Network | AF_INET/AF_INET6/AF_UNIX/AF_PACKET/vsock socket paths, TCP/UDP, IPv4/IPv6 routing, reassembly, multicast, ICMP/ICMPv6, ARP/NDP, net namespaces, rtnetlink, sock_diag, and netfilter/nft expression code exist. |
| Devices | Reworked driver core, PCI, virtio common, virtio-blk/net/gpu/input/rng/vsock/snd, NVMe, AHCI, serial UARTs, PS/2 keyboard, DRM, fbdev/fbcon, VT, sound/OSS/PCM code exist. |
| Pseudo system surfaces | `/proc` files for status/stat/meminfo/vmstat/cpuinfo/mounts/net/diskstats/partitions/sysctl-like paths; `/sys` class/device surfaces for block/net/tty/input/drm/modules/bus; `/dev` node registry and console/tty nodes. |
| Security | Capabilities/creds paths, seccomp, cBPF interpreter/verifier pieces, BPF syscall path, Landlock syscall path, LSM self-attr syscall paths, and cgroup v2 controllers are present. |
| Observability | klog ring/console, tracefs, tracepoints, perf-event shaped fd, proc counters, syscall enter/exit tracepoints, debug feature gates, and smoke tests exist. |
| glibc/userspace | The glibc crate covers libc areas including ctype/string/malloc/stdio/stdlib/POSIX/signal/time/pthread/dlfcn/net/NSS/math/locale/crypt/termios/setjmp/ucontext/regex/aio; ldso has relocation, search, symbol, version, TLS, loader, and freestanding syscall pieces. |

## Not Done / Incomplete

| Priority | Gap | Code evidence |
|---|---|---|
| P0 | `NR_LISTNS` syscall slot is declared but not actively referenced by kernel syscall routing. | `crates/kernel/syscall/src/nrs.rs` declares 470; scan of `crates/kernel/syscalls`, `sched`, `fs`, `security`, `ipc` found no `NR_LISTNS` use. |
| P0 | Old low-level `crates/kernel/syscall/src/dispatch.rs` still contains many v1 fallback handlers and is still the fallback for unhandled active routes. This is a risk for silent success/ENOSYS/weak semantics. | `oxide_syscall_dispatch` falls back to `syscall::dispatch`; that table contains minimal `write`, `mmap`, `pipe2`, `getrandom`, fd, signal, and identity stubs. |
| P0 | Full Linux syscall semantics are not guaranteed by routing coverage. Many handlers are real, but code still contains accepted no-ops, EPERM/EOPNOTSUPP approximations, v1 simplifications, and compatibility fallbacks. | Examples: `memfd_create` has an `Enosys` branch for unsupported flags; `kill(pid == -1)` comments as not implemented; `prlimit64` says only `RLIMIT_NOFILE` is consulted; `timerfd`, `signalfd`, `flock`, `userfaultfd`, `io_uring`, and net paths contain v1 limits. |
| P0 | Kernel completeness needs a syscall semantic audit, not just a dispatch audit. | Active handlers span hundreds of files; there is no generated report in repo proving Linux-compatible behavior per slot. |
| P0 | Boot/runtime verification was not run for this report. | This was a code scan and doc edit only. |
| P1 | SMP and CPU hotplug are incomplete. | CPU topology exists; comments and HAL paths still show single-CPU/v1 assumptions and future AP bring-up work. |
| P1 | NUMA, memory policy, migration, swap, and overcommit are incomplete. | NUMA syscalls route to UMA/single-node behavior; swap syscalls are not visible as implemented routes; VMM comments still call out missing file-backed rmap/shared-mmap follow-up. |
| P1 | Full async block IO/writeback is incomplete. | Block layer comments show synchronous page-cache paths and out-of-scope async submit/writeback daemon/radix/PG_LOCKED waiters. |
| P1 | Filesystem portfolio is small versus Linux. | ext4/tmpfs/pseudo filesystems exist; no code for XFS, Btrfs, NFS, overlayfs, squashfs, ISO9660, FAT/exFAT, 9p, or full FUSE daemon integration beyond shaped code. |
| P1 | Full ext4/Linux VFS feature parity remains open. | ext4 has RW/journal/xattr tests, but code still returns `Eopnotsupp`/unsupported for some depth/features and VFS defaults reject optional inode ops. |
| P1 | Driver coverage is QEMU/virtio/PC focused, not Linux hardware complete. | Present drivers are PCI, virtio family, NVMe, AHCI, UARTs, PS/2, DRM/fbdev/fbcon, sound; no native USB host controller/storage/HID, Wi-Fi, Bluetooth, GPU vendor drivers, ACPI battery/thermal, HID stack, SCSI/SATA breadth, or broad NIC set. |
| P1 | Linux KPI is partial. | `modules` has many `linux_*` files, but module loader comments list missing signature verification, W^X module memory, executable init/exit callbacks, async drain, CRC/symtab section walking; `linux_irq` returns `ENOSYS` for some request-threaded IRQ cases. |
| P1 | Networking is broad but not Linux-complete. | Code has TCP/UDP/IPv4/IPv6/netlink/netfilter, but comments and module shapes show raw socket, multicast/query, advanced counters, NAT/conntrack, policy routing, forwarding, and nftables depth still need completion/conformance. |
| P1 | Full systemd/udev compatibility remains work. | `svc` is a service-unit parser/supervisor subset; sysfs/devfs/netlink/uevent code exists, but systemd-level behavior requires more than parsed units and device nodes. |
| P1 | Security model is not complete Linux LSM/BPF. | Seccomp/cBPF/Landlock/BPF paths exist; BPF/perf/userfaultfd/io_uring comments show limited semantics; no full eBPF helper/JIT/map/program ecosystem or full LSM stacking. |
| P2 | Observability/perf is partial. | `obs::init()` returns `NotImplemented`; `perf_event_open` creates a shaped fd but comments indicate sample/PMU depth is limited. |
| P2 | glibc exists but is not full glibc/distro parity yet. | libc modules are broad; code comments still mention TLS/rtld/pthread/folded-lib/shim stages, resolver depth, and unsupported relocation/compressor cases. |
| P2 | Package/service userspace is minimal. | RPM reader lacks signature verification; `pkg` supports gzip payloads only; service parser lacks line continuations, drop-ins, templating, socket/timer units, and full systemd semantics. |

## What To Implement Next

1. Close `NR_LISTNS` routing or remove the stale constant if it is intentionally unsupported.
2. Replace the fallback use of `syscall::dispatch` with an explicit active syscall audit path so unhandled syscalls cannot silently hit old v1 stubs.
3. Generate a syscall matrix from code: number, name, route target, return classes, known no-op/EOPNOTSUPP/ENOSYS branches, tests.
4. Promote the highest-impact weak syscall families first: `io_uring`, `userfaultfd`, `timerfd/signalfd`, `prlimit64`, memory policy/NUMA, `kill(-1)`, BPF/perf, and modern mount namespace edges.
5. Finish Linux KPI/module loader essentials: module init/exit execution, W^X allocation, signature/CRC/vermagic enforcement, threaded IRQ, DMA, USB, netdev, and platform-device depth.
6. Deepen storage and filesystems: async block submission, writeback, page-cache locking/waiters, ext4 feature parity, and at least one additional Linux-common filesystem or full FUSE.
7. Deepen networking: raw sockets, conntrack/NAT, nftables expression coverage, IPv6 edge behavior, route/rule parity, socket diagnostics/counters, and packet socket behavior.
8. Close SMP/preemption/RCU/lockdep realities: AP bring-up, IPIs, TLB shootdown across CPUs, per-CPU scheduler load balancing, hotplug decisions.
9. Make udev/systemd the integration target: sysfs attributes, uevent payloads, netlink groups, cgroup delegation, pid/user/session semantics, devtmpfs, and unit/supervisor behavior.
10. Build a Linux-completeness CI report from code, then make this file a generated or semi-generated status artifact.
