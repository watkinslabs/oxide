# System Compatibility Inventory

Audited: 2026-08-15. Baseline: `54747985c`. Branch: `D553-system-compat`.

Linux has thousands of Kconfig switches and individual hardware drivers. This is the complete **system-level** inventory: every major kernel subsystem plus the filesystem, network, security, architecture, and driver families represented by the Linux reference taxonomy. It does not claim per-device or per-option parity.

| Status | Meaning |
|---|---|
| `HAVE` | A production owner exists in the current source tree. This is presence, not a claim of full semantic parity. |
| `PARTIAL` | An owner exists, but the project documents incomplete depth, missing interfaces, or active parity defects. |
| `MISSING` | No corresponding production subsystem was found, or the project explicitly says it is not implemented. |
| `NOT TARGETED` | Absent and explicitly excluded by the current modernity charter. |
| `CONFLICT` | Project documents disagree about whether the system is in scope. |

Evidence refers only to the current Oxide tree. `Branch` is the implementation lane, not this audit branch; `—` means no lane is claimed by this inventory.

## Scope conflict

| Status | System | Oxide state | Evidence | Branch |
|---|---|---|---|---|
| `CONFLICT` | Full Linux system surface | `docs/00` says every Linux subsystem is in scope except 32-bit and big-endian support. `docs/03` instead excludes many filesystem, network, architecture, and legacy ABI systems. This inventory reports what exists today; a scope decision is still required for the absent `NOT TARGETED` rows. | `docs/00` §§3,9; `docs/03` §§2,5–7 | — |

## Architecture, boot, core kernel, and memory

| Status | System | Oxide state | Evidence | Branch |
|---|---|---|---|---|
| `HAVE` | x86_64 architecture, boot, traps, MMU, interrupts, timers | Native boot/HAL/kernel-image path exists. | `crates/arch/{boot-x86_64,hal-x86_64,kernel-bin-x86_64}` | — |
| `HAVE` | AArch64 architecture, boot, traps, MMU, interrupts, timers | Native boot/HAL/kernel-image path exists. | `crates/arch/{boot-aarch64,hal-aarch64,kernel-bin-aarch64}` | — |
| `MISSING` | Other Linux architectures: Alpha, ARC, AArch32, C-SKY, Hexagon, LoongArch, m68k, MicroBlaze, MIPS, Nios II, OpenRISC, PA-RISC, PowerPC, RISC-V, s390, SH, SPARC, UML, Xtensa | No architecture port or HAL backend beyond x86_64 and AArch64. | `crates/arch/` | — |
| `NOT TARGETED` | 32-bit kernel and user ABI, x32, compat syscall layer | Explicitly excluded. | `docs/00` §9; `docs/03` §§2,7 | — |
| `NOT TARGETED` | Big-endian support | Explicitly excluded. | `docs/00` §9 | — |
| `PARTIAL` | SMP, inter-processor calls, TLB shootdown, load balancing | Cross-CPU mechanisms exist, but README still records SMP and CPU hotplug as incomplete. | `crates/kernel/{cpu,arch-irq,sched,mm-pmm}`; `README.md` | — |
| `MISSING` | CPU hotplug, cpufreq, cpuidle, energy/performance policy | No dedicated subsystem; project records CPU hotplug as incomplete. | `README.md`; source inventory | — |
| `MISSING` | RAS, machine-check recovery, EDAC, livepatch/liveupdate | No production owner found. | source inventory | — |
| `PARTIAL` | Scheduler, preemption, real-time/deadline policy, task accounting | Scheduler, task, signal, rlimit, priority, deadline, and timer owners exist; SMP depth remains incomplete. | `crates/kernel/sched` | — |
| `HAVE` | Process lifecycle, clone/fork, exec, wait, signals, sessions, process groups, pidfds | Production owners and syscall routes exist. | `crates/kernel/{sched,exec,pidfd,syscalls}` | — |
| `PARTIAL` | Linux syscall ABI | Hundreds of routes exist, but one `listns` constant lacks an active route and the older fallback dispatch table still contains stubs. | `README.md`; `scratch/syscall-compliance-matrix.md` | — |
| `PARTIAL` | Futexes, restartable sequences, membarrier, robust synchronization | Classic futex, rseq, membarrier, robust lists, and futex2 wait/wake/waitv/requeue owners exist; futex2 currently serves only 32-bit non-NUMA/non-MPOL words. | `crates/kernel/{ipc,sched,syscall,syscalls}` | — |
| `PARTIAL` | Kernel locking, wait queues, work/deferred execution, RCU | Spin/RW locks, wait queues, softirq, timers, per-CPU workqueues, and RCU exist; their runtime model is still effectively-UP while SMP work remains incomplete. | `crates/shared/sync/{rcu,lib}`; `crates/kernel/{sched,softirq,timer}`; `README.md` | — |
| `HAVE` | Physical memory, page metadata, buddy allocation, slab/kalloc | Production PMM, slab, allocator, reclaim, and page metadata owners exist. | `crates/kernel/mm-pmm`; `crates/shared/{slab,kalloc}` | — |
| `PARTIAL` | Virtual memory, user address spaces, mmap, faults, COW, mprotect, mremap | Production owners exist; active ledger contains mremap locking/relocation defects and parity gaps. | `crates/kernel/mm-vmm`; `scratch/known_issues.md` | — |
| `PARTIAL` | Huge pages and hugetlbfs | Pool and hugetlbfs exist; accounting, cgroup control, boot setup, observability, and shared-memory integration have open gaps. | `crates/kernel/{mm-pmm,fs}`; `scratch/known_issues.md` | — |
| `PARTIAL` | Swap, zram, reclamation, working set, overcommit | zram and swap/reclaim code exist; README records swap and full overcommit behavior as incomplete. | `crates/drivers/drv-zram`; `crates/kernel/mm-pmm`; `README.md` | — |
| `PARTIAL` | NUMA topology and memory policy | Memory-policy code exists, but NUMA policy is explicitly incomplete and there is no multi-node architecture support. | `crates/kernel/mm-vmm/mempolicy`; `README.md` | — |
| `MISSING` | Memory hotplug, CXL memory, DAX/pmem mappings, DAMON | No complete production subsystem found; raw persistent-memory mappings are an active gap. | source inventory; `scratch/known_issues.md` | — |
| `PARTIAL` | Memory debugging and sanitizers | efence and debug allocation diagnostics exist; Linux KASAN/KMSAN/KFENCE-class coverage is absent. | `crates/kernel/efence`; `crates/shared/kalloc` | — |

## IPC, namespaces, cgroups, and user/kernel interfaces

| Status | System | Oxide state | Evidence | Branch |
|---|---|---|---|---|
| `HAVE` | File descriptors, fd tables, pipes, eventfd, signalfd, timerfd, epoll, splice | Production VFS/FS owners exist. | `crates/kernel/{vfs,fs}` | — |
| `PARTIAL` | POSIX message queues and SysV IPC (message queues, semaphores, shared memory) | Owners exist, but full Linux semantic coverage is not established. | `crates/kernel/ipc` | — |
| `PARTIAL` | Keyrings, request-key, watch queues | Production keyring/watch-queue code exists; active gaps remain. | `crates/kernel/fs/{keyring,watch_queue}` | — |
| `PARTIAL` | AIO, io_uring, userfaultfd | Full subsystem trees exist; project docs and active issues still identify incomplete behavior and coverage. | `crates/kernel/{fs,syscalls}` | — |
| `PARTIAL` | ptrace, core dumps, accounting, audit | Owners exist, but ptrace depth, coredump generation, and audit parity are incomplete. | `crates/kernel/{sched,fs,audit,syscalls}`; `README.md` | — |
| `PARTIAL` | PID, mount, network, UTS, IPC, user, cgroup, and time namespaces | Namespace identities and per-kind owners exist; container-level parity remains incomplete. | `crates/kernel/{namespace-identity,network-namespace,user-namespace,time-namespace,nscg}` | — |
| `PARTIAL` | cgroup v2 and controllers | A cgroup v2 tree exists, but controller breadth—including hugetlb—and accounting depth are incomplete. | `crates/kernel/cgroup`; `scratch/known_issues.md` | — |
| `NOT TARGETED` | cgroup v1 hierarchy/controllers | The modernity charter selects only unified cgroup v2. | `docs/03` §2 | — |
| `PARTIAL` | procfs, sysfs, kernfs, devtmpfs/devfs, devpts, tracefs | All have production owners; their published Linux surfaces are intentionally incomplete in places. | `crates/kernel/{procfs,sysfs,kernfs,devfs,devpts,tracefs}` | — |
| `PARTIAL` | binfmt_misc, ELF loading, vDSO, dynamic-loader ABI | ELF and binfmt_misc owners exist, but dynamic loader and full glibc ABI compatibility remain incomplete. | `crates/kernel/{exec,fs,syscall,syscalls}`; `README.md` | — |
| `MISSING` | Linux kernel configuration/Kconfig module system | Cargo build configuration is not a Linux Kconfig/Kbuild compatibility subsystem. | build/source inventory | — |
| `PARTIAL` | Loadable modules and Linux driver KPI | Loader, relocation, symbols, and a partial KPI exist; enforcement, W^X, init/exit, IRQ depth, and API breadth remain incomplete. | `crates/kernel/modules`; `README.md` | — |

## Filesystems and storage stack

| Status | System | Oxide state | Evidence | Branch |
|---|---|---|---|---|
| `HAVE` | VFS, dentries, inodes, mounts, name lookup, file locking, quotas, writeback framework | Production VFS owner exists. | `crates/kernel/vfs` | — |
| `PARTIAL` | ext4 and JBD2 | RW ext4, extents, xattrs, quota, journal, and mount-option owners exist; many mount/writeback behaviors remain open. | `crates/kernel/ext4`; `scratch/known_issues.md` | — |
| `PARTIAL` | tmpfs/ramfs and shmem-style anonymous files | tmpfs owner exists, including casefold and mount options; parity gaps remain. | `crates/kernel/fs/tmpfs` | — |
| `HAVE` | proc, sysfs, kernfs, devpts, devtmpfs/devfs, tracefs, pstore | Pseudo-filesystem owners exist. | `crates/kernel/{procfs,sysfs,kernfs,devpts,devfs,tracefs,pstore}` | — |
| `PARTIAL` | FUSE | Protocol/connection code exists; full FUSE integration is explicitly incomplete. | `crates/kernel/fs/fuse`; `README.md` | — |
| `PARTIAL` | hugetlbfs, autofs, binfmt_misc, filesystem notifications, xattrs | Dedicated owners exist, but the full Linux surface is not established. | `crates/kernel/fs/{hugetlbfs,autofs,binfmt_misc,inotify,xattr}` | — |
| `MISSING` | FAT32, exFAT, VFAT, MSDOS | FAT32 is retained as a desired ESP filesystem but no filesystem implementation is present; exFAT is excluded. | `docs/03` §5; source inventory | — |
| `MISSING` | OverlayFS | A container-relevant target in the charter, with no implementation owner. | `docs/03` §5; source inventory | — |
| `MISSING` | 9p and virtiofs | Both are needed for host sharing in the charter; no implementation owner exists. | `docs/03` §5; source inventory | — |
| `MISSING` | Btrfs, XFS, F2FS, EROFS, bcachefs, zonefs | No local filesystem implementation owner. | source inventory | — |
| `MISSING` | Squashfs, cramfs, romfs, ISO9660, UDF | Read-only image/optical filesystem families are absent. | source inventory | — |
| `MISSING` | NFS, SMB/CIFS, CephFS, AFS, 9p network filesystems, OrangeFS, Coda, Vbox shared folders | No network/distributed filesystem client owner. | source inventory | — |
| `MISSING` | NFS server, lockd, exportfs, pNFS | No server/export/lock-manager subsystem. | source inventory | — |
| `MISSING` | GFS2, OCFS2, DLM | No clustered filesystem or distributed lock manager. | source inventory | — |
| `MISSING` | UBIFS, JFFS2, MTD-backed filesystems | No flash/MTD stack. | source inventory | — |
| `MISSING` | NTFS/NTFS3, HPFS, JFS, ReiserFS, NILFS2, UFS, Minix, QNX, BFS/BEFS, EFS, OMFS, ADFS, AFFS, HFS/HFS+, legacy platform filesystems | No owners; many are legacy rather than current project targets. | source inventory | — |
| `MISSING` | fscrypt, eCryptfs, fs-verity, fs-cache/cachefiles, fs-dax, fs-resctrl | No complete filesystem encryption, verification, caching, persistent-memory, or resource-control owner. | source inventory | — |
| `MISSING` | configfs and debugfs as mounted filesystems | Partial Linux KPI helpers exist, but no production mounted configfs/debugfs filesystem is established. | `crates/kernel/modules/linux_configfs`; source inventory | — |
| `PARTIAL` | Block layer, partitions, page cache, elevators, direct I/O | Production block/page-cache owners exist; async block I/O, writeback, and locking depth remain incomplete. | `crates/kernel/block`; `README.md` | — |
| `HAVE` | Virtio block, NVMe, AHCI/SATA, zram | Dedicated driver crates exist. | `crates/drivers/{drv-virtio-blk,drv-nvme,drv-ahci,drv-zram}` | — |
| `MISSING` | SCSI, USB mass storage, UFS, MMC/SD, floppy, optical/CD-ROM, tape, target mode | No production storage transport/driver subsystem. | source inventory | — |
| `MISSING` | Device mapper, LVM, dm-crypt, dm-integrity, dm-verity, multipath | No device-mapper subsystem. | source inventory | — |
| `MISSING` | MD RAID, bcache, bcached, loop devices, network block devices | No RAID/cache/loop/network block owner. | source inventory | — |
| `MISSING` | NVDIMM, pmem, CXL, memory-device block support | No production persistent-memory/CXL device subsystem. | source inventory | — |

## Networking

| Status | System | Oxide state | Evidence | Branch |
|---|---|---|---|---|
| `HAVE` | Ethernet device model, loopback, IPv4, IPv6, ARP, NDP, ICMP/ICMPv6 | Production networking owners exist. | `crates/kernel/net` | — |
| `PARTIAL` | TCP, UDP, raw IP, ping sockets, multicast, routing, neighbor tables | Production stacks exist; README identifies raw-socket, IPv6-edge, route/rule, and diagnostics parity gaps. | `crates/kernel/net`; `README.md` | — |
| `HAVE` | AF_UNIX, AF_PACKET, AF_VSOCK, AF_NETLINK, rtnetlink, generic netlink, sock_diag | Dedicated socket/netlink owners exist. | `crates/kernel/{net,netlink,socket}` | — |
| `PARTIAL` | Socket options, ancillary data, zero-copy, timestamping, packet rings | Large owners and conformance work exist; compatibility remains actively audited. | `crates/kernel/{net,syscalls}`; `scratch/known_issues.md` | — |
| `PARTIAL` | Netfilter/nftables | State and nft expression owners exist; full filtering, conntrack, NAT, and nftables depth are incomplete. | `crates/kernel/netfilter`; `README.md` | — |
| `PARTIAL` | BPF sockets, cBPF/eBPF, XDP, tc, traffic control, qdisc | BPF and network hooks exist, but verifier/JIT/XDP/tc depth is incomplete. | `crates/kernel/security/bpf`; `docs/03`; `README.md` | — |
| `MISSING` | Conntrack, NAT, flow offload, IPVS | Explicitly called out as incomplete or no owner found. | `README.md`; source inventory | — |
| `MISSING` | MPTCP, SCTP, DCCP, RDS, TIPC, SMC, KCM | No complete transport/protocol implementation. | `docs/03` §6; source inventory | — |
| `NOT TARGETED` | IPX, X.25, DECnet, AppleTalk, NetROM, AX.25, ROSE, Econet, LLC, Bridge AF, Phonet, CAIF, ALG AF, NFC AF, QIPCRTR | Explicitly dropped address-family/protocol surface. | `docs/03` §6 | — |
| `MISSING` | Bridge, VLAN/802.1Q, bonding/team, Open vSwitch, DSA/switchdev, HSR | No L2 switching/virtual-device subsystem. | source inventory | — |
| `MISSING` | Wi-Fi/mac80211/cfg80211, Bluetooth, NFC, 6LoWPAN, IEEE 802.15.4, CAN, ATM | No wireless/personal-area/industrial network stack. | `README.md`; source inventory | — |
| `MISSING` | RDMA/InfiniBand, iWARP/RoCE, devlink | No RDMA or fabric-management subsystem. | source inventory | — |
| `MISSING` | MPLS, L2TP, PPP, RXRPC, SUNRPC, MCTP, QRTR, XFRM/IPsec, TLS offload | No production owner. | source inventory | — |
| `MISSING` | Netlabel, network policy labeling, hardware offload framework, PTP/PHC | No complete label/offload/precision-time subsystem. | source inventory | — |
| `PARTIAL` | Ethernet NIC drivers | Virtio-net plus E1000, IGC, RTL8125, and Atlantic drivers exist; broad Linux NIC coverage is absent. | `crates/drivers/{drv-virtio-net,drv-e1000,drv-igc,drv-rtl8125,drv-atlantic}` | — |

## Security, crypto, and observability

| Status | System | Oxide state | Evidence | Branch |
|---|---|---|---|---|
| `HAVE` | Credentials, UIDs/GIDs, capabilities, securebits, Yama-style ptrace policy | Production security/scheduler owners exist. | `crates/kernel/{security,sched}` | — |
| `PARTIAL` | seccomp, including user notification | Production seccomp and notification owners exist; overall security depth remains incomplete. | `crates/kernel/security/seccomp`; `README.md` | — |
| `PARTIAL` | Landlock | Dedicated Landlock owner exists; it is not a substitute for full LSM coverage. | `crates/kernel/landlock` | — |
| `PARTIAL` | eBPF, verifier, maps, links, BTF, BPF LSM | Subsystem code exists; verifier/JIT/hook parity remains incomplete. | `crates/kernel/security/bpf` | — |
| `HAVE` | Audit and kernel/user event records | Dedicated audit owner exists. | `crates/kernel/audit` | — |
| `PARTIAL` | Kernel keyrings and asymmetric-key support | Keyring owner exists; certificate/algorithm support is narrow. | `crates/kernel/fs/keyring`; `scratch/known_issues.md` | — |
| `PARTIAL` | Cryptographic primitives and kernel crypto API | Shared cryptography and partial Linux KPI exist; broad Crypto API, hardware acceleration, and algorithm coverage are not complete. | `crates/shared/crypt`; `crates/kernel/modules/linux_crypto` | — |
| `MISSING` | SELinux, AppArmor, Smack, TOMOYO, IPE, LoadPin, SafeSetID, Lockdown | No full LSM implementations; project lists SELinux/AppArmor/IMA as later work. | `README.md`; `docs/03` §9; source inventory | — |
| `MISSING` | IMA/EVM and measured/verified boot integrity stack | No production integrity subsystem. | source inventory | — |
| `MISSING` | TPM, TEE, key retention hardware, trusted execution interfaces | No production device/security subsystem. | source inventory | — |
| `PARTIAL` | Kernel log, `/dev/kmsg`, pstore, tracefs | Production owners exist; pstore zone/trace/pmsg and trace depth have open gaps. | `crates/shared/klog`; `crates/kernel/{pstore,tracefs}`; `scratch/known_issues.md` | — |
| `PARTIAL` | perf events, software counters, PMU/BPF integration | Perf/BPF owners exist, but full perf/PMU tooling is incomplete. | `crates/kernel/fs/perf`; `README.md` | — |
| `MISSING` | ftrace function/graph tracing, kprobes, uprobes, tracepoint ecosystem, hwtracing | No complete Linux tracing/probe subsystem. | `README.md`; source inventory | — |
| `MISSING` | KCSAN, lockdep, gcov, full kernel unwinder/crash analysis tooling | No matching production subsystem. | source inventory | — |

## Firmware, virtualization, power, and driver infrastructure

| Status | System | Oxide state | Evidence | Branch |
|---|---|---|---|---|
| `HAVE` | PCI/PCIe enumeration, MSI/MSI-X/INTx, virtio transport | Production core and boot owners exist. | `crates/kernel/{pci-boot,pci-irq,pcie-port}`; `crates/drivers/{pci,virtio}` | — |
| `PARTIAL` | ACPI, SMBIOS/DMI, FDT/device-tree firmware description | Static-table and identity support exists; AML runtime and overlays remain absent. | `crates/kernel/firmware`; `crates/shared/fdt`; `README.md` | — |
| `PARTIAL` | IOMMU (Intel VT-d and AMD-Vi) | Dedicated IOMMU owner exists; full device/DMA integration breadth is unproven. | `crates/kernel/iommu` | — |
| `PARTIAL` | Reset, reboot, halt, kexec, crash kernel, pstore | Production power/kexec/pstore owners exist; suspend/hibernate/runtime-PM depth is absent. | `crates/kernel/{power,kexec,pstore}` | — |
| `MISSING` | ACPI AML interpreter, ACPI runtime drivers, thermal, battery, power-supply policy | Explicitly incomplete/no owner. | `README.md`; source inventory | — |
| `MISSING` | KVM, Xen, Hyper-V, vhost, VFIO, VDPA, remoteproc/RPMsg, paravirtual device frameworks | No hypervisor/device-assignment subsystem; KVM is a planned phase. | `docs/00` §3; source inventory | — |
| `PARTIAL` | Linux driver model, DMA API, IRQ API, device/PCI/platform/input/netdev KPI | Partial KPI surface and driver registry exist. | `crates/kernel/modules`; `crates/drivers/drv` | — |
| `HAVE` | UART/serial console, TTY, PTY, virtual terminals, framebuffer console | Dedicated UART, tty, VT, console, fbcon owners exist. | `crates/kernel/{tty,vt,console,serialtty,vtconsole}`; `crates/drivers/{drv-serial,drv-uart-16550,drv-uart-pl011,fbcon,vt}` | — |
| `PARTIAL` | DRM/KMS, framebuffer, display, virtual GPU | DRM/fbdev/fbcon plus Bochs, simplefb, and virtio-GPU drivers exist; real vendor GPU stack is absent. | `crates/drivers/{drm,fbdev,fbcon,drv-bochs,drv-simplefb,drv-virtio-gpu}`; `README.md` | — |
| `PARTIAL` | Sound/ALSA-like PCM and OSS, virtio-snd | Sound/OSS/PCM and virtio-snd owners exist; broad Linux audio is absent. | `crates/kernel/sound`; `crates/drivers/drv-virtio-snd` | — |
| `PARTIAL` | Input and evdev-style delivery | Input core, virtio-input, and PS/2 keyboard exist; HID, touch, mouse, game controllers, and broad device support are absent. | `crates/kernel/input`; `crates/drivers/{drv-virtio-input,drv-ps2-keyboard}` | — |
| `PARTIAL` | USB | usb-core and xHCI driver exist; broad host, hub, HID, storage, gadget, and class drivers are incomplete. | `crates/drivers/{usb-core,drv-xhci}`; `README.md` | — |
| `MISSING` | SCSI, UFS, MMC/SD, MTD/NAND/NOR, FireWire, Thunderbolt, ATA/PATA legacy, optical/tape transports | No production driver stack beyond AHCI/NVMe/virtio block. | source inventory | — |
| `MISSING` | GPU vendor drivers, compute accelerators, media/V4L2/camera, TV/radio | No production vendor GPU, accelerator, or media subsystem. | `README.md`; source inventory | — |
| `MISSING` | HID, Bluetooth, Wi-Fi, RFKill, NFC, IEEE 802.15.4, CAN, automotive/network appliance drivers | No corresponding device-stack owner. | `README.md`; source inventory | — |
| `MISSING` | GPIO, pinctrl, I2C, I3C, SPI, UART multiplexers, regulators, clocks, resets, power domains, interconnect, mailbox | No board/peripheral control framework. | source inventory | — |
| `MISSING` | RTC, watchdog, hwmon, thermal, LEDs, PWM, counters, PTP/PPS, DPLL, NVMEM, EDAC, RAS | No hardware-management subsystem. | source inventory | — |
| `MISSING` | CXL, NVDIMM, DAX, DMA engines, dma-buf, memory-tiering devices, devfreq | No production subsystem. | source inventory | — |
| `MISSING` | FPGA, IIO, GNSS, GPIB, comedi, industrial fieldbus, MFD, W1, most, accessory/display drivers | No production subsystem. | source inventory | — |
| `MISSING` | Legacy/platform-bus families: AMBA, BCMA, EISA, PCMCIA, RapidIO, SBUS, NuBus, Zorro, Macintosh, PS3, s390/SH/PA-RISC platform drivers | No architecture/platform support for these families. | source inventory | — |

## Linux distribution and desktop-facing integration

| Status | System | Oxide state | Evidence | Branch |
|---|---|---|---|---|
| `PARTIAL` | Fedora/glibc binary ABI, ELF dynamic loading, NSS, PAM, locale | Oxide targets Fedora glibc binaries, but README identifies glibc/userspace/NSS/PAM compatibility as incomplete. | `README.md`; `docs/29a-userspace-platform.md` | — |
| `PARTIAL` | systemd, udev, login/session management | The image can reach modern userspace milestones, but udev/systemd compatibility and seat/device handoff remain incomplete. | `README.md`; `docs/60-udev-kernel-contract.md`; `state.md` | — |
| `PARTIAL` | RPM/package management | RPM/package readers and image composition exist; a complete package-management runtime is incomplete. | `README.md`; `docs/00` §3 | — |
| `PARTIAL` | Wayland, display manager, GNOME desktop | Graphics/VT/session prerequisites are under active work; the full greeter/session desktop layer is not complete. | `README.md`; `state.md` | — |
| `MISSING` | Linux ABI support for 32-bit applications and legacy libc stacks | Explicitly outside the target. | `docs/00` §9; `docs/03` §§1–2 | — |
