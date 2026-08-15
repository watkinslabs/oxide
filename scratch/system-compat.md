# Stock Linux System Compatibility

Code-only audit: `c7c5465e0`. This covers the common in-kernel services a normal Linux distro uses. It intentionally excludes individual hardware-driver coverage, alternate CPU architectures, obsolete protocols, and distro userspace such as systemd, package managers, and desktops.

Device rows cover the kernel framework needed to use a driver. They are not a demand to reproduce Linux's entire driver catalog.

| Status | Meaning |
|---|---|
| `HAVE` | A production owner exists in the current source tree. |
| `PARTIAL` | Production code exists, but the code itself shows a bounded implementation or only selected backends. |
| `NOT FOUND` | No dedicated production owner was found in the current source tree. |

## Core runtime

| Status | System | Current code | Code evidence | Branch |
|---|---|---|---|---|
| `HAVE` | x86_64 and AArch64 boot, traps, MMU, IRQ, timers | Separate boot, HAL, and kernel-image implementations exist for both targets. | `crates/arch/{boot-x86_64,hal-x86_64,kernel-bin-x86_64,boot-aarch64,hal-aarch64,kernel-bin-aarch64}` | — |
| `PARTIAL` | SMP, CPU scheduling, cross-CPU calls, RCU, workqueues | Per-CPU scheduler, cross-CPU, RCU, and workqueue code exists; RCU’s code documents an effectively-UP runtime model. | `crates/kernel/{cpu,sched,arch-irq}`; `crates/shared/sync/{rcu,percpu}` | — |
| `HAVE` | Processes, threads, exec, signals, sessions, process groups, pidfds | Dedicated scheduler, exec, and pidfd production owners exist. | `crates/kernel/{sched,exec,pidfd}` | — |
| `HAVE` | Timekeeping, POSIX timers, timerfds, random numbers | Dedicated timekeeper/timer/CRNG owners and timerfd code exist. | `crates/kernel/{timekeeper,timer,crng,fs/timerfd}` | — |
| `PARTIAL` | Memory allocation, virtual memory, page faults, COW, reclamation | PMM/VMM/reclaim code exists; the PMM code currently describes a one-zone allocator. | `crates/kernel/{mm-pmm,mm-vmm}` | — |
| `PARTIAL` | Swap, zram, huge pages, memory cgroups | Swap, zram, hugetlb, reclaim, and memcg code exist, but are distinct bounded implementations. | `crates/kernel/mm-pmm/{swap,hugetlb,memcg,reclaim}`; `crates/drivers/drv-zram` | — |
| `PARTIAL` | Futexes, robust lists, priority inheritance, futex2 | Classic futex and futex2 owners exist; futex2 accepts only 32-bit non-NUMA/non-MPOL words. | `crates/kernel/ipc/{live/futex,futex2_flags,futex_pi_rules,robust_decode}` | — |
| `HAVE` | Pipes, eventfd, signalfd, timerfd, epoll, splice | Production FS/VFS owners exist. | `crates/kernel/fs/{pipe,signalfd,timerfd,epoll,splice}`; `crates/kernel/vfs` | — |
| `PARTIAL` | SysV IPC, POSIX message queues, keyrings, userfaultfd, io_uring | Each has production code, but the source is split across selective work functions/backends rather than one broad completed service. | `crates/kernel/{ipc,fs/keyring,fs/userfaultfd,syscalls/io_uring}` | — |

## Files and storage

| Status | System | Current code | Code evidence | Branch |
|---|---|---|---|---|
| `HAVE` | VFS: paths, mounts, dentries, inodes, fd tables, permissions, xattrs, quotas | Full set of core VFS ownership modules is present. | `crates/kernel/vfs/{namei,mount,dentry,inode,fdtable,quota,xattr}` | — |
| `HAVE` | ext4 and journal | ext4 owns allocation, extents, JBD2, inode, xattr, quota, and mount code. | `crates/kernel/ext4/{balloc,extent_rw,jbd2,inode,xattr,quota,mount}` | — |
| `HAVE` | tmpfs, procfs, sysfs, kernfs, devfs, devpts, tracefs, pstore | Each filesystem has a production crate or module. | `crates/kernel/{fs/tmpfs,procfs,sysfs,kernfs,devfs,devpts,tracefs,pstore}` | — |
| `PARTIAL` | FUSE, hugetlbfs, autofs, binfmt_misc, filesystem notifications | Production modules exist, but the source contains only their specific protocol/features, not a broad filesystem family implementation. | `crates/kernel/fs/{fuse,hugetlbfs,autofs,binfmt_misc,inotify}` | — |
| `NOT FOUND` | OverlayFS, FAT/VFAT, 9p/virtiofs | No dedicated filesystem owner is present. | source-tree audit under `crates/kernel` | — |
| `NOT FOUND` | Btrfs, XFS, F2FS, EROFS, squashfs | No dedicated filesystem owner is present. | source-tree audit under `crates/kernel` | — |
| `NOT FOUND` | NFS, SMB/CIFS, SCSI filesystem/export stack | No dedicated network-filesystem or SCSI owner is present. | source-tree audit under `crates/kernel` | — |
| `HAVE` | Block layer, partitions, page cache, elevators, direct I/O | Dedicated block crate contains these owners. | `crates/kernel/block/{partitions,elevator,direct,registry}` | — |
| `HAVE` | Current storage backends | Virtio block, NVMe, AHCI, and zram driver crates exist. | `crates/drivers/{drv-virtio-blk,drv-nvme,drv-ahci,drv-zram}` | — |
| `NOT FOUND` | Device mapper/LVM, MD RAID, loop devices, broad SCSI/USB storage stack | No dedicated production subsystem is present. | source-tree audit under `crates/kernel` and `crates/drivers` | — |

## Network and containment

| Status | System | Current code | Code evidence | Branch |
|---|---|---|---|---|
| `HAVE` | IPv4/IPv6, ARP/NDP, ICMP, TCP, UDP, raw and ping sockets | Dedicated network-stack modules exist. | `crates/kernel/net/{stack,stack_ipv6,arp,neigh,raw4,raw6,ping}` | — |
| `HAVE` | AF_UNIX, AF_PACKET, AF_VSOCK, netlink, rtnetlink, generic netlink | Dedicated socket and netlink modules exist. | `crates/kernel/{net/unix_sock,net/vsock,netlink/{rtnetlink,genetlink},socket}` | — |
| `PARTIAL` | Firewalling, nftables, BPF/XDP, socket filtering | Netfilter state/nft code and BPF code exist; they are separate, selected implementations. | `crates/kernel/{netfilter,security/bpf}` | — |
| `NOT FOUND` | Conntrack/NAT, Wi-Fi/mac80211, Bluetooth, bridge/VLAN/bonding, RDMA | No dedicated production owner is present. | source-tree audit under `crates/kernel` and `crates/drivers` | — |
| `HAVE` | Namespaces and cgroups | Production owners exist for namespace identity, per-network/user/time namespaces, and cgroup trees. | `crates/kernel/{namespace-identity,network-namespace,user-namespace,time-namespace,nscg,cgroup}` | — |
| `PARTIAL` | Container-ready filesystem/network/resource isolation | The namespace and cgroup primitives exist; stock container dependencies such as OverlayFS and full networking are absent. | `crates/kernel/{nscg,cgroup}`; source-tree audit | — |

## Security and observability

| Status | System | Current code | Code evidence | Branch |
|---|---|---|---|---|
| `HAVE` | Credentials, capabilities, seccomp, Landlock, audit, Yama policy | Dedicated security/scheduler owners exist. | `crates/kernel/{security,landlock,audit,sched/{cred,yama,seccomp_filter}}` | — |
| `PARTIAL` | eBPF verifier, maps, links, BTF, BPF LSM | Production BPF owners exist; the source separates verifier/interpreter/map/link paths. | `crates/kernel/security/{bpf,bpf_verify,bpf_interp,bpf_lsm}` | — |
| `HAVE` | Kernel keyring and asymmetric-key plumbing | Key construction, keyctl, lifecycle, payload, and report modules exist. | `crates/kernel/fs/keyring` | — |
| `NOT FOUND` | SELinux, AppArmor, IMA/EVM, TPM/TEE | No dedicated production security subsystem is present. | source-tree audit under `crates/kernel` | — |
| `HAVE` | Kernel logging, tracefs, perf records, persistent logs | Production klog, tracefs, perf, and pstore owners exist. | `crates/shared/klog`; `crates/kernel/{tracefs,fs/perf,pstore}` | — |
| `PARTIAL` | ftrace, kprobes, uprobes, hardware PMU tracing | Trace/perf code exists, but no dedicated full tracing/probe owner is present. | `crates/kernel/{tracefs,fs/perf}`; source-tree audit | — |

## Driver-facing kernel systems

| Status | System | Current code | Code evidence | Branch |
|---|---|---|---|---|
| `HAVE` | Driver registration, PCI/PCIe, virtio, MSI/MSI-X/INTx, IOMMU | Core driver, PCI, virtio, IRQ, and IOMMU owners exist. | `crates/kernel/{pci-boot,pci-irq,pcie-port,iommu,modules}`; `crates/drivers/{drv,pci,virtio}` | — |
| `HAVE` | Firmware discovery: ACPI tables, SMBIOS/DMI, FDT | Firmware and FDT owners exist. | `crates/kernel/firmware`; `crates/shared/fdt` | — |
| `PARTIAL` | USB host and common classes | USB core and xHCI include hub, HID, and storage modules; no conclusion is made about individual device-driver coverage. | `crates/drivers/{usb-core,drv-xhci/{usb,hid,storage}}` | — |
| `HAVE` | Console, TTY, PTY, terminal emulation, serial UARTs | Core TTY/VT/console and 16550/PL011 serial drivers exist. | `crates/kernel/{tty,vt,console,serialtty,vtconsole}`; `crates/drivers/{drv-serial,drv-uart-16550,drv-uart-pl011}` | — |
| `HAVE` | Display/input/audio substrate | DRM, fbdev/fbcon, virtual GPU, input, PS/2/virtio input, sound, and virtio-snd owners exist. | `crates/drivers/{drm,fbdev,fbcon,drv-virtio-gpu,drv-bochs,drv-simplefb,drv-virtio-input,drv-ps2-keyboard,drv-virtio-snd}`; `crates/kernel/{input,sound}` | — |
| `HAVE` | Current Ethernet device support | Virtio-net plus E1000, IGC, RTL8125, and Atlantic driver crates exist. | `crates/drivers/{drv-virtio-net,drv-e1000,drv-igc,drv-rtl8125,drv-atlantic}` | — |
| `PARTIAL` | Reset, reboot, kexec, crash kernel | Dedicated power and kexec owners exist. | `crates/kernel/{power,kexec}` | — |
| `NOT FOUND` | ACPI AML/runtime power management, battery/thermal, CPU frequency/idle, KVM/VFIO | No dedicated production subsystem is present. | source-tree audit under `crates/kernel` and `crates/drivers` | — |
