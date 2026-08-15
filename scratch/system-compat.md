# Stock Linux System Compatibility

Code-only audit: `c7c5465e0`. This covers the common in-kernel services a normal Linux distro uses. It intentionally excludes individual hardware-driver coverage, alternate CPU architectures, obsolete protocols, and distro userspace such as systemd, package managers, and desktops.

Device rows cover the kernel framework needed to use a driver. They are not a demand to reproduce Linux's entire driver catalog.

## What we have

| Status | System | Code evidence | Branch |
|---|---|---|---|
| `HAVE` | x86_64 and AArch64 boot, traps, MMU, IRQ, and timers | `crates/arch/{boot-x86_64,hal-x86_64,kernel-bin-x86_64,boot-aarch64,hal-aarch64,kernel-bin-aarch64}` | — |
| `HAVE` | Processes, threads, exec, signals, sessions, process groups, and pidfds | `crates/kernel/{sched,exec,pidfd}` | — |
| `HAVE` | Timekeeping, POSIX timers, timerfds, and random numbers | `crates/kernel/{timekeeper,timer,crng,fs/timerfd}` | — |
| `HAVE` | Pipes, eventfd, signalfd, timerfd, epoll, and splice | `crates/kernel/fs/{pipe,signalfd,timerfd,epoll,splice}`; `crates/kernel/vfs` | — |
| `HAVE` | VFS: paths, mounts, dentries, inodes, fd tables, permissions, xattrs, and quotas | `crates/kernel/vfs/{namei,mount,dentry,inode,fdtable,quota,xattr}` | — |
| `HAVE` | ext4 and JBD2 journal | `crates/kernel/ext4/{balloc,extent_rw,jbd2,inode,xattr,quota,mount}` | — |
| `HAVE` | tmpfs, procfs, sysfs, kernfs, devfs, devpts, tracefs, and pstore | `crates/kernel/{fs/tmpfs,procfs,sysfs,kernfs,devfs,devpts,tracefs,pstore}` | — |
| `HAVE` | Block layer, partitions, page cache, elevators, and direct I/O | `crates/kernel/block/{partitions,elevator,direct,registry}` | — |
| `HAVE` | Current storage backends: virtio-blk, NVMe, AHCI, and zram | `crates/drivers/{drv-virtio-blk,drv-nvme,drv-ahci,drv-zram}` | — |
| `HAVE` | IPv4/IPv6, ARP/NDP, ICMP, TCP, UDP, raw, and ping sockets | `crates/kernel/net/{stack,stack_ipv6,arp,neigh,raw4,raw6,ping}` | — |
| `HAVE` | AF_UNIX, AF_PACKET, AF_VSOCK, netlink, rtnetlink, and generic netlink | `crates/kernel/{net/unix_sock,net/vsock,netlink/{rtnetlink,genetlink},socket}` | — |
| `HAVE` | Namespace and cgroup primitives | `crates/kernel/{namespace-identity,network-namespace,user-namespace,time-namespace,nscg,cgroup}` | — |
| `HAVE` | Credentials, capabilities, seccomp, Landlock, audit, and Yama policy | `crates/kernel/{security,landlock,audit,sched/{cred,yama,seccomp_filter}}` | — |
| `HAVE` | Kernel keyring, logging, tracefs, perf records, and persistent logs | `crates/kernel/fs/keyring`; `crates/shared/klog`; `crates/kernel/{tracefs,fs/perf,pstore}` | — |
| `HAVE` | Driver registration, PCI/PCIe, virtio, MSI/MSI-X/INTx, and IOMMU | `crates/kernel/{pci-boot,pci-irq,pcie-port,iommu,modules}`; `crates/drivers/{drv,pci,virtio}` | — |
| `HAVE` | Firmware discovery: ACPI tables, SMBIOS/DMI, and FDT | `crates/kernel/firmware`; `crates/shared/fdt` | — |
| `HAVE` | Console, TTY, PTY, terminal emulation, and 16550/PL011 serial UARTs | `crates/kernel/{tty,vt,console,serialtty,vtconsole}`; `crates/drivers/{drv-serial,drv-uart-16550,drv-uart-pl011}` | — |
| `HAVE` | Display/input/audio substrate, including virtio GPU/input/sound | `crates/drivers/{drm,fbdev,fbcon,drv-virtio-gpu,drv-bochs,drv-simplefb,drv-virtio-input,drv-ps2-keyboard,drv-virtio-snd}`; `crates/kernel/{input,sound}` | — |
| `HAVE` | Current Ethernet support: virtio-net, E1000, IGC, RTL8125, and Atlantic | `crates/drivers/{drv-virtio-net,drv-e1000,drv-igc,drv-rtl8125,drv-atlantic}` | — |

## Missing or partial — priority work queue

Priority is a recommendation based on the impact to a normal installed Linux userspace with the drivers already in this tree. `PARTIAL` means code exists but source identifies a bound; `NOT FOUND` means no dedicated production owner was found in the current source tree.

| Status | Missing or partial system | Why this order | Code evidence | Branch |
|---|---|---|---|---|
| `P0` | `PARTIAL` — SMP, cross-CPU runtime, RCU, and workqueues | This is the first scaling and correctness blocker: the RCU implementation describes an effectively-UP runtime. | `crates/kernel/{cpu,sched,arch-irq}`; `crates/shared/sync/{rcu,percpu}` | — |
| `P0` | `PARTIAL` — PMM, VMM, reclaim, page faults, and COW | Memory management underpins every process and driver; the PMM describes itself as a one-zone allocator. | `crates/kernel/{mm-pmm,mm-vmm}` | — |
| `P1` | `PARTIAL` — swap, zram, huge pages, and memory cgroups | Needed once normal workloads exceed simple single-node memory pressure; the implementations are bounded and separate. | `crates/kernel/mm-pmm/{swap,hugetlb,memcg,reclaim}`; `crates/drivers/drv-zram` | — |
| `P1` | `NOT FOUND` — OverlayFS | Needed for ordinary container image layers and writable container roots. | source-tree audit under `crates/kernel` | — |
| `P1` | `NOT FOUND` — FAT/VFAT, 9p, and virtiofs | FAT/VFAT supports common EFI/removable-media workflows; 9p/virtiofs are common VM host-share paths. | source-tree audit under `crates/kernel` and `crates/drivers` | — |
| `P1` | `PARTIAL` — FUSE, hugetlbfs, autofs, binfmt_misc, and filesystem notifications | These are the remaining common filesystem-service hooks around the working VFS/ext4 base. | `crates/kernel/fs/{fuse,hugetlbfs,autofs,binfmt_misc,inotify}` | — |
| `P1` | `NOT FOUND` — device mapper/LVM, MD RAID, loop devices, and broad SCSI/USB storage | These are the standard storage composition paths beyond direct NVMe/AHCI/virtio-blk. | source-tree audit under `crates/kernel` and `crates/drivers` | — |
| `P1` | `PARTIAL` — netfilter, nftables, BPF/XDP, and socket filtering | Current selected implementations need completion for ordinary host firewalling and container network policy. | `crates/kernel/{netfilter,security/bpf}` | — |
| `P1` | `NOT FOUND` — conntrack/NAT, bridge, VLAN, and bonding | Required to turn the existing IP stack and namespace primitives into normal container, router, and multi-link networking. | source-tree audit under `crates/kernel` and `crates/drivers` | — |
| `P1` | `PARTIAL` — USB host and common classes | USB core/xHCI, hub, HID, and storage code exists; complete and validate this framework before adding individual device drivers. | `crates/drivers/{usb-core,drv-xhci/{usb,hid,storage}}` | — |
| `P2` | `PARTIAL` — SysV IPC, POSIX message queues, keyrings, userfaultfd, and io_uring | Production owners exist, but the code is split across selective work functions and backends. | `crates/kernel/{ipc,fs/keyring,fs/userfaultfd,syscalls/io_uring}` | — |
| `P2` | `PARTIAL` — futex2, robust lists, and priority inheritance | Classic futex support exists; futex2 accepts only 32-bit non-NUMA/non-MPOL words. | `crates/kernel/ipc/{live/futex,futex2_flags,futex_pi_rules,robust_decode}` | — |
| `P2` | `NOT FOUND` — Btrfs, XFS, F2FS, EROFS, and squashfs | Expand local filesystem choice after the core ext4/VFS and storage-composition work is dependable. | source-tree audit under `crates/kernel` | — |
| `P2` | `NOT FOUND` — NFS, SMB/CIFS, and SCSI filesystem/export services | Add once the local-filesystem and block/storage base is solid. | source-tree audit under `crates/kernel` | — |
| `P2` | `NOT FOUND` — Wi-Fi/mac80211 and Bluetooth | Important for general-purpose machines, but Ethernet is already covered for early host/server work. | source-tree audit under `crates/kernel` and `crates/drivers` | — |
| `P2` | `NOT FOUND` — SELinux, AppArmor, IMA/EVM, TPM, and TEE | The existing credentials, seccomp, Landlock, audit, and keyring base comes first; these expand policy and measured-trust coverage. | `crates/kernel/{security,landlock,audit,sched/{cred,yama,seccomp_filter},fs/keyring}`; source-tree audit | — |
| `P2` | `NOT FOUND` — ACPI AML/runtime power, thermal, battery, CPU frequency, and CPU idle | Static firmware-table discovery exists; these are needed for broad physical-machine and laptop support. | `crates/kernel/firmware`; source-tree audit under `crates/kernel` and `crates/drivers` | — |
| `P2` | `PARTIAL` — reset, reboot, kexec, and crash kernel | Dedicated owners exist; finish this for dependable maintenance and failure recovery. | `crates/kernel/{power,kexec}` | — |
| `P3` | `PARTIAL` — eBPF verifier, maps, links, BTF, BPF LSM, ftrace, kprobes, uprobes, and hardware-PMU tracing | Valuable for production tooling, but a later priority than runtime, storage, and basic networking. | `crates/kernel/security/{bpf,bpf_verify,bpf_interp,bpf_lsm}`; `crates/kernel/{tracefs,fs/perf}`; source-tree audit | — |
| `P3` | `NOT FOUND` — RDMA | Specialized high-performance networking; not required for the ordinary IP/Ethernet baseline. | source-tree audit under `crates/kernel` and `crates/drivers` | — |
| `P3` | `NOT FOUND` — KVM and VFIO | Needed for hosting VMs and direct device assignment, not for the base OS/runtime. | source-tree audit under `crates/kernel` and `crates/drivers` | — |
