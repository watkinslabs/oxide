# Stock Linux System Compatibility

Code-only audit: `9283872bd`. This covers the common in-kernel services a normal Linux distro uses. It intentionally excludes individual hardware-driver coverage, alternate CPU architectures, obsolete protocols, and distro userspace such as systemd, package managers, and desktops.

Device rows cover the kernel framework needed to use a driver. They are not a demand to reproduce Linux's entire driver catalog.

## What we have

`HAVE` means a production owner exists. It does not silently claim every Linux feature in that owner; any source-proven gap is named below.

| Status | System | Code evidence | Branch |
|---|---|---|---|
| `HAVE` | x86_64 and AArch64 boot, traps, MMU, IRQ, and timers | `crates/arch/{boot-x86_64,hal-x86_64,kernel-bin-x86_64,boot-aarch64,hal-aarch64,kernel-bin-aarch64}` | — |
| `HAVE` | Processes, threads, exec, signals, sessions, process groups, and pidfds | `crates/kernel/{sched,exec,pidfd}` | — |
| `HAVE` | Timekeeping, POSIX timers, timerfds, and random numbers | `crates/kernel/{timekeeper,timer,crng,fs/timerfd}` | — |
| `HAVE` | Pipes, eventfd, signalfd, timerfd, epoll, and splice | `crates/kernel/fs/src/{pipe,signalfd,timerfd,epoll,splice}`; `crates/kernel/vfs` | — |
| `HAVE` | Swap, zram, huge pages, and memory cgroups | `crates/kernel/mm-pmm/src/{swap,hugetlb,reclaim,memcg}.rs`; `crates/drivers/drv-zram` | — |
| `HAVE` | SysV IPC, POSIX message queues, keyrings, and userfaultfd | `crates/kernel/ipc`; `crates/kernel/fs/src/{keyring,userfaultfd}` | — |
| `HAVE` | VFS: paths, mounts, dentries, inodes, fd tables, permissions, xattrs, and quotas | `crates/kernel/vfs/src/{namei,mount,dentry,inode,fdtable,quota,xattr}` | — |
| `HAVE` | ext4 and JBD2 journal | `crates/kernel/ext4/src/{balloc,extent_rw,jbd2,inode,xattr,quota,mount}` | — |
| `HAVE` | tmpfs, procfs, sysfs, kernfs, devfs, devpts, tracefs, and pstore | `crates/kernel/fs/src/tmpfs`; `crates/kernel/{procfs,sysfs,kernfs,devfs,devpts,tracefs,pstore}` | — |
| `HAVE` | FUSE, hugetlbfs, autofs, binfmt_misc, and inotify/fanotify | `crates/kernel/fs/src/{fuse,hugetlbfs,autofs,binfmt_misc,inotify}` | — |
| `HAVE` | Block layer, partitions, page cache, elevators, and direct I/O | `crates/kernel/block/{partitions,elevator,direct,registry}` | — |
| `HAVE` | Current storage backends: virtio-blk, NVMe, AHCI, and zram | `crates/drivers/{drv-virtio-blk,drv-nvme,drv-ahci,drv-zram}` | — |
| `HAVE` | IPv4/IPv6, ARP/NDP, ICMP, TCP, UDP, raw, and ping sockets | `crates/kernel/net/{stack,stack_ipv6,arp,neigh,raw4,raw6,ping}` | — |
| `HAVE` | AF_UNIX, AF_PACKET, AF_VSOCK, netlink, rtnetlink, and generic netlink | `crates/kernel/{net/unix_sock,net/vsock,netlink/{rtnetlink,genetlink},socket}` | — |
| `HAVE` | Ethernet bridging and STP | `crates/kernel/net/src/stack/{bridge,bridge_stp}.rs`; `crates/kernel/syscalls/src/siocgif/bridge.rs` | — |
| `HAVE` | Namespace and cgroup primitives | `crates/kernel/{namespace-identity,network-namespace,user-namespace,time-namespace,nscg,cgroup}` | — |
| `HAVE` | Credentials, capabilities, seccomp, Landlock, audit, and Yama policy | `crates/kernel/{security,landlock,audit,sched/{cred,yama,seccomp_filter}}` | — |
| `HAVE` | Kernel keyring, logging, tracefs, perf records, and persistent logs | `crates/kernel/fs/keyring`; `crates/shared/klog`; `crates/kernel/{tracefs,fs/perf,pstore}` | — |
| `HAVE` | Driver registration, PCI/PCIe, virtio, MSI/MSI-X/INTx, and IOMMU | `crates/kernel/{pci-boot,pci-irq,pcie-port,iommu,modules}`; `crates/drivers/{drv,pci,virtio}` | — |
| `HAVE` | Firmware discovery, ACPI table parsing, AML PCI routing, and S5 power-off setup | `crates/kernel/firmware/src/{acpi,acpi/aml_routes,acpi/aml_handler,acpi/power_action}.rs`; `crates/shared/fdt` | — |
| `HAVE` | USB core/xHCI, hub, HID, and mass storage | `crates/drivers/{usb-core,drv-xhci}` | — |
| `HAVE` | Console, TTY, PTY, terminal emulation, and 16550/PL011 serial UARTs | `crates/kernel/{tty,vt,console,serialtty,vtconsole}`; `crates/drivers/{drv-serial,drv-uart-16550,drv-uart-pl011}` | — |
| `HAVE` | Display/input/audio substrate, including virtio GPU/input/sound | `crates/drivers/{drm,fbdev,fbcon,drv-virtio-gpu,drv-bochs,drv-simplefb,drv-virtio-input,drv-ps2-keyboard,drv-virtio-snd}`; `crates/kernel/{input,sound}` | — |
| `HAVE` | Current Ethernet support: virtio-net, E1000, IGC, RTL8125, and Atlantic | `crates/drivers/{drv-virtio-net,drv-e1000,drv-igc,drv-rtl8125,drv-atlantic}` | — |

## Missing or partial — priority work queue

`PARTIAL` is never a placeholder here: **Exact missing now** names the missing behavior visible in code. `NOT FOUND` means no dedicated production owner was found in the current source tree.

| Status | System | Exact missing now | Why this order | Code evidence | Branch |
|---|---|---|---|---|---|
| `P0 · PARTIAL` | SMP, cross-CPU runtime, RCU, and workqueues | Application processors park in `cli;hlt`; the RCU grace model therefore runs effectively UP instead of with concurrently running APs. | First scaling and correctness blocker. | `crates/kernel/arch-irq/src/smp_x86.rs`; `crates/shared/sync/src/rcu.rs` | — |
| `P0 · PARTIAL` | PMM zone management | The physical-memory allocator has exactly one zone; there is no multi-zone allocator. | Memory allocation underpins every process and driver. | `crates/kernel/mm-pmm/src/lib.rs` | — |
| `P1 · NOT FOUND` | OverlayFS | No OverlayFS mount, lookup, copy-up, or whiteout owner exists. | Required for ordinary container image layers and writable container roots. | source-tree audit under `crates/kernel` | — |
| `P1 · NOT FOUND` | FAT/VFAT, 9p, and virtiofs | No filesystem owner exists for any of these three filesystems. | FAT/VFAT covers common EFI/removable-media flows; 9p/virtiofs are common VM host-share paths. | source-tree audit under `crates/kernel` and `crates/drivers` | — |
| `P1 · NOT FOUND` | Device mapper/LVM, MD RAID, loop devices, and a SCSI transport stack | No device-mapper, MD, loop, or SCSI transport owner exists; the present SCSI code only reserves `sd*` disk names. | Standard storage composition beyond direct NVMe/AHCI/virtio-blk. | `crates/kernel/block/src/registry/scsi.rs`; source-tree audit under `crates/kernel` and `crates/drivers` | — |
| `P1 · PARTIAL` | nftables expression support | Rule parsing accepts only `payload`, `cmp`, `immediate`, `meta`, `lookup`, `counter`, `bitwise`, and `byteorder`; every other expression returns `Unsupported`. | Basic host firewalling and container policy need a broader ruleset. | `crates/kernel/netfilter/src/nft_expr.rs` | — |
| `P1 · NOT FOUND` | Conntrack/NAT, VLAN, and bonding | No production owner exists for connection tracking, NAT, VLAN interfaces, or bonding. Bridge support is present and is listed above. | Completes normal container, router, and multi-link networking. | `crates/kernel/net/src/stack/bridge.rs`; source-tree audit under `crates/kernel` and `crates/drivers` | — |
| `P1 · PARTIAL` | USB mass-storage block operations | USB mass storage implements read, write, and flush, but returns `EOPNOTSUPP` for discard and write-zeroes. | Finish framework behavior before adding individual USB device drivers. | `crates/drivers/drv-xhci/src/storage_block.rs` | — |
| `P2 · PARTIAL` | futex2 | Only 32-bit futex words work; NUMA-keyed and memory-policy-keyed futexes are rejected. | Important for broad userspace compatibility after runtime and storage/network basics. | `crates/kernel/ipc/src/futex2_flags.rs` | — |
| `P2 · PARTIAL` | io_uring | Only opcodes named by `op_supported` run; all others return `EINVAL`. Polled read/write also requires direct I/O and a pollable backend or returns `EOPNOTSUPP`. | Useful high-throughput I/O expansion, after the basic I/O stack. | `crates/kernel/syscalls/src/io_uring/{abi/ops,submit,dispatch/rw}.rs` | — |
| `P2 · NOT FOUND` | Btrfs, XFS, F2FS, EROFS, and squashfs | No filesystem owner exists for these five filesystems. | Expand local filesystem choice after ext4 and block composition are dependable. | source-tree audit under `crates/kernel` | — |
| `P2 · NOT FOUND` | NFS and SMB/CIFS | No NFS or SMB/CIFS filesystem/client owner exists. | Add once local-filesystem and storage composition work is dependable. | source-tree audit under `crates/kernel` | — |
| `P2 · NOT FOUND` | Wi-Fi/mac80211 and Bluetooth | No Wi-Fi/mac80211 or Bluetooth subsystem owner exists. | Important for general-purpose machines; Ethernet supports early host/server work. | source-tree audit under `crates/kernel` and `crates/drivers` | — |
| `P2 · NOT FOUND` | SELinux, AppArmor, IMA/EVM, TPM, and TEE | No owner exists for MAC policy, integrity measurement/appraisal, TPM, or TEE services. | Existing credentials, seccomp, Landlock, audit, and keyring form the base. | source-tree audit under `crates/kernel` | — |
| `P2 · PARTIAL` | ACPI runtime services and platform power management | AML is used for PCI `_PRT`/`_OSC` and S5 power-off setup; no thermal, battery, CPU-frequency, or CPU-idle owner exists. | Needed for broad physical-machine and laptop support. | `crates/kernel/firmware/src/acpi/{aml_routes,aml_handler,power_action}.rs`; source-tree audit under `crates/kernel` and `crates/drivers` | — |
| `P2 · PARTIAL` | x86 reset fallbacks | The reset ladder lacks EFI runtime-services reset and real-mode BIOS reset. | Needed for dependable maintenance and failure recovery on more firmware. | `crates/kernel/power/src/reset.rs` | — |
| `P3 · PARTIAL` | eBPF link operations | Cgroup links support detach and update; LSM and iterator links reject detach and update. | Production tooling comes after runtime, storage, and basic networking. | `crates/kernel/security/src/bpf/cmd/link_cmd.rs` | — |
| `P3 · PARTIAL` | perf event types | `perf_event_open` accepts only software event type; hardware PMU event types return `ENOENT`. | Valuable observability, but later than base OS capability. | `crates/kernel/fs/src/perf/{open,counter}.rs` | — |
| `P3 · NOT FOUND` | RDMA | No RDMA subsystem owner exists. | Specialized high-performance networking. | source-tree audit under `crates/kernel` and `crates/drivers` | — |
| `P3 · NOT FOUND` | KVM and VFIO | No KVM virtualization or VFIO device-assignment owner exists. | Needed for hosting VMs and direct device assignment, not the base OS/runtime. | source-tree audit under `crates/kernel` and `crates/drivers` | — |
