# Stock Linux System Compatibility

Code audit: `2f197dfcf` (rows below carry their own evidence). This covers the in-kernel services a normal Linux distro uses.

**Ranked by one question: can a person log in, use a desktop, and run normal programs?** Everything else — VM hosting, device assignment, router and container-orchestration features — sorts below that, however much kernel surface it represents.

Two rules this file previously broke, restated so they are not broken again:

- **`HAVE` means an owner exists in code. It does not mean the behaviour works.** Verified this session: TTY/console is `HAVE` and `serial-getty@ttyS0` still exits every 5.000 s and restart-loops 23 times in one boot. Code presence is a *necessary* condition and nothing more, so the queue starts with a behaviour tier that no inventory can express.
- **A recorded gap is a hypothesis.** The previous revision's top P0 was stale — see `Corrected below`. Re-read the code before spending a lane on any row here.

Device rows cover the kernel framework needed to use a driver, not a demand to reproduce Linux's driver catalog.

## Tier 0 — behaviour: nothing below matters until these are true

Not expressible as a code inventory, which is why the earlier revision had none of it. These are the acceptance gates.

| Status | Gate | Where it stands | Branch |
|---|---|---|---|
| `BLOCKED` | A boot reaches a login prompt and stays there | `serial-getty@ttyS0` starts, exits successfully after exactly 5.000 s, and restart-loops; 23 restarts in one 129 s boot | — |
| `BLOCKED` | Every boot reaches userspace | Intermittent silent wedge at ~3.3-3.6 s, 3 of 6 boots on one image, with no watchdog output at all | — |
| `UNKNOWN` | A user can log in and get a shell | Never observed; blocked behind the two rows above | — |
| `UNKNOWN` | A graphical session starts | Never observed | — |
| `UNKNOWN` | A normal program launches, runs and exits cleanly | Never observed as a gate; individual programs run during boot | — |

Rows in `scratch/known_issues.md` carry the evidence for each.

## Corrected below

The previous revision's ranking was written for a server/container target and its first row was wrong. Both are fixed here.

| Was | Now | Why |
|---|---|---|
| `P0 · PARTIAL` SMP: "application processors park in `cli;hlt`; the RCU grace model runs effectively UP" | Removed as a defect; kept as a *configuration* note | Stale. `arch-irq/src/smp_x86.rs:230`: "Enter the idle→schedule loop with IRQs on (sti) — **replaces the cli;hlt park**. The AP runs its idle task until ttwu migrates a task onto its runqueue and IPIs it." `sched::halt_forever` is a real idle→schedule loop with newidle load balancing. What is true is duller: `SMP ?= 1` in the Makefile, so development boots are single-CPU by choice |
| Scope excluded "distro userspace such as systemd, package managers, and desktops" | Scope is the desktop | The excluded set was the goal |
| Ranking led with OverlayFS, nftables, conntrack, device-mapper, SCSI | Those sort to Tier 3 | All server work; none of it stands between a user and a session |

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
| `HAVE` | Display/input/audio substrate for VIRTUAL machines | `crates/drivers/{drm,fbdev,fbcon,drv-virtio-gpu,drv-bochs,drv-simplefb,drv-virtio-input,drv-ps2-keyboard,drv-virtio-snd}`; `crates/kernel/{input,sound}`. Scope narrowed from the previous revision: every display and audio driver present is virtual or firmware-framebuffer. See `T1` below | — |
| `HAVE` | Current Ethernet support: virtio-net, E1000, IGC, RTL8125, and Atlantic | `crates/drivers/{drv-virtio-net,drv-e1000,drv-igc,drv-rtl8125,drv-atlantic}` | — |

## Tier 1 — the desktop session itself

Without these a logged-in user has no working machine. `T1-a` and `T1-b` are answered for free by a virtual-machine target and are driver projects on physical hardware; the rest are needed either way.

| ID | Status | System | Exact missing now | Code evidence | Branch |
|---|---|---|---|---|---|
| `T1-a` | `HAVE` | KMS over the firmware framebuffer (`simpledrm`) | **Retraction of this row's first revision, which said no modesetting driver existed for a physical machine.** It does: `drv-simplefb` registers a DRM card named `simpledrm` ("DRM driver for firmware framebuffers") with a full scanout backend — one CRTC, one connector, one encoder, one primary plane, the firmware's geometry as its single fixed mode, XRGB8888. `present_drm` maps a dumb buffer through the HHDM and blits the damaged rect into the write-combining aperture, which is the reference's shadow-plane update. `kmain` creates the `simple-framebuffer.0` platform device on every boot, so `/dev/dri/card0` exists on any machine with a boot framebuffer. The first revision was written from a grep of `lib.rs` and `format.rs`; the implementation is in `driver.rs`. | `crates/drivers/drv-simplefb/src/driver.rs::{attach_firmware_scanout,present_drm,SimpleDrm}`; `crates/kernel/kmain/src/kmain/runtime.rs:332` | — |
| `T1-a2` | `PARTIAL` | Hardware cursor on the firmware framebuffer | `simpledrm` answers `MODE_CURSOR` with failure (`unsupported_cursor`, `unsupported_move_cursor`). A compositor must software-composite its pointer. The reference's simpledrm has no cursor plane either, so this is a divergence only if a client refuses the fallback. | `crates/drivers/drv-simplefb/src/driver.rs::{unsupported_cursor,unsupported_move_cursor}` | — |
| `T1-a3` | `NOT FOUND` | Accelerated GPU drivers (i915, amdgpu, nouveau, vc4) | No native GPU driver for physical hardware. With `T1-a` present this costs acceleration and multi-monitor modesetting, not the session itself — the reference boots a desktop on `simpledrm` plus software rendering. | no `i915`/`amdgpu`/`nouveau`/`vc4` owner in `crates/drivers` | — |
| `T1-b` | `NOT FOUND` | HD-Audio (HDA) codec and controller | The sound subsystem's only driver is virtio-snd. A physical machine has no audio path at all | `crates/kernel/sound`; `crates/drivers/drv-virtio-snd`; no HDA owner | — |
| `T1-c` | `NOT FOUND` | Suspend and resume | No suspend owner of any kind — not S3, not s2idle, not freeze. `power/` covers poweroff, reset, CAD and kexec only. Closing a laptop lid does nothing; `/sys/power/state` has no working target | `crates/kernel/power/src/{lib,poweroff,reset,cad,machine}.rs`; grep for `s2idle`/`suspend_to_ram` finds no owner | — |
| `T1-d` | `NOT FOUND` | `power_supply` class | No battery or AC-adapter reporting. upower has nothing to read, so a desktop shows no battery, no charge state and no low-battery action | no `power_supply` owner under `crates/kernel` or `crates/drivers` | — |
| `T1-e` | `NOT FOUND` | Backlight class | No brightness control. Brightness keys and the desktop's slider have no device to act on | no `backlight` owner under `crates/kernel` or `crates/drivers` | — |
| `T1-f` | `PARTIAL` | ACPI runtime and platform power management | AML is used for PCI `_PRT`/`_OSC` and S5 setup; no thermal, no CPU-frequency, no CPU-idle owner. A laptop runs at a fixed operating point with no thermal response | `crates/kernel/firmware/src/acpi/{aml_routes,aml_handler,power_action}.rs` | — |

## Tier 2 — running normal programs

| ID | Status | System | Exact missing now | Code evidence | Branch |
|---|---|---|---|---|---|
| `T2-a` | `NOT FOUND` | OverlayFS | No mount, lookup, copy-up or whiteout owner. Container tooling a desktop user actually runs — toolbox, podman, layered images — has no writable root | source-tree audit under `crates/kernel` | — |
| `T2-b` | `HAVE` | Loop devices | `/dev/loop0`..`loop7` are published at boot under the reference's fixed major, `/dev/loop-control` answers the three index ioctls, and the `LOOP_*` commands are wired into the ioctl shim: bind, clear, status both layouts, capacity, block size, direct-I/O refusal, and configure. A device backed by itself is refused before anything is bound. Remaining: `LOOP_CHANGE_FD` returns `EINVAL` rather than swapping a live device's backing description, and there is no partition scan on `LO_FLAGS_PARTSCAN`. | `crates/drivers/drv-loop` (63 hosted tests); `crates/kernel/syscalls/src/016_ioctl/loop_dev.rs`; `devfs::misc::make_loop_control_inode`. Boot evidence: `systemd[1]: Finished modprobe@loop.service - Load Kernel Module loop.` | F1161-loop-userspace-wiring |
| `T2-c` | `PARTIAL` | FAT/VFAT | The volume layer exists: boot-sector validation in the reference's refusal order, and the geometry — region placement, the cluster-count rule that derives FAT12 from FAT16, the clamp against a table shorter than the data area, and cluster-to-sector mapping that refuses a number past the end. What remains is directory iteration with long names, the cluster-chain walk, and the read and write paths, so no volume mounts yet. | `crates/kernel/fatfs` (22 hosted tests); no `FileSystemType` registered | F1162-fat-geometry |
| `T2-d` | `NOT FOUND` | exFAT and NTFS | No owner for either. Large USB media and any disk shared with Windows are unreadable | source-tree audit under `crates/kernel` | — |
| `T2-e` | `NOT FOUND` | V4L2 | No video-capture subsystem. No webcam, on any bus, ever — video calls and camera apps have no device | no `v4l2`/`videodev` owner under `crates/kernel` or `crates/drivers` | — |
| `T2-f` | `NOT FOUND` | SELinux | No MAC-policy owner. The composed image's distribution ships SELinux enforcing, so a boot has to disable it and diverge from the distribution it is built from | source-tree audit under `crates/kernel` | — |
| `T2-g` | `NOT FOUND` | Bluetooth | No Bluetooth subsystem. Wireless keyboards, mice and headphones do not work | source-tree audit under `crates/kernel` and `crates/drivers` | — |
| `T2-h` | `NOT FOUND` | Wi-Fi and mac80211 | No Wi-Fi subsystem. A laptop with no Ethernet port has no network at all | source-tree audit under `crates/kernel` and `crates/drivers` | — |
| `T2-i` | `PARTIAL` | futex2 | Only 32-bit futex words; NUMA-keyed and memory-policy-keyed futexes are rejected. Broad userspace compatibility | `crates/kernel/ipc/src/futex2_flags.rs` | — |
| `T2-j` | `PARTIAL` | USB mass-storage block operations | Read, write and flush work; discard and write-zeroes return `EOPNOTSUPP` | `crates/drivers/drv-xhci/src/storage_block.rs` | — |

## Tier 3 — server, router and container features

Real Linux surface, none of it between a user and a working session.

| Status | System | Exact missing now | Code evidence | Branch |
|---|---|---|---|---|
| `NOT FOUND` | Device mapper/LVM, MD RAID, and a SCSI transport stack | No device-mapper, MD or SCSI transport owner; the present SCSI code only reserves `sd*` disk names | `crates/kernel/block/src/registry/scsi.rs` | — |
| `PARTIAL` | nftables expression support | Accepts only `payload`, `cmp`, `immediate`, `meta`, `lookup`, `counter`, `bitwise`, `byteorder`; every other expression returns `Unsupported` | `crates/kernel/netfilter/src/nft_expr.rs` | — |
| `NOT FOUND` | Conntrack/NAT, VLAN, and bonding | No owner for connection tracking, NAT, VLAN interfaces or bonding. Bridging is present | source-tree audit under `crates/kernel` | — |
| `NOT FOUND` | 9p and virtiofs | No owner for either host-share filesystem | source-tree audit under `crates/kernel` and `crates/drivers` | — |
| `NOT FOUND` | Btrfs, XFS, F2FS, EROFS, and squashfs | No owner for these five filesystems | source-tree audit under `crates/kernel` | — |
| `NOT FOUND` | NFS and SMB/CIFS | No network-filesystem client owner | source-tree audit under `crates/kernel` | — |
| `PARTIAL` | io_uring | Only opcodes named by `op_supported` run; others return `EINVAL`. Polled read/write also requires direct I/O and a pollable backend | `crates/kernel/syscalls/src/io_uring/{abi/ops,submit,dispatch/rw}.rs` | — |
| `PARTIAL` | PMM zone management | One zone; no multi-zone allocator. Matters when a device needs a bounded DMA address range — physical hardware, not a virtual machine | `crates/kernel/mm-pmm/src/lib.rs` | — |
| `NOT FOUND` | IMA/EVM, TPM, TEE, and AppArmor | No owner for integrity measurement/appraisal, TPM, TEE, or that MAC policy | source-tree audit under `crates/kernel` | — |
| `PARTIAL` | x86 reset fallbacks | The reset ladder lacks EFI runtime-services reset and real-mode BIOS reset | `crates/kernel/power/src/reset.rs` | — |
| `PARTIAL` | eBPF link operations | Cgroup links support detach and update; LSM and iterator links reject both | `crates/kernel/security/src/bpf/cmd/link_cmd.rs` | — |
| `PARTIAL` | perf event types | `perf_event_open` accepts software events only; hardware PMU types return `ENOENT` | `crates/kernel/fs/src/perf/{open,counter}.rs` | — |
| `NOT FOUND` | RDMA | No RDMA subsystem owner | source-tree audit under `crates/kernel` and `crates/drivers` | — |
| `NOT FOUND` | KVM and VFIO | No virtualization or device-assignment owner | source-tree audit under `crates/kernel` and `crates/drivers` | — |

## Platform support — which machines this can run on at all

The x86_64 target boots QEMU and is the only configuration with boot evidence. The AArch64 target is QEMU `virt` **and nothing else**, which is a stronger statement than "some drivers are missing": the platform is a fixed map, not a discovered one.

| Status | Platform | Exact position | Code evidence | Branch |
|---|---|---|---|---|
| `HAVE` | QEMU x86_64 (q35, virtio, NVMe, AHCI) | The development target; every boot in the ledger is this | `crates/kernel/smoke/src/device_map` | — |
| `HAVE` | QEMU AArch64 `virt` | Boots with a hardcoded device map | `crates/kernel/smoke/src/device_map/arm.rs` | — |
| `NOT FOUND` | GICv2 / GIC-400 | The interrupt-controller driver is GICv3 only, and its distributor and redistributor addresses are compile-time constants for QEMU `virt` (`GICD_PHYS = 0x0800_0000`, `GICR_PHYS = 0x080A_0000`) rather than discovered | `crates/kernel/arch-irq/src/gic.rs:1`; `crates/kernel/smoke/src/device_map/arm.rs:10,17` | — |
| `PARTIAL` | Device-tree platform discovery | Three properties are read from the FDT: a `simple-framebuffer`, the first `arm,pl011` UART with its clock, and the machine model. Memory regions and CPUs are enumerated. Everything else about the platform is the fixed QEMU map above | `crates/shared/fdt/src/props.rs::{simple_framebuffer,pl011_clock_hz,machine_model,memory_regions,enum_cpus}` | — |
| `NOT FOUND` | SD/MMC (SDHCI) | No MMC host or card owner. Any board whose root device is an SD card is unreachable | source-tree audit under `crates/drivers` | — |
| `NOT FOUND` | Raspberry Pi | Blocked on four independent items, not on polish: GIC-400 is GICv2 (above); device discovery is the fixed QEMU map (above); no SD/MMC (above); no BCM GENET (Pi 4) or RP1 southbridge (Pi 5) Ethernet. Display would be a firmware framebuffer only — no VideoCore/VC4 owner. The boot path is the one part that could work today, via EDK2 UEFI firmware loading our GRUB | rows above; no `bcm`/`vc4`/`genet`/`rp1` owner under `crates/drivers` | — |
| `NOT FOUND` | Physical x86 laptop or desktop | Blocked on `T1-a` through `T1-f`: no GPU modesetting, no audio, no suspend, no battery, no backlight, no thermal or frequency control | Tier 1 above | — |
