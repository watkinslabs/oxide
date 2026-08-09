cargo run -p xtask -- stats 
# oxide2 kernel stats

_Generated: 2026-08-08 16:23:21 UTC. Vendored third-party code (`vendor/`) is excluded from every figure._

## Scale

| Metric | Value |
|---|---:|
| Tracked files | 5369 |
| Crates | 110 |
| Workspace members | 103 |
| Code files / LOC | 5073 / 773194 |
| Rust files / LOC | 4658 / 739573 |
| Docs files / LOC | 139 / 33049 |
| Commits | 13213 |
| Merged PRs | 4687 |

## Composition

| Group | Path | Crates | Rust files | Rust LOC |
|---|---|---:|---:|---:|
| Kernel subsystems | `crates/kernel/` | 58 | 4029 | 626339 |
| Device drivers | `crates/drivers/` | 22 | 313 | 54077 |
| Arch / HAL | `crates/arch/` | 7 | 145 | 30918 |
| Shared kernel libs | `crates/shared/` | 15 | 112 | 19693 |
| Userspace libs | `crates/user/` | 0 | 0 | 0 |
| Build tooling | `tools/` | 2 | 44 | 7074 |

## Kernel subsystems (58)

| Crate | Rust files | Rust LOC |
|---|---:|---:|
| `net` | 569 | 104334 |
| `syscalls` | 806 | 99493 |
| `vfs` | 490 | 71824 |
| `fs` | 361 | 60205 |
| `sched` | 329 | 52071 |
| `ext4` | 186 | 35478 |
| `modules` | 144 | 26059 |
| `security` | 118 | 18277 |
| `mm-vmm` | 95 | 17410 |
| `netlink` | 77 | 14207 |
| `ipc` | 111 | 13505 |
| `mm-pmm` | 66 | 12194 |
| `procfs` | 86 | 11976 |
| `sysfs` | 56 | 9465 |
| `tty` | 46 | 6819 |
| _43 more_ | | 73022 |

## Device drivers (22)

Crate name states the hardware each covers.

| Crate | Rust files | Rust LOC |
|---|---:|---:|
| `drm` | 51 | 8636 |
| `drv-virtio-input` | 43 | 7246 |
| `drv-zram` | 41 | 6232 |
| `drv-virtio-gpu` | 22 | 4195 |
| `virtio` | 18 | 3861 |
| `fbcon` | 19 | 2987 |
| `drv-virtio-net` | 18 | 2676 |
| `drv-virtio-blk` | 15 | 2278 |
| `drv` | 10 | 2221 |
| `drv-ahci` | 8 | 2062 |
| `drv-virtio-snd` | 12 | 1978 |
| `pci` | 9 | 1848 |
| `fbdev` | 8 | 1483 |
| `drv-nvme` | 4 | 1161 |
| `vt` | 6 | 1073 |
| `drv-virtio-vsock` | 6 | 961 |
| `drv-virtio-rng` | 5 | 812 |
| `drv-ps2-keyboard` | 10 | 783 |
| `drv-uart-16550` | 2 | 706 |
| `drv-uart-pl011` | 2 | 516 |
| `drv-simplefb` | 3 | 272 |
| `drv-serial` | 1 | 90 |

## Arch / HAL (7)

| Crate | Rust files | Rust LOC |
|---|---:|---:|
| `hal-x86_64` | 45 | 10312 |
| `hal-aarch64` | 44 | 10265 |
| `hal` | 28 | 5983 |
| `boot-aarch64` | 16 | 2908 |
| `boot-x86_64` | 8 | 1316 |
| `kernel-bin-x86_64` | 2 | 93 |
| `kernel-bin-aarch64` | 2 | 41 |

## Syscall ABI

| Metric | Value |
|---|---:|
| `NR_*` slots declared | 385 |
| ABI shim slot files | 269 |
| Compliance-matrix rows | 385 |

| Status | Count | Share |
|---|---:|---:|
| `IMPL` | 343 | 89.1% |
| `LINUX-ENOSYS` | 22 | 5.7% |
| `PARTIAL` | 20 | 5.2% |

## Supported surface

| Kind | Count | Names |
|---|---:|---|
| Filesystems | 19 | `binfmt_misc`, `bpf`, `cgroup2`, `configfs`, `debugfs`, `devpts`, `devtmpfs`, `efivarfs`, `ext4`, `fusectl`, `hugetlbfs`, `mqueue`, `proc`, `pstore`, `ramfs`, `securityfs`, `sysfs`, `tmpfs`, `tracefs` |
| Address families | 6 | `INET`, `INET6`, `NETLINK`, `PACKET`, `UNIX`, `VSOCK` |
| Socket types | 6 | `DGRAM`, `PACKET`, `RAW`, `RDM`, `SEQPACKET`, `STREAM` |
| IP protocols | 6 | `ICMP`, `ICMPV6`, `IP`, `RAW`, `TCP`, `UDP` |

## Specs and tests

| Metric | Value |
|---|---:|
| Specs in `docs/` | 64 |
| DRAFT / FROZEN / unmarked | 14 / 49 / 1 |
| Hosted test functions | 14543 |

## Health

| Metric | Value |
|---|---:|
| Issue rows OPEN | 272 |
| Issue rows IN-PROGRESS | 0 |
| Issue rows FIXED | 0 |
| Files at/over the 500-line split cutoff | 76 |
| Files over the 1000-line hard cap | 0 |

| Largest over the split cutoff | LOC |
|---|---:|
| `crates/shared/kalloc/src/holes.rs` | 967 |
| `crates/kernel/netlink/src/netlink_socket.rs` | 939 |
| `crates/kernel/sched/src/task.rs` | 913 |
| `crates/arch/hal-aarch64/src/vbar/asm.rs` | 838 |
| `crates/kernel/syscalls/src/siocgif.rs` | 811 |
| `crates/kernel/fs/src/inotify_fan_tests.rs` | 809 |
| `crates/kernel/syscalls/src/dispatch/core.rs` | 793 |
| `docs/15-syscall-abi.md` | 763 |
| `crates/kernel/sched/src/live/schedule/switch.rs` | 742 |
| `crates/kernel/ipc/tests/futex_core_hosted.rs` | 740 |
| `crates/kernel/fs/tests/sys_ioctl_shape.rs` | 712 |
| `crates/kernel/syscalls/src/056_clone.rs` | 671 |
| `crates/shared/kalloc/src/tests.rs` | 668 |
| `crates/shared/sync/src/lib.rs` | 650 |
| `crates/kernel/sched/src/task/methods.rs` | 641 |

## Language mix

| Language | Files | LOC | Share |
|---|---:|---:|---:|
| Rust | 4658 | 739573 | 90.7% |
| Markdown | 139 | 33049 | 4.1% |
| C/C++ | 366 | 23086 | 2.8% |
| Python | 15 | 5897 | 0.7% |
| Other | 25 | 5033 | 0.6% |
| Shell | 32 | 4490 | 0.6% |
| Config | 119 | 4006 | 0.5% |
| Assembly | 2 | 148 | 0.0% |
| Text | 7 | 129 | 0.0% |

## Largest files

| File | LOC | Language |
|---|---:|---|
| `scratch/network-plan.md` | 2377 | Markdown |
| `Cargo.lock` | 2312 | Other |
| `tools/kpi-header-smoke.c` | 1573 | C/C++ |
| `scratch/done/driver_anal.md` | 1531 | Markdown |
| `tools/qemu-mcp/server.py` | 1340 | Python |
| `scratch/fixed-issues.md` | 1238 | Markdown |
| `scratch/syscall-compliance-matrix.md` | 1187 | Markdown |
| `scratch/done/glibc_done.md` | 1140 | Markdown |
| `scratch/done/interruptible-wait-plan.md` | 981 | Markdown |
| `tools/stack-depth-gate.py` | 977 | Python |
| `crates/shared/kalloc/src/holes.rs` | 967 | Rust |
| `crates/kernel/netlink/src/netlink_socket.rs` | 939 | Rust |
| `crates/kernel/sched/src/task.rs` | 913 | Rust |
| `scratch/firefox-performance-20260806.md` | 864 | Markdown |
| `crates/arch/hal-aarch64/src/vbar/asm.rs` | 838 | Rust |
