# oxide2 kernel stats

_Generated: 2026-08-01 18:51:34 UTC. Vendored third-party code (`vendor/`) is excluded from every figure._

## Scale

| Metric | Value |
|---|---:|
| Tracked files | 5290 |
| Crates | 117 |
| Workspace members | 116 |
| Code files / LOC | 4971 / 752921 |
| Rust files / LOC | 4425 / 706489 |
| Docs files / LOC | 145 / 31310 |
| Commits | 11948 |
| Merged PRs | 4251 |

## Composition

| Group | Path | Crates | Rust files | Rust LOC |
|---|---|---:|---:|---:|
| Kernel subsystems | `crates/kernel/` | 58 | 3545 | 549692 |
| Device drivers | `crates/drivers/` | 21 | 295 | 51750 |
| Arch / HAL | `crates/arch/` | 8 | 131 | 27086 |
| Shared kernel libs | `crates/shared/` | 17 | 101 | 19647 |
| Userspace libs | `crates/user/` | 11 | 315 | 52195 |
| Build tooling | `tools/` | 2 | 38 | 6119 |

## Kernel subsystems (58)

| Crate | Rust files | Rust LOC |
|---|---:|---:|
| `syscalls` | 711 | 85604 |
| `net` | 447 | 85096 |
| `vfs` | 463 | 66643 |
| `fs` | 306 | 52831 |
| `sched` | 316 | 49089 |
| `ext4` | 172 | 32157 |
| `modules` | 128 | 23774 |
| `mm-vmm` | 79 | 14916 |
| `ipc` | 106 | 12693 |
| `security` | 67 | 12277 |
| `mm-pmm` | 62 | 11475 |
| `procfs` | 82 | 11022 |
| `netlink` | 57 | 10677 |
| `sysfs` | 54 | 9004 |
| `tty` | 45 | 6735 |
| _43 more_ | | 65699 |

## Device drivers (21)

Crate name states the hardware each covers.

| Crate | Rust files | Rust LOC |
|---|---:|---:|
| `drm` | 50 | 8513 |
| `drv-virtio-input` | 43 | 7206 |
| `drv-zram` | 41 | 6217 |
| `drv-virtio-gpu` | 21 | 3898 |
| `virtio` | 18 | 3725 |
| `fbcon` | 19 | 2978 |
| `drv-virtio-net` | 16 | 2543 |
| `drv-virtio-blk` | 15 | 2209 |
| `drv` | 9 | 2134 |
| `drv-ahci` | 8 | 2052 |
| `drv-virtio-snd` | 12 | 1827 |
| `pci` | 9 | 1694 |
| `fbdev` | 7 | 1339 |
| `drv-nvme` | 4 | 1161 |
| `vt` | 6 | 1063 |
| `drv-virtio-vsock` | 6 | 928 |
| `drv-virtio-rng` | 5 | 693 |
| `drv-ps2-keyboard` | 2 | 657 |
| `drv-uart-pl011` | 2 | 491 |
| `drv-uart-16550` | 1 | 332 |
| `drv-serial` | 1 | 90 |

## Arch / HAL (8)

| Crate | Rust files | Rust LOC |
|---|---:|---:|
| `hal-aarch64` | 41 | 9388 |
| `hal-x86_64` | 43 | 9220 |
| `hal` | 17 | 3826 |
| `boot-aarch64` | 11 | 2540 |
| `boot-x86_64` | 9 | 1415 |
| `limine-proto` | 6 | 564 |
| `kernel-bin-x86_64` | 2 | 92 |
| `kernel-bin-aarch64` | 2 | 41 |

## Syscall ABI

| Metric | Value |
|---|---:|
| `NR_*` slots declared | 385 |
| ABI shim slot files | 269 |
| Compliance-matrix rows | 385 |

| Status | Count | Share |
|---|---:|---:|
| `IMPL` | 290 | 75.3% |
| `PARTIAL` | 56 | 14.5% |
| `LINUX-ENOSYS` | 22 | 5.7% |
| `NEEDS-REWORK` | 17 | 4.4% |

## Supported surface

| Kind | Count | Names |
|---|---:|---|
| Filesystems | 21 | `autofs`, `binfmt_misc`, `bpf`, `cgroup2`, `configfs`, `debugfs`, `devpts`, `devtmpfs`, `efivarfs`, `ext4`, `fuse`, `fusectl`, `hugetlbfs`, `mqueue`, `proc`, `pstore`, `ramfs`, `securityfs`, `sysfs`, `tmpfs`, `tracefs` |
| Address families | 6 | `INET`, `INET6`, `NETLINK`, `PACKET`, `UNIX`, `VSOCK` |
| Socket types | 6 | `DGRAM`, `PACKET`, `RAW`, `RDM`, `SEQPACKET`, `STREAM` |
| IP protocols | 3 | `ICMP`, `ICMPV6`, `RAW` |

## Specs and tests

| Metric | Value |
|---|---:|
| Specs in `docs/` | 65 |
| DRAFT / FROZEN / unmarked | 15 / 49 / 1 |
| Hosted test functions | 12789 |

## Health

| Metric | Value |
|---|---:|
| Issue rows OPEN | 157 |
| Issue rows IN-PROGRESS | 8 |
| Issue rows FIXED | 22 |
| Files at/over the 500-line split cutoff | 69 |
| Files over the 1000-line hard cap | 1 |

| Largest over the split cutoff | LOC |
|---|---:|
| `crates/shared/kalloc/src/lib.rs` | 1202 |
| `crates/shared/kalloc/src/holes.rs` | 933 |
| `crates/kernel/sched/src/task.rs` | 859 |
| `docs/15-syscall-abi.md` | 855 |
| `crates/arch/hal-aarch64/src/vbar/asm.rs` | 818 |
| `crates/kernel/syscalls/src/siocgif.rs` | 804 |
| `crates/kernel/fs/src/inotify_fan_tests.rs` | 770 |
| `crates/kernel/syscalls/src/dispatch/core.rs` | 767 |
| `crates/kernel/sched/src/live/schedule/switch.rs` | 756 |
| `crates/kernel/netlink/src/netlink_socket.rs` | 736 |
| `crates/kernel/fs/tests/sys_ioctl_shape.rs` | 712 |
| `crates/kernel/ipc/tests/futex_core_hosted.rs` | 675 |
| `crates/kernel/syscalls/src/056_clone.rs` | 659 |
| `crates/shared/kalloc/src/tests.rs` | 651 |
| `crates/kernel/mm-pmm/src/user_as/fault.rs` | 645 |

## Language mix

| Language | Files | LOC | Share |
|---|---:|---:|---:|
| Rust | 4425 | 706489 | 89.0% |
| C/C++ | 490 | 36907 | 4.6% |
| Markdown | 145 | 31310 | 3.9% |
| Other | 32 | 5503 | 0.7% |
| Shell | 45 | 5502 | 0.7% |
| Config | 127 | 4064 | 0.5% |
| Python | 9 | 3875 | 0.5% |
| Text | 9 | 164 | 0.0% |
| Assembly | 2 | 148 | 0.0% |

## Largest files

| File | LOC | Language |
|---|---:|---|
| `crates/user/glibc/c/longdouble_x86_64.c` | 2575 | C/C++ |
| `scratch/network-plan.md` | 2376 | Markdown |
| `Cargo.lock` | 2363 | Other |
| `tools/kpi-header-smoke.c` | 1573 | C/C++ |
| `scratch/done/driver_anal.md` | 1531 | Markdown |
| `tools/qemu-mcp/server.py` | 1346 | Python |
| `crates/shared/kalloc/src/lib.rs` | 1202 | Rust |
| `scratch/syscall-compliance-matrix.md` | 1188 | Markdown |
| `scratch/done/glibc_done.md` | 1140 | Markdown |
| `scratch/done/interruptible-wait-plan.md` | 987 | Markdown |
| `crates/shared/kalloc/src/holes.rs` | 933 | Rust |
| `crates/kernel/sched/src/task.rs` | 859 | Rust |
| `docs/15-syscall-abi.md` | 855 | Markdown |
| `crates/arch/hal-aarch64/src/vbar/asm.rs` | 818 | Rust |
| `crates/kernel/syscalls/src/siocgif.rs` | 804 | Rust |
