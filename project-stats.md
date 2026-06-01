# oxide2 project code stats

_Generated: 2026-06-01 21:30:12 UTC_

| Metric | Value |
|---|---:|
| Tracked files (git) | 1862 |
| Commits (`git rev-list --all`) | 3145 |
| PRs (detected from commit subjects) | 1464 |
| Text files analyzed (non-vendor) | 701 |
| Text files analyzed (`vendor/`) | 840 |
| Crates (`Cargo.toml` outside root) | 65 |
| Workspace members | 65 |
| Code files | 537 |
| Code LOC | 119618 |
| Rust files | 424 |
| Rust LOC | 112342 |
| Docs files | 76 |
| Docs LOC | 14920 |
| Test-like files | 9 |
| Test-like LOC | 1395 |

## Language mix

| Rank | Language | Files | LOC | Share |
|---:|---|---:|---:|---:|
| 1 | Rust | 424 | 112342 | 81.1% |
| 2 | Markdown | 76 | 14920 | 10.8% |
| 3 | C/C++ | 53 | 3515 | 2.5% |
| 4 | Shell | 56 | 2498 | 1.8% |
| 5 | Other | 16 | 2362 | 1.7% |
| 6 | Config | 72 | 1584 | 1.1% |
| 7 | Python | 2 | 1034 | 0.7% |
| 8 | Assembly | 2 | 229 | 0.2% |

## Top workspace members by Rust LOC

| Rank | Path | Rust files | Rust LOC | Avg LOC/file |
|---:|---|---:|---:|---:|
| 1 | `kernel` | 91 | 23367 | 256.8 |
| 2 | `crates/kernel/net` | 31 | 9225 | 297.6 |
| 3 | `crates/kernel/sched` | 35 | 6829 | 195.1 |
| 4 | `crates/kernel/ext4` | 24 | 6131 | 255.5 |
| 5 | `crates/arch/hal-x86_64` | 16 | 4383 | 273.9 |
| 6 | `crates/kernel/fs` | 16 | 4057 | 253.6 |
| 7 | `crates/kernel/mm-vmm` | 11 | 4040 | 367.3 |
| 8 | `crates/arch/hal-aarch64` | 16 | 3526 | 220.4 |
| 9 | `crates/kernel/vfs` | 16 | 3449 | 215.6 |
| 10 | `crates/kernel/mm-pmm` | 6 | 3411 | 568.5 |
| 11 | `crates/kernel/netfilter` | 5 | 2520 | 504.0 |
| 12 | `tools/xtask` | 5 | 2385 | 477.0 |
| 13 | `crates/kernel/ipc` | 10 | 2323 | 232.3 |
| 14 | `crates/kernel/arch-irq` | 5 | 2227 | 445.4 |
| 15 | `crates/kernel/syscall` | 9 | 1924 | 213.8 |

## Largest files

| Rank | File | LOC | Language |
|---:|---|---:|---|
| 1 | `Cargo.lock` | 1271 | Other |
| 2 | `CHANGELOG.md` | 1035 | Markdown |
| 3 | `crates/kernel/net/src/tcp_conn.rs` | 1000 | Rust |
| 4 | `tools/xtask/src/main.rs` | 1000 | Rust |
| 5 | `crates/kernel/net/src/stack.rs` | 999 | Rust |
| 6 | `crates/kernel/netlink/src/rtnetlink.rs` | 999 | Rust |
| 7 | `crates/kernel/net/src/sock.rs` | 998 | Rust |
| 8 | `kernel/src/lib.rs` | 996 | Rust |
| 9 | `kernel/src/pci_boot/virtio_drv.rs` | 994 | Rust |
| 10 | `kernel/src/procfs/mod.rs` | 993 | Rust |
| 11 | `crates/kernel/ext4/src/rootfs.rs` | 990 | Rust |
| 12 | `kernel/src/syscalls/mod.rs` | 986 | Rust |
| 13 | `kernel/src/syscalls/fs.rs` | 983 | Rust |
| 14 | `crates/kernel/sched/src/task.rs` | 980 | Rust |
| 15 | `kernel/src/syscalls/proc.rs` | 978 | Rust |

## Vendor stats (`vendor/`)

| Metric | Value |
|---|---:|
| Vendor text files | 840 |
| Vendor LOC | 248701 |

| Rank | Language | Files | LOC | Share |
|---:|---|---:|---:|---:|
| 1 | C/C++ | 726 | 215902 | 86.8% |
| 2 | Other | 67 | 29701 | 11.9% |
| 3 | Shell | 45 | 3053 | 1.2% |
| 4 | Markdown | 2 | 45 | 0.0% |

| Rank | File | LOC | Language |
|---:|---|---:|---|
| 1 | `vendor/openssl/install-aarch64/include/openssl/obj_mac.h` | 5481 | C/C++ |
| 2 | `vendor/openssl/install-x86_64/include/openssl/obj_mac.h` | 5481 | C/C++ |
| 3 | `vendor/zstd/install-aarch64/include/zstd.h` | 3089 | C/C++ |
| 4 | `vendor/zstd/install-x86_64/include/zstd.h` | 3089 | C/C++ |
| 5 | `vendor/libunistring/install-aarch64/include/unistd.h` | 2936 | C/C++ |
| 6 | `vendor/libunistring/install-x86_64/include/unistd.h` | 2936 | C/C++ |
| 7 | `vendor/openssl/install-aarch64/include/openssl/ssl.h` | 2599 | C/C++ |
| 8 | `vendor/openssl/install-x86_64/include/openssl/ssl.h` | 2599 | C/C++ |
| 9 | `vendor/openssl/install-aarch64/include/openssl/ssl.h.in` | 2527 | Other |
| 10 | `vendor/openssl/install-x86_64/include/openssl/ssl.h.in` | 2527 | Other |
| 11 | `vendor/libunistring/install-aarch64/include/unistd.in.h` | 2419 | C/C++ |
| 12 | `vendor/libunistring/install-x86_64/include/unistd.in.h` | 2419 | C/C++ |
| 13 | `vendor/libseccomp/install-aarch64/include/seccomp-syscalls.h` | 2355 | C/C++ |
| 14 | `vendor/libseccomp/install-x86_64/include/seccomp-syscalls.h` | 2355 | C/C++ |
| 15 | `vendor/openssl/install-aarch64/include/openssl/evp.h` | 2172 | C/C++ |

## Docs status (docs/*.md)

| DRAFT | FROZEN | Other/Unmarked |
|---:|---:|---:|
| 12 | 48 | 1 |
