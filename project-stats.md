cargo run -p xtask -- stats 
# oxide2 project code stats

_Generated: 2026-07-30 23:20:55 UTC_

| Metric | Value |
|---|---:|
| Tracked files (git) | 4725 |
| Commits (`git rev-list --all`) | 11427 |
| PRs (detected from commit subjects) | 4094 |
| Text files analyzed (non-vendor) | 4481 |
| Text files analyzed (`vendor/`) | 238 |
| Crates (`Cargo.toml` outside root) | 114 |
| Workspace members | 2 |
| Code files | 4190 |
| Code LOC | 631608 |
| Rust files | 3652 |
| Rust LOC | 587392 |
| Docs files | 131 |
| Docs LOC | 30586 |
| Test-like files | 628 |
| Test-like LOC | 95869 |

## Language mix

| Rank | Language | Files | LOC | Share |
|---:|---|---:|---:|---:|
| 1 | Rust | 3652 | 587392 | 87.5% |
| 2 | C/C++ | 489 | 36691 | 5.5% |
| 3 | Markdown | 131 | 30586 | 4.6% |
| 4 | Other | 32 | 5230 | 0.8% |
| 5 | Shell | 41 | 5119 | 0.8% |
| 6 | Config | 122 | 3839 | 0.6% |
| 7 | Python | 6 | 2258 | 0.3% |
| 8 | Assembly | 2 | 148 | 0.0% |
| 9 | Text | 6 | 38 | 0.0% |

## Top workspace members by Rust LOC

| Rank | Path | Rust files | Rust LOC | Avg LOC/file |
|---:|---|---:|---:|---:|
| 1 | `vendor/rust/structured-zstd-0.0.49` | 184 | 93920 | 510.4 |
| 2 | `vendor/rust/zlib-rs-0.6.6` | 45 | 17726 | 393.9 |

## Largest files

| Rank | File | LOC | Language |
|---:|---|---:|---|
| 1 | `crates/user/glibc/c/longdouble_x86_64.c` | 2575 | C/C++ |
| 2 | `scratch/network-plan.md` | 2376 | Markdown |
| 3 | `Cargo.lock` | 2290 | Other |
| 4 | `tools/kpi-header-smoke.c` | 1573 | C/C++ |
| 5 | `scratch/done/driver_anal.md` | 1531 | Markdown |
| 6 | `tools/qemu-mcp/server.py` | 1346 | Python |
| 7 | `crates/shared/kalloc/src/lib.rs` | 1202 | Rust |
| 8 | `scratch/syscall-compliance-matrix.md` | 1146 | Markdown |
| 9 | `scratch/done/glibc_done.md` | 1140 | Markdown |
| 10 | `scratch/done/interruptible-wait-plan.md` | 987 | Markdown |
| 11 | `crates/shared/kalloc/src/holes.rs` | 933 | Rust |
| 12 | `docs/15-syscall-abi.md` | 855 | Markdown |
| 13 | `crates/kernel/syscalls/src/siocgif.rs` | 804 | Rust |
| 14 | `crates/arch/hal-aarch64/src/vbar/asm.rs` | 784 | Rust |
| 15 | `crates/user/glibc/version/floatn.map` | 746 | Other |

## Vendor stats (`vendor/`)

| Metric | Value |
|---|---:|
| Vendor text files | 238 |
| Vendor LOC | 112639 |

| Rank | Language | Files | LOC | Share |
|---:|---|---:|---:|---:|
| 1 | Rust | 229 | 111646 | 99.1% |
| 2 | Other | 4 | 426 | 0.4% |
| 3 | Markdown | 3 | 344 | 0.3% |
| 4 | Config | 2 | 223 | 0.2% |

| Rank | File | LOC | Language |
|---:|---|---:|---|
| 1 | `vendor/rust/structured-zstd-0.0.49/src/encoding/match_generator/tests.rs` | 5100 | Rust |
| 2 | `vendor/rust/zlib-rs-0.6.6/src/deflate.rs` | 4331 | Rust |
| 3 | `vendor/rust/structured-zstd-0.0.49/src/decoding/frame_decoder.rs` | 3458 | Rust |
| 4 | `vendor/rust/structured-zstd-0.0.49/src/encoding/dfast/mod.rs` | 2917 | Rust |
| 5 | `vendor/rust/zlib-rs-0.6.6/src/inflate.rs` | 2740 | Rust |
| 6 | `vendor/rust/structured-zstd-0.0.49/src/encoding/frame_compressor/tests.rs` | 2731 | Rust |
| 7 | `vendor/rust/structured-zstd-0.0.49/src/encoding/frame_compressor.rs` | 2547 | Rust |
| 8 | `vendor/rust/structured-zstd-0.0.49/src/encoding/row/mod.rs` | 2515 | Rust |
| 9 | `vendor/rust/structured-zstd-0.0.49/src/encoding/match_table/storage.rs` | 2491 | Rust |
| 10 | `vendor/rust/structured-zstd-0.0.49/src/encoding/blocks/compressed.rs` | 2452 | Rust |
| 11 | `vendor/rust/structured-zstd-0.0.49/src/decoding/frame_decoder/tests.rs` | 2409 | Rust |
| 12 | `vendor/rust/structured-zstd-0.0.49/src/encoding/hc/optimal.rs` | 2277 | Rust |
| 13 | `vendor/rust/structured-zstd-0.0.49/src/encoding/match_generator/mod.rs` | 2158 | Rust |
| 14 | `vendor/rust/structured-zstd-0.0.49/src/encoding/simple/fast_matcher.rs` | 2076 | Rust |
| 15 | `vendor/rust/structured-zstd-0.0.49/src/encoding/simple/fast_kernel/kernel.rs` | 1970 | Rust |

## Docs status (docs/*.md)

| DRAFT | FROZEN | Other/Unmarked |
|---:|---:|---:|
| 15 | 49 | 1 |
