// Per-arch Linux syscall numbers (docs/59§4). Sourced from the canonical
// Linux uapi tables — x86_64 from arch/x86/.../syscall_64.tbl, aarch64
// from include/uapi/asm-generic/unistd.h — the same split glibc keeps in
// sysdeps/<arch>. Named constants only; call sites use `nr::FOO`, never a
// bare slot literal (07§5). Numbers grow per area as wrappers land.
//
// aarch64 is asm-generic: it has NO open/stat/lstat/access/pipe/dup2/
// poll/select/fork/rename/*at-less variants — libc composes those from
// openat/newfstatat/faccessat/etc. (see posix/io.rs arch dispatch).
#![allow(dead_code)]

#[cfg(target_arch = "aarch64")]
pub use self::aarch64::*;
#[cfg(not(target_arch = "aarch64"))]
pub use self::x86_64::*;


// Module manifest: x86_64 and aarch64 own per-arch syscall number tables.
#[cfg(not(target_arch = "aarch64"))]
pub mod x86_64;
#[cfg(target_arch = "aarch64")]
pub mod aarch64;
