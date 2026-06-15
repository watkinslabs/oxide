// Linux syscall numbers used by libc. Named constants only (07§5 — no
// bare slot literals at call sites). G3 replaces this hand list with the
// UAPI-exported table from `userspace/uapi/` (29a§3, 15§6.7); kept tiny
// here so G1/G2 (exit path, hello) link.
#![allow(dead_code)]

#[cfg(target_arch = "x86_64")]
pub const EXIT_GROUP: usize = 231;
#[cfg(target_arch = "x86_64")]
pub const WRITE: usize = 1;
#[cfg(target_arch = "x86_64")]
pub const READ: usize = 0;

#[cfg(target_arch = "aarch64")]
pub const EXIT_GROUP: usize = 94;
#[cfg(target_arch = "aarch64")]
pub const WRITE: usize = 64;
#[cfg(target_arch = "aarch64")]
pub const READ: usize = 63;

// Host builds (hosted/test on the dev box, neither x86_64-target asm
// path) still need the symbols to exist for type-checking the rlib.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub const EXIT_GROUP: usize = 0;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub const WRITE: usize = 0;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub const READ: usize = 0;
