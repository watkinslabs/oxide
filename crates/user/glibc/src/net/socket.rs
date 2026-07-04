// socket — BSD sockets API (docs/59§6 G13). Address/message structs (byte-
// exact glibc layout, size-asserted vs the libc crate) + freestanding syscall
// wrappers. x86_64/aarch64 both use individual socket syscalls (not socketcall).
#![allow(clippy::upper_case_acronyms)]

// Module manifest: types owns socket ABI layouts; exports owns syscall wrappers; tests checks host layouts.
mod types;
pub use types::*;
#[cfg(feature = "freestanding")]
mod exports;
#[cfg(feature = "freestanding")]
pub use exports::*;
#[cfg(test)]
mod tests;
