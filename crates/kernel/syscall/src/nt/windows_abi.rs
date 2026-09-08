//! The shipped runtime's calling convention, converted to the kernel's
//! argument record.
//!
//! A stock service stub moves the first argument into the one call register
//! the syscall instruction does not clobber and does nothing else, so the
//! arguments reach the kernel in the caller's own convention: four in
//! registers, the rest in the caller's frame above its reserved area. The
//! kernel's record is ordered by the host convention instead, so without a
//! conversion every service behind the raw ordinal route reads its
//! neighbour's argument — and the first one it reads is not an argument at
//! all.
//!
//! The conversion belongs at the entry boundary, once, rather than in each
//! service: a service's own decode is written against argument positions, and
//! those are what this restores.

use crate::SyscallArgs;

/// Arguments the caller's convention passes in registers. Every later
/// argument is a word in the caller's frame.
pub const REGISTER_ARGS: usize = 4;

/// Convert one entry record from the shipped runtime's convention into the
/// kernel's, reading the frame words for the arguments the caller did not
/// pass in registers. A frame word that cannot be read is not an argument the
/// caller passed, so it reads as zero rather than failing the call: a service
/// taking four arguments never reserves the space for a fifth.
///
/// Only one architecture's conventions differ this way. Elsewhere the two
/// agree on the first six argument registers, so the record already holds the
/// arguments in their own positions and is passed through.
/// # C: O(1) plus two frame reads
#[cfg(target_arch = "x86_64")]
pub fn windows_args(entry: SyscallArgs, mut frame: impl FnMut(usize) -> Option<u64>) -> SyscallArgs {
    SyscallArgs {
        // The first argument travels in the register the stub moved it to,
        // which the host convention reads as its fourth.
        a0: entry.a3,
        a1: entry.a2,
        a2: entry.a4,
        a3: entry.a5,
        a4: frame(REGISTER_ARGS).unwrap_or(0),
        a5: frame(REGISTER_ARGS + 1).unwrap_or(0),
    }
}

/// The two conventions agree here: the record already names the arguments in
/// their own positions. # C: O(1)
#[cfg(not(target_arch = "x86_64"))]
pub fn windows_args(entry: SyscallArgs, _frame: impl FnMut(usize) -> Option<u64>) -> SyscallArgs { entry }

#[cfg(all(test, target_arch = "x86_64"))]
#[path = "windows_abi/tests.rs"]
mod tests;
