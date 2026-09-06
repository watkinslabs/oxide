//! Narrowing of NT `ULONG` arguments carried in 64-bit registers.
//!
//! An NT service that declares a `ULONG` length receives it in a 64-bit
//! register whose upper half is not part of the value and is not required to
//! be zero. Reading the whole register turns a caller's byte count into a
//! value derived from whatever the register last held, which is how a correct
//! 128-byte conversion came to be measured as needing 2687 units.

/// The `ULONG` a caller actually passed, discarding the register's upper half.
/// # C: O(1)
pub(crate) const fn ulong(raw: u64) -> usize { raw as u32 as usize }

#[cfg(test)]
#[path = "tests/nt_ulong.rs"]
mod tests;
