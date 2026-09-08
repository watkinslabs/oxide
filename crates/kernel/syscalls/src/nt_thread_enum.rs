//! Enumeration order and handle attributes for the next-thread service.
//!
//! The service walks one process's threads in a stable total order, opening a
//! handle to the first one past the caller's previous position. The order
//! itself only has to be total and stable — what the contract fixes is that
//! every thread appears exactly once, that a null previous position starts at
//! one end, and that running off the end is its own status rather than an
//! error.

/// Reverse the walk. It is the only defined flag; the service refuses a
/// larger value rather than ignoring the bits it does not know.
pub const NEXT_THREAD_PREVIOUS: u32 = 0x0000_0001;
/// Object attribute asking for a handle a child process inherits.
pub const OBJ_INHERIT: u32 = 0x0000_0002;
/// Every attribute bit an object-attributes word may carry.
pub const OBJ_VALID_ATTRIBUTES: u32 = 0x0000_03f2;
/// Table flag recording that a handle is inherited.
pub const HANDLE_FLAG_INHERIT: u32 = 0x0000_0001;

/// Whether the flags word names a walk this service performs. # C: O(1)
pub fn flags_admitted(flags: u32) -> bool { flags <= NEXT_THREAD_PREVIOUS }

/// Whether the walk runs from the last thread towards the first. # C: O(1)
pub fn walks_backwards(flags: u32) -> bool { flags & NEXT_THREAD_PREVIOUS != 0 }

/// Whether the attributes word carries only defined attribute bits. # C: O(1)
pub fn attributes_admitted(attributes: u32) -> bool { attributes & !OBJ_VALID_ATTRIBUTES == 0 }

/// Handle-table flags one attributes word asks for. Only inheritance is a
/// property of the handle; the rest describe a name lookup this service does
/// not perform.
/// # C: O(1)
pub fn handle_flags_from_attributes(attributes: u32) -> u32 {
    if attributes & OBJ_INHERIT != 0 { HANDLE_FLAG_INHERIT } else { 0 }
}

/// The next thread in the walk, given the ascending identities of the
/// process's threads and the caller's previous position. A previous position
/// that names no thread of this process still orders the walk, so a caller
/// that hands back a thread which has since exited resumes where that thread
/// would have been rather than starting over.
/// # C: O(N_threads)
pub fn next_of(order: &[u32], last: Option<u32>, backwards: bool) -> Option<u32> {
    match (last, backwards) {
        (None, false) => order.first().copied(),
        (None, true) => order.last().copied(),
        (Some(last), false) => order.iter().copied().find(|id| *id > last),
        (Some(last), true) => order.iter().copied().rev().find(|id| *id < last),
    }
}

#[cfg(test)]
#[path = "nt_thread_enum/tests.rs"]
mod tests;
