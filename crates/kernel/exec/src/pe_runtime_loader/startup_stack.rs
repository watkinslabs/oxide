//! Where the startup context sits on the initial thread's own stack.
//!
//! The runtime's thread-start path is entered with a pointer to the context
//! record in the first argument register. Before it resumes that context it
//! rounds the pointer down to a page, drops its own stack pointer a fixed
//! extent below that page, and zeroes the whole extent — running on it as its
//! stack while it does. The record therefore cannot live in a mapping of its
//! own: it belongs on the thread stack, far enough above the low end that the
//! scrubbed extent is entirely inside the same mapping.
//!
//! The reference derives the record's address from the stack base alone:
//! reserve a small gap below the base, align down, and step back one record.
//! The entry stack pointer is one machine word below the record.

use pe::nt_context::CONTEXT_BYTES;

/// Bytes left free below the stack base before the record is placed.
pub const START_STACK_GAP: u64 = 0x28;
/// Extent the runtime scrubs below the page the record starts in, before it
/// has resumed the context. Every byte of it is written.
pub const START_SCRUB_BYTES: u64 = 0xf000;
/// Bytes the entry stack pointer sits below the record.
pub const START_RETURN_SLOT: u64 = 8;
/// Alignment the record is placed on.
const RECORD_ALIGN: u64 = 16;
const PAGE_MASK: u64 = hal::PAGE_SIZE_BYTES - 1;

/// Smallest thread stack that can carry a startup context. The record plus its
/// gap never spans more than two pages, and the scrub runs a fixed extent
/// below the lower of them.
pub const MIN_START_STACK_BYTES: u64 = START_SCRUB_BYTES + 2 * hal::PAGE_SIZE_BYTES;

/// A startup context placed on a thread stack.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct StartupStack {
    /// Address of the context record.
    pub context: u64,
    /// Stack pointer the thread is entered on.
    pub stack_pointer: u64,
    /// Lowest address the runtime writes before it resumes the context.
    pub scrub_floor: u64,
}

impl StartupStack {
    /// Bytes the record occupies, from its own address. # C: O(1)
    pub const fn context_bytes(&self) -> u64 { CONTEXT_BYTES as u64 }
}

/// Place the startup context on `[stack_base, stack_top)`, or refuse a stack
/// that cannot carry the extent the runtime writes before it resumes.
/// # C: O(1)
pub fn place(stack_base: u64, stack_top: u64) -> Option<StartupStack> {
    if stack_base >= stack_top { return None; }
    let cursor = stack_top.checked_sub(START_STACK_GAP)? & !(RECORD_ALIGN - 1);
    let context = cursor.checked_sub(CONTEXT_BYTES as u64)?;
    let stack_pointer = context.checked_sub(START_RETURN_SLOT)?;
    let scrub_floor = (context & !PAGE_MASK).checked_sub(START_SCRUB_BYTES)?;
    if scrub_floor < stack_base { return None; }
    Some(StartupStack { context, stack_pointer, scrub_floor })
}

#[cfg(test)]
#[path = "startup_stack/tests.rs"]
mod tests;
