//! The eleven-argument thread-creation record.
//!
//! Thread creation declares eleven arguments: six arrive in the caller's
//! argument slots and five more are words of the caller's own frame. Reading
//! only the first six leaves every argument past the first naming its
//! neighbour — the access mask read as the process handle, the object
//! attributes read as the start routine, the start routine read as the stack
//! size — and the two arguments that actually size the stack are never read
//! at all.
//!
//! The flags word is a ULONG in a frame slot, so its upper half keeps
//! whatever the frame held before the caller's word-wide store. Flags this
//! kernel does not act on are not a caller error: a runtime asks for loader
//! and debugger behaviour this personality does not implement, and refusing
//! the word refuses the thread.

/// The thread starts suspended and runs at its creator's next resume.
pub const THREAD_CREATE_FLAGS_CREATE_SUSPENDED: u32 = 0x0000_0001;
/// The new thread skips the per-thread attach callbacks.
pub const THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH: u32 = 0x0000_0002;
/// The new thread is not reported to an attached debugger.
pub const THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER: u32 = 0x0000_0004;
/// The new thread does not run loader initialisation.
pub const THREAD_CREATE_FLAGS_SKIP_LOADER_INIT: u32 = 0x0000_0010;
/// The new thread runs even while the process is frozen.
pub const THREAD_CREATE_FLAGS_BYPASS_PROCESS_FREEZE: u32 = 0x0000_0040;

/// One decoded creation request.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Args {
    pub handle: u64,
    pub desired_access: u32,
    pub attributes: u64,
    pub process: u64,
    pub start: u64,
    pub parameter: u64,
    pub flags: u32,
    pub zero_bits: u64,
    pub stack_commit: u64,
    pub stack_reserve: u64,
    pub attribute_list: u64,
}

/// The record one call carries: six argument slots and five frame words, each
/// narrowed to its own declared width. The access mask and the flags are
/// halves; every other argument is a pointer, a handle or an address-sized
/// count and keeps its whole slot.
/// # C: O(1)
pub fn args(registers: [u64; 6], frame: [u64; 5]) -> Args {
    Args {
        handle: registers[0], desired_access: registers[1] as u32, attributes: registers[2],
        process: registers[3], start: registers[4], parameter: registers[5],
        flags: frame[0] as u32, zero_bits: frame[1], stack_commit: frame[2],
        stack_reserve: frame[3], attribute_list: frame[4],
    }
}

/// Whether the requested address-bit reservation is one no address space can
/// satisfy: a count naming more high bits than an address has, but short of
/// the width at which the argument means an address mask instead.
/// # C: O(1)
pub const fn zero_bits_refused(zero_bits: u64) -> bool { zero_bits > 21 && zero_bits < 32 }

/// Flags that change what this personality does with the new thread. The rest
/// describe loader and debugger behaviour a caller may ask for and this
/// kernel need not act on; they are never a refusal.
/// # C: O(1)
pub const fn starts_suspended(flags: u32) -> bool {
    flags & THREAD_CREATE_FLAGS_CREATE_SUSPENDED != 0
}

#[cfg(test)]
#[path = "tests/nt_thread_create_args.rs"]
mod tests;
