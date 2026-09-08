//! The order in which an access check refuses its arguments.
//!
//! The service takes eight arguments and refuses them in a fixed order: the
//! privilege set and its length are read before anything else, the security
//! descriptor is marshalled next, and only then is the token handle named.
//! The order is observable — a call carrying both an unreadable descriptor
//! and a handle that names nothing answers for the descriptor — so it is
//! fixed here rather than left to the order a handler happens to test in.
//!
//! An absent descriptor is not a caller error at the argument boundary: a
//! descriptor too short to be one is refused the same way whether the caller
//! passed none or passed one that cannot be read, and that refusal is the
//! same status either way.

/// A caller argument names memory the service cannot use.
pub const STATUS_ACCESS_VIOLATION: u64 = 0xc000_0005;
/// The token argument names no object.
pub const STATUS_INVALID_HANDLE: u64 = 0xc000_0008;

/// The eight argument words, in their declared positions.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Args {
    pub descriptor: u64,
    pub token: u64,
    pub desired_access: u32,
    pub mapping: u64,
    pub privileges: u64,
    pub return_length: u64,
    pub granted: u64,
    pub access_status: u64,
}

/// The status the argument ladder answers with, or `None` when every argument
/// is one the service can act on. `descriptor_readable` reports whether a
/// descriptor of the minimum size could be read at the descriptor argument;
/// a caller that passed none never has one.
/// # C: O(1)
pub fn refusal(args: Args, descriptor_readable: bool) -> Option<u64> {
    if args.privileges == 0 || args.return_length == 0 { return Some(STATUS_ACCESS_VIOLATION); }
    if args.mapping == 0 { return Some(STATUS_ACCESS_VIOLATION); }
    if !descriptor_readable { return Some(STATUS_ACCESS_VIOLATION); }
    if args.token == 0 { return Some(STATUS_INVALID_HANDLE); }
    if args.granted == 0 || args.access_status == 0 { return Some(STATUS_ACCESS_VIOLATION); }
    None
}

/// The argument record one call carries, with each word narrowed to its own
/// declared width. The desired access is an access mask: a half, not a word.
/// # C: O(1)
pub fn args(registers: [u64; 6], frame: [u64; 2]) -> Args {
    Args {
        descriptor: registers[0], token: registers[1], desired_access: registers[2] as u32,
        mapping: registers[3], privileges: registers[4], return_length: registers[5],
        granted: frame[0], access_status: frame[1],
    }
}

#[cfg(test)]
#[path = "tests/nt_access_check_policy.rs"]
mod tests;
