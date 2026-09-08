//! Argument narrowing for the NT token services.
//!
//! A caller spells a BOOLEAN in the low byte of its argument slot; the bits
//! above it are not part of the value and are not required to be zero. A
//! service that compares the whole slot against one refuses every TRUE a
//! caller spells with a wider register, and a service that range-checks a
//! ULONG slot refuses every call whose slot kept a previous value in its
//! upper half.

/// The BOOLEAN a caller passed: the low byte of the slot, never the slot.
/// # C: O(1)
pub const fn boolean(raw: u64) -> bool { raw as u8 != 0 }

/// The ULONG a caller passed, discarding the slot's upper half. # C: O(1)
pub const fn ulong(raw: u64) -> u32 { raw as u32 }

/// Token type naming a token that can be a process's own.
pub const TOKEN_PRIMARY: u32 = 1;
/// Token type naming a token a thread wears while impersonating.
pub const TOKEN_IMPERSONATION: u32 = 2;

/// Whether a duplication names one of the two token types. # C: O(1)
pub const fn duplicate_type_admitted(raw: u64) -> bool {
    matches!(ulong(raw), TOKEN_PRIMARY | TOKEN_IMPERSONATION)
}

#[cfg(test)]
#[path = "tests/nt_token_args.rs"]
mod tests;
