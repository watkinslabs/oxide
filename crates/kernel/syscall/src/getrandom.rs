// getrandom(2) flag vocabulary per docs/15, Linux
// `include/uapi/linux/random.h` + `drivers/char/random.c`
// `SYSCALL_DEFINE3(getrandom, ...)`. Pure ABI validation, no kernel
// state, so it lives in the ABI boundary crate (docs/53) and stays
// hosted-testable even though the syscall shim
// (`crates/kernel/syscalls/src/318_getrandom.rs`) only compiles under
// the oxide-kernel target (gated behind `kernel_body.rs`'s
// `#[cfg(target_os = "oxide-kernel")]` include, which excludes every
// numbered syscall file — this one included — from a hosted
// `cargo test`). Single source of truth: the shim calls
// `validate_grnd_flags`, never reimplements it.

use crate::errno::Errno;

/// `GRND_NONBLOCK` — return `EAGAIN` instead of blocking when the entropy
/// pool is not yet initialised.
pub const GRND_NONBLOCK: u32 = 0x0001;
/// `GRND_RANDOM` — draw from the blocking ("random") pool instead of urandom.
pub const GRND_RANDOM: u32 = 0x0002;
/// `GRND_INSECURE` — return possibly-insecure bytes, never blocking.
pub const GRND_INSECURE: u32 = 0x0004;
const GRND_KNOWN: u32 = GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE;

/// Linux `INT_MAX` — `getrandom(2)` silently clamps `count` to this
/// (`drivers/char/random.c`), since the return value is a signed `ssize_t`.
pub const GETRANDOM_COUNT_MAX: u64 = i32::MAX as u64;

/// Validate `getrandom(2)`'s `flags` argument. Unknown bits are `EINVAL`;
/// `GRND_RANDOM|GRND_INSECURE` together is `EINVAL` (mutually exclusive
/// pool selectors, matching Linux). # C: O(1)
pub fn validate_grnd_flags(flags: u32) -> Result<(), Errno> {
    if (flags & !GRND_KNOWN) != 0 { return Err(Errno::Einval); }
    if (flags & GRND_RANDOM) != 0 && (flags & GRND_INSECURE) != 0 { return Err(Errno::Einval); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_no_flags() { assert_eq!(validate_grnd_flags(0), Ok(())); }

    #[test]
    fn accepts_each_known_flag_and_nonblock_combos() {
        assert_eq!(validate_grnd_flags(GRND_NONBLOCK), Ok(()));
        assert_eq!(validate_grnd_flags(GRND_RANDOM), Ok(()));
        assert_eq!(validate_grnd_flags(GRND_INSECURE), Ok(()));
        assert_eq!(validate_grnd_flags(GRND_NONBLOCK | GRND_RANDOM), Ok(()));
        assert_eq!(validate_grnd_flags(GRND_NONBLOCK | GRND_INSECURE), Ok(()));
    }

    #[test]
    fn rejects_unknown_bit() {
        assert_eq!(validate_grnd_flags(0x8), Err(Errno::Einval));
        assert_eq!(validate_grnd_flags(GRND_NONBLOCK | 0x1000), Err(Errno::Einval));
        assert_eq!(validate_grnd_flags(u32::MAX), Err(Errno::Einval));
    }

    #[test]
    fn rejects_random_and_insecure_together() {
        assert_eq!(validate_grnd_flags(GRND_RANDOM | GRND_INSECURE), Err(Errno::Einval));
        assert_eq!(validate_grnd_flags(GRND_NONBLOCK | GRND_RANDOM | GRND_INSECURE), Err(Errno::Einval));
    }

    #[test]
    fn count_max_matches_int_max() {
        assert_eq!(GETRANDOM_COUNT_MAX, 0x7FFF_FFFF);
    }
}
