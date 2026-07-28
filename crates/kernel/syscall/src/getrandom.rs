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

/// What a caller must do when the pool is not yet initialised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColdPool {
    /// Hand out bytes regardless — `GRND_INSECURE`.
    Proceed,
    /// `EAGAIN` — `GRND_NONBLOCK` without `GRND_INSECURE`.
    Again,
    /// Block until seeded (Linux `wait_for_random_bytes()`).
    Wait,
}

/// Linux `drivers/char/random.c` `SYSCALL_DEFINE3(getrandom)`:
///
/// ```text
/// if (!crng_ready() && !(flags & GRND_INSECURE)) {
///         if (flags & GRND_NONBLOCK)
///                 return -EAGAIN;
///         ret = wait_for_random_bytes();
/// }
/// ```
///
/// `GRND_INSECURE` means "never block, never fail" and so suppresses the
/// `EAGAIN` entirely; it is not itself an `EAGAIN` trigger. # C: O(1)
pub fn cold_pool_action(flags: u32) -> ColdPool {
    if (flags & GRND_INSECURE) != 0 { return ColdPool::Proceed; }
    if (flags & GRND_NONBLOCK) != 0 { return ColdPool::Again; }
    ColdPool::Wait
}

/// Linux `wait_for_random_bytes()` re-checks readiness on a 1 s timeout, so a
/// pool that becomes ready without an explicit wakeup still releases waiters.
pub const CRNG_WAIT_POLL_NS: u64 = 1_000_000_000;

/// How a `ColdPool::Wait` waiter must return once it stops waiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    /// Pool became ready — go on and fill the buffer.
    Ready,
    /// Linux `wait_for_random_bytes()` returns `-ERESTARTSYS` on a signal, and
    /// `getrandom(2)` propagates it unchanged.
    Restart,
}

/// Resolve one iteration of the `wait_for_random_bytes()` loop. Split out from
/// the syscall shim so the decision is testable: the shim itself is
/// `#[cfg(target_os = "oxide-kernel")]` and its tests would never compile.
/// # C: O(1)
pub fn wait_step(seeded: bool, signal_pending: bool) -> Option<WaitOutcome> {
    // Linux checks `crng_ready()` first: a pool that went ready in the same
    // instant a signal arrived still succeeds rather than returning ERESTARTSYS.
    if seeded { return Some(WaitOutcome::Ready); }
    if signal_pending { return Some(WaitOutcome::Restart); }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insecure_never_fails_even_with_nonblock() {
        assert_eq!(cold_pool_action(GRND_INSECURE), ColdPool::Proceed);
        assert_eq!(cold_pool_action(GRND_INSECURE | GRND_NONBLOCK), ColdPool::Proceed);
    }

    #[test]
    fn nonblock_alone_is_eagain() {
        assert_eq!(cold_pool_action(GRND_NONBLOCK), ColdPool::Again);
        assert_eq!(cold_pool_action(GRND_NONBLOCK | GRND_RANDOM), ColdPool::Again);
    }

    #[test]
    fn plain_and_random_block() {
        assert_eq!(cold_pool_action(0), ColdPool::Wait);
        assert_eq!(cold_pool_action(GRND_RANDOM), ColdPool::Wait);
    }

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
    fn a_ready_pool_ends_the_wait() {
        assert_eq!(wait_step(true, false), Some(WaitOutcome::Ready));
    }

    #[test]
    fn readiness_beats_a_signal_that_arrived_in_the_same_instant() {
        // Linux checks `crng_ready()` before the interruptible wait returns, so
        // a caller whose bytes are available does not get ERESTARTSYS.
        assert_eq!(wait_step(true, true), Some(WaitOutcome::Ready));
    }

    #[test]
    fn a_signal_on_a_cold_pool_restarts() {
        assert_eq!(wait_step(false, true), Some(WaitOutcome::Restart));
    }

    #[test]
    fn a_cold_pool_with_no_signal_keeps_waiting() {
        // The load-bearing case: `None` means "park and re-check". If this
        // returned `Ready`, getrandom would hand out bytes from an
        // uninitialised pool — the behaviour the old always-seeded flag caused.
        assert_eq!(wait_step(false, false), None);
    }

    #[test]
    fn the_wait_poll_matches_linux_one_second_recheck() {
        assert_eq!(CRNG_WAIT_POLL_NS, 1_000_000_000);
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
