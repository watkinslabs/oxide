// Shared timespec→ns ABI conversion per docs/15, Linux `include/linux/ktime.h`
// `ktime_set`. Every syscall that decodes a user `{ tv_sec, tv_nsec }` pair
// into a nanosecond count (relative duration OR absolute deadline — futex
// WAIT/WAIT_BITSET/waitv, timerfd_settime, clock_nanosleep, nanosleep, ppoll,
// pselect6/select, epoll_pwait2, rt_sigtimedwait) must go through
// `timespec_to_ns` rather than reinventing `secs * NSEC_PER_SEC + nsec`
// inline: a bare `saturating_mul`/`saturating_add` over u64 accepts any
// non-negative `tv_sec` up to `u64::MAX/1e9` (~584 billion years) with no
// upper bound, which real Linux does NOT allow — `ktime_set` clamps to
// `KTIME_MAX` (`i64::MAX` ns, ~292 years) the moment `tv_sec >= KTIME_SEC_MAX`
// specifically so no absolute deadline can exceed what `ktime_t` (a signed
// 64-bit ns count) can represent. Without this clamp, a malformed or
// corrupted absolute timespec (`TFD_TIMER_ABSTIME`/`FUTEX_WAIT_BITSET`/
// `TIMER_ABSTIME`) can install a `wakeup_deadline_ns` far beyond anything
// Linux could ever produce — observed as a task with a
// `wakeup_deadline_ns` of ~527 years that the deadline scanner
// (`sched::live::tick_deadline::tick_wake_expired`) can never reach.

use crate::errno::Errno;

/// Nanoseconds per second — the sole owner of this ABI conversion constant
/// for every timespec-consuming syscall (`07§5`: named constant, not an
/// inline literal repeated per call site).
pub const NSEC_PER_SEC: u64 = 1_000_000_000;

/// Linux `KTIME_MAX` — the largest ns count a signed 64-bit `ktime_t` can
/// hold. `ktime_set` clamps to this rather than overflow.
pub const KTIME_MAX_NS: u64 = i64::MAX as u64;

/// Linux `KTIME_SEC_MAX` — `KTIME_MAX / NSEC_PER_SEC`. `tv_sec` at or above
/// this clamps the whole conversion to `KTIME_MAX_NS`.
pub const KTIME_SEC_MAX: u64 = KTIME_MAX_NS / NSEC_PER_SEC;

/// Decode one user `{ tv_sec, tv_nsec }` pair into nanoseconds, Linux
/// `ktime_set` semantics: `tv_sec < 0`, `tv_nsec` outside `[0, NSEC_PER_SEC)`
/// is `EINVAL`; a `tv_sec >= KTIME_SEC_MAX` clamps to `KTIME_MAX_NS` instead
/// of overflowing/misrepresenting the deadline. Callers add this to a
/// monotonic "now" (relative) or fold it against another clock's "now"
/// (absolute) — this function only owns the raw decode + range clamp.
/// # C: O(1)
pub fn timespec_to_ns(secs: i64, nsec: i64) -> Result<u64, Errno> {
    if secs < 0 || nsec < 0 || nsec >= NSEC_PER_SEC as i64 {
        return Err(Errno::Einval);
    }
    if secs as u64 >= KTIME_SEC_MAX {
        return Ok(KTIME_MAX_NS);
    }
    Ok((secs as u64) * NSEC_PER_SEC + nsec as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typical_relative_value_round_trips_exactly() {
        assert_eq!(timespec_to_ns(5, 500_000_000), Ok(5_500_000_000));
        assert_eq!(timespec_to_ns(0, 0), Ok(0));
    }

    #[test]
    fn negative_seconds_or_out_of_range_nanoseconds_is_einval() {
        assert_eq!(timespec_to_ns(-1, 0), Err(Errno::Einval));
        assert_eq!(timespec_to_ns(0, -1), Err(Errno::Einval));
        assert_eq!(timespec_to_ns(0, 1_000_000_000), Err(Errno::Einval));
        assert_eq!(timespec_to_ns(0, i64::MAX), Err(Errno::Einval));
    }

    #[test]
    fn huge_tv_sec_clamps_to_ktime_max_instead_of_wrapping_past_it() {
        // The exact magnitude this lane's bug report observed: a ~527-year
        // absolute deadline (tv_sec ~16.66e9) must clamp to KTIME_MAX_NS
        // (~292 years), never propagate past a real ktime_t's range.
        assert_eq!(timespec_to_ns(16_661_643_624, 155_194_468), Ok(KTIME_MAX_NS));
        assert_eq!(timespec_to_ns(i64::MAX, 0), Ok(KTIME_MAX_NS));
    }

    #[test]
    fn boundary_seconds_at_and_below_ktime_sec_max() {
        assert_eq!(timespec_to_ns(KTIME_SEC_MAX as i64, 0), Ok(KTIME_MAX_NS));
        let below = KTIME_SEC_MAX - 1;
        assert_eq!(timespec_to_ns(below as i64, 999_999_999),
            Ok(below * NSEC_PER_SEC + 999_999_999));
    }
}
