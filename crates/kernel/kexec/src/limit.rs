// The two per-image-type load limits (`kexec_load_limit_panic`,
// `kexec_load_limit_reboot`) and the rules that govern them.
//
// Ungated on purpose: both rules are pure arithmetic on one integer and both
// have a wrong answer that no boot would reveal — a limit that can be raised
// turns the whole mechanism into a suggestion, and a limit that decrements at
// zero wraps into "unlimited" at the exact moment it is supposed to refuse.
//
// `-1` means no limit. A limited counter is decremented once per PERMITTED
// load, not once per successful one: the resource being rationed is the
// attempt, so a load that goes on to fail validation still costs one.

/// `kexec_load_limit.limit == -1`: no limit.
pub const UNLIMITED: i64 = -1;

/// May `new` replace `cur` through `/proc/sys/kernel/kexec_load_limit_*`?
///
/// A limit may only ever become MORE restrictive. An unlimited counter accepts
/// any non-negative value; a limited one accepts only a strictly smaller one.
/// Negative writes are refused outright — `-1` is the initial state, not a
/// value userspace may restore.
/// # C: O(1)
pub fn limit_write_ok(cur: i64, new: i64) -> bool {
    if new < 0 { return false; }
    cur == UNLIMITED || new < cur
}

/// Consume one load from a limit.
///
/// `None` refuses the load (the limit is exhausted). `Some(next)` permits it
/// and gives the value to store back — unchanged when the counter is
/// unlimited, one lower otherwise.
/// # C: O(1)
pub fn limit_take(cur: i64) -> Option<i64> {
    if cur == UNLIMITED { return Some(UNLIMITED); }
    if cur <= 0 { return None; }
    Some(cur - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_limit_may_only_ever_tighten() {
        assert!(limit_write_ok(UNLIMITED, 0));
        assert!(limit_write_ok(UNLIMITED, 5));
        assert!(limit_write_ok(5, 4));
        // Raising it would let a process that already tightened the limit undo
        // its own restriction, which is the whole point of the counter.
        assert!(!limit_write_ok(5, 6));
        assert!(!limit_write_ok(5, 5));
        assert!(!limit_write_ok(0, 1));
    }

    #[test]
    fn a_limit_can_never_be_restored_to_unlimited() {
        // `-1` is the initial state, not a writable value: accepting it would
        // make every tightening reversible through the same file.
        assert!(!limit_write_ok(5, UNLIMITED));
        assert!(!limit_write_ok(UNLIMITED, UNLIMITED));
        assert!(!limit_write_ok(0, -7));
    }

    #[test]
    fn an_unlimited_counter_never_moves() {
        assert_eq!(limit_take(UNLIMITED), Some(UNLIMITED));
    }

    #[test]
    fn a_limited_counter_spends_exactly_its_budget() {
        let mut cur = 2i64;
        for _ in 0..2 {
            cur = limit_take(cur).expect("budget not yet spent");
        }
        assert_eq!(cur, 0);
        assert_eq!(limit_take(cur), None);
    }

    #[test]
    fn an_exhausted_counter_refuses_instead_of_wrapping() {
        // The failure this pins: decrementing at zero yields -1, the UNLIMITED
        // sentinel, so an exhausted limit would silently become no limit.
        assert_eq!(limit_take(0), None);
        assert_eq!(limit_take(0), None);
    }
}
