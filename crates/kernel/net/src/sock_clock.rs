// Monotonic clock + SO_RCVTIMEO/SO_SNDTIMEO deadline arithmetic for the
// socket wait layer. Owned here rather than inside the blocking receive
// machinery so a deadline decision is reachable without a kernel target:
// `sock_wait` needs the same reading on every build that can park.

/// Monotonic nanoseconds. Kernel builds read the arch timer; host builds read
/// the host's own monotonic clock, so a deadline computed hosted advances for
/// the same reason it does on hardware.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn monotonic_ns_safe() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { return hal_x86_64::X86TimerOps::monotonic_ns().0; }
    #[cfg(target_arch = "aarch64")]
    { return hal_aarch64::ArmTimerOps::monotonic_ns().0; }
    #[allow(unreachable_code)]
    0
}

/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn monotonic_ns_safe() -> u64 {
    use std::sync::OnceLock;
    use std::time::Instant;
    static BASE: OnceLock<Instant> = OnceLock::new();
    let base = BASE.get_or_init(Instant::now);
    // A monotonic reading of 0 means "no clock" to every caller below, so the
    // host baseline starts at 1ns rather than at the instant it was taken.
    base.elapsed().as_nanos().saturating_add(1) as u64
}

/// Convert a `SO_RCVTIMEO` / `SO_SNDTIMEO` nanosecond value into an absolute
/// monotonic deadline. `0` (no timeout configured) → `0` (indefinite wait).
/// Saturating add prevents wrap.
/// # C: O(1)
pub fn compute_deadline_ns(timeo_ns: i64) -> u64 {
    if timeo_ns <= 0 { return 0; }
    let now = monotonic_ns_safe();
    if now == 0 { return 0; }
    now.saturating_add(timeo_ns as u64)
}

/// True once `deadline_ns` has passed. A `0` deadline never expires.
/// # C: O(1)
pub fn deadline_expired(deadline_ns: u64) -> bool {
    deadline_ns != 0 && monotonic_ns_safe() >= deadline_ns
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_timeout_is_an_indefinite_wait() {
        assert_eq!(compute_deadline_ns(0), 0);
        assert_eq!(compute_deadline_ns(-1), 0);
    }

    #[test]
    fn a_positive_timeout_produces_a_future_deadline() {
        let now = monotonic_ns_safe();
        let d = compute_deadline_ns(1_000_000_000);
        assert!(d > now, "deadline {d} must be past the reading {now} it was taken from");
    }

    #[test]
    fn a_zero_deadline_never_expires() {
        assert!(!deadline_expired(0));
    }

    #[test]
    fn a_past_deadline_is_expired() {
        assert!(deadline_expired(1));
    }
}
