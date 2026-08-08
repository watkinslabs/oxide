// Emission rate limiting. A flood of records must not be able to exhaust
// memory or drown the consumer, so a configured per-second ceiling drops the
// excess — and every drop is counted, because the lost count is what tells
// userspace its log has a hole.
//
// Pure state machine: the caller supplies the clock, so the whole contract is
// driven by the hosted suite.

/// Rate-limiter state. One instance guards the whole record stream.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct RateState {
    /// Records admitted since the window opened.
    pub messages: u32,
    /// When the window last rolled over.
    pub last_check_ms: u64,
}

/// One second in the units the caller's clock reports.
pub const WINDOW_MS: u64 = 1000;

/// Whether one more record may be emitted.
///
/// A zero limit is no limit. Otherwise the counter is charged first and the
/// record passes while the window still has room; once the window is full the
/// record passes only if a whole second has elapsed, which also reopens the
/// window. That ordering is what makes the limiter self-clearing without a
/// timer: nothing resets the counter except an admitted record after the
/// window expired.
/// # C: O(1)
pub fn rate_check(st: &mut RateState, limit: u32, now_ms: u64) -> bool {
    if limit == 0 { return true; }
    st.messages = st.messages.saturating_add(1);
    if st.messages < limit { return true; }
    if now_ms > st.last_check_ms.saturating_add(WINDOW_MS) {
        st.last_check_ms = now_ms;
        st.messages = 0;
        return true;
    }
    false
}

/// Whether the "records were lost" warning may be printed again.
///
/// The lost counter is always incremented; the warning is throttled to one per
/// second unless there is no rate limit at all, or a failure mode that must be
/// noisy. Without that, the reaction to a flood would itself be a flood.
/// # C: O(1)
pub fn lost_print_check(last_msg_ms: &mut u64, rate_limit: u32, always_print: bool, now_ms: u64)
    -> bool
{
    if always_print || rate_limit == 0 { return true; }
    if now_ms > last_msg_ms.saturating_add(WINDOW_MS) { *last_msg_ms = now_ms; return true; }
    false
}

#[cfg(test)]
#[path = "tests/ratelimit.rs"]
mod tests;
