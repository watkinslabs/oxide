// TLB-shootdown round bookkeeping — the DECISION half, with no target gate so
// every rule is host-unit-tested. `tlb.rs` is the mechanism; it is
// `#![cfg(target_os = "oxide-kernel")]` AND declared under an x86-only `cfg` in
// the crate manifest, so a test module living there would be compiled out
// silently while `cargo test` still printed "ok".
//
// Linux serialises a cross-CPU call per TARGET with the per-CPU `csd` lock
// (`kernel/smp.c` `csd_lock`/`csd_unlock`): a second call to the same CPU
// cannot start until the first completes, so an ACK can never be credited to
// the wrong request. This port has ONE global in-flight slot instead, so the
// same guarantee has to be carried explicitly by a round id.

/// Advance to the next round id. Wrapping is deliberate and harmless: the test
/// is equality against the id a target read moments earlier, not ordering.
/// # C: O(1)
pub fn next_round(cur: u64) -> u64 { cur.wrapping_add(1) }

/// Whether an ACK for the round a target READ may be applied to the round that
/// is live NOW. Rejecting the mismatch is what stops a target that was still
/// inside `service()` when a round was torn down from clearing its bit in the
/// NEXT round having flushed the PREVIOUS round's VA — the owner would then see
/// `PENDING == 0` and free a frame the peer still has cached.
/// # C: O(1)
pub fn ack_valid(round_read: u64, round_now: u64) -> bool { round_read == round_now }

/// Drop a target that could not be IPI'd (no hardware id for its logical id)
/// from the pending set. It was never told to flush, so waiting on it is a
/// guaranteed hang for an ACK that cannot arrive; and it cannot hold a stale
/// translation for an mm it was never able to run, because a CPU with no
/// hardware id is not a CPU this kernel ever scheduled on.
/// # C: O(1)
pub fn drop_unreachable(pending: u64, cpu: u32) -> u64 {
    if cpu >= 64 { return pending; }
    pending & !(1u64 << cpu)
}

/// Whether the stuck-wait escalation is due. Linux's `csd_lock_wait_toolong`
/// keys purely on `ktime_get_mono_fast_ns()`; this port also has to survive the
/// window where the TSC is not yet calibrated and `monotonic_ns()` reports 0,
/// so the spin count is the fallback measure. Losing the diagnostic entirely is
/// the one outcome the escalation exists to prevent.
/// # C: O(1)
pub fn escalation_due(now_ns: u64, next_warn_ns: u64, spins: u64, next_warn_spins: u64) -> bool {
    if now_ns != 0 { now_ns.wrapping_sub(next_warn_ns) as i64 >= 0 } else { spins >= next_warn_spins }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_ack_for_a_torn_down_round_is_refused() {
        assert!(ack_valid(7, 7));
        assert!(!ack_valid(7, next_round(7)), "late ACK must not credit the next round");
        assert!(!ack_valid(7, 9));
        // Wrapping is a legal round id, not a special case.
        assert_eq!(next_round(u64::MAX), 0);
        assert!(ack_valid(0, next_round(u64::MAX)));
    }

    #[test]
    fn an_un_ipid_target_leaves_the_pending_set() {
        assert_eq!(drop_unreachable(0b1011, 1), 0b1001);
        assert_eq!(drop_unreachable(0b1011, 2), 0b1011, "clearing a clear bit is a no-op");
        assert_eq!(drop_unreachable(0b1011, 64), 0b1011, "out-of-range never touches the mask");
        assert_eq!(drop_unreachable(0b1011, u32::MAX), 0b1011);
    }

    #[test]
    fn escalation_uses_the_clock_when_it_runs_and_spins_when_it_does_not() {
        // Calibrated clock: spins are ignored entirely.
        assert!(!escalation_due(500, 1_000, u64::MAX, 10));
        assert!(escalation_due(1_000, 1_000, 0, u64::MAX));
        assert!(escalation_due(1_001, 1_000, 0, u64::MAX));
        // Uncalibrated (`monotonic_ns() == 0`): the spin count decides.
        assert!(!escalation_due(0, 1_000, 9, 10));
        assert!(escalation_due(0, 1_000, 10, 10));
    }

    #[test]
    fn a_clock_that_wraps_does_not_suppress_the_escalation() {
        // `next_warn` computed just below the u64 boundary; `now` has wrapped
        // past it. A plain `>=` on the raw values would read as "not due yet"
        // and the escalation would be lost for one full wrap.
        let next_warn = u64::MAX - 10;
        assert!(escalation_due(5, next_warn, 0, u64::MAX));
        assert!(!escalation_due(u64::MAX - 20, next_warn, 0, u64::MAX));
    }
}
