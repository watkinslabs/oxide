//! Preempt-count ownership at the context-switch handoff.

#[cfg(feature = "debug-preempt")]
use core::sync::atomic::{AtomicBool, Ordering};

use crate::preempt;
#[cfg(feature = "debug-preempt")]
use super::super::runqueue::global;

#[cfg(feature = "debug-preempt")]
static ENTRY_REPORTED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "debug-preempt")]
static FINISH_REPORTED: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "debug-preempt")]
fn cpu() -> usize {
    use hal::CpuOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86CpuOps::current_cpu() as usize }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmCpuOps::current_cpu() as usize }
}

#[cfg(feature = "debug-preempt")]
fn identity() {
    klog::write_raw(b" cpu=");
    klog::write_dec_u64(cpu() as u64);
    klog::write_raw(b" tid=");
    klog::write_dec_u64(super::current().map_or(0, |task| task.tid) as u64);
    klog::write_raw(b" count=0x");
    klog::write_hex_u64(preempt::preempt_count() as u64);
    klog::write_raw(b" handoff=");
    klog::write_dec_u64(global().is_some_and(|rq|
        !rq.switched_from.load(Ordering::Acquire).is_null()) as u64);
    sync::preempt_gate::write_held_stack();
}

/// Schedule must enter from base count zero. Report the first orphan credit
/// before the entry increment obscures which side of the pair was missing.
pub(super) fn schedule_entry() {
    #[cfg(feature = "debug-preempt")]
    {
        if preempt::preempt_count() == 0
            || ENTRY_REPORTED.swap(true, Ordering::AcqRel)
        {
            return;
        }
        klog::write_raw(b"[PREEMPT-PROVENANCE] schedule-entry");
        identity();
        klog::write_raw(b"\n");
    }
}

/// A real switch reaches its incoming tail with exactly the scheduler and
/// forgotten-rq credits. Snapshot all three transition points once if not.
pub(super) fn finish(stage: &[u8], expected: u32) {
    #[cfg(feature = "debug-preempt")]
    {
        if preempt::preempt_count() == expected
            || FINISH_REPORTED.swap(true, Ordering::AcqRel)
        {
            return;
        }
        klog::write_raw(b"[PREEMPT-PROVENANCE] finish stage=");
        klog::write_raw(stage);
        klog::write_raw(b" expected=0x");
        klog::write_hex_u64(expected as u64);
        identity();
        klog::write_raw(b"\n");
    }
    #[cfg(not(feature = "debug-preempt"))]
    { let _ = (stage, expected); }
}

/// Linux 7.2-rc4 `finish_task_switch` requires count two here: schedule's
/// entry disable plus the forgotten rq-lock credit. Its WARN recovery resets
/// `preempt_count` to `FORK_PREEMPT_COUNT` before `finish_lock_switch`.
/// Doing the same prevents a malformed count one from letting rq unlock steal
/// schedule's credit and the following release underflow into unrelated BH
/// ownership. This boundary owns only switch debt; ordinary guard releases
/// remain checked independently before they reach it. # C: O(1)
pub(super) fn normalize_finish() {
    const FINISH_COUNT: u32 = 2 * preempt::PREEMPT_DISABLED;
    let observed = preempt::preempt_count();
    if observed == FINISH_COUNT { return; }
    finish(b"before-normalize", FINISH_COUNT);
    preempt::preempt_count_set(FINISH_COUNT);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_one_is_normalized_before_rq_release() {
        preempt::_test_reset();
        preempt::preempt_count_set(1);
        normalize_finish();
        assert_eq!(preempt::preempt_count(), 2);
        preempt::_test_reset();
    }

    #[test]
    fn malformed_zero_is_normalized_before_rq_release() {
        preempt::_test_reset();
        normalize_finish();
        assert_eq!(preempt::preempt_count(), 2);
        preempt::_test_reset();
    }

    #[test]
    fn correct_finish_count_is_preserved() {
        preempt::_test_reset();
        preempt::preempt_count_set(2);
        normalize_finish();
        assert_eq!(preempt::preempt_count(), 2);
        preempt::_test_reset();
    }

    #[test]
    fn ordinary_guard_credit_is_not_repaired_at_schedule_entry() {
        preempt::_test_reset();
        preempt::install_spinlock_gate();
        let lock = sync::Spinlock::<(), sync::Buddy>::new(());
        let guard = lock.lock();
        assert_eq!(preempt::preempt_count(), 1);
        schedule_entry();
        assert_eq!(preempt::preempt_count(), 1,
            "diagnosis outside a switch handoff must not rewrite guard ownership");
        drop(guard);
        assert_eq!(preempt::preempt_count(), 0);
    }
}
