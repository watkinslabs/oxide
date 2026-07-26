use core::sync::atomic::Ordering;

#[test]
fn rlimit_clamp_pair_accepts_cur_le_max() {
    use crate::rlimit::clamp_pair;
    assert_eq!(clamp_pair(0, 100), Some((0, 100)));
    assert_eq!(clamp_pair(50, 100), Some((50, 100)));
    assert_eq!(clamp_pair(100, 100), Some((100, 100)));
    assert_eq!(clamp_pair(0, 0), Some((0, 0)));
}

#[test]
fn rlimit_clamp_pair_rejects_cur_above_max() {
    use crate::rlimit::clamp_pair;
    assert_eq!(clamp_pair(101, 100), None);
    assert_eq!(clamp_pair(1, 0), None);
}

#[test]
fn rlimit_validate_setrlimit_round_trip() {
    use crate::rlimit::validate_setrlimit;
    let old = (10, 100);
    assert_eq!(validate_setrlimit(old, (5, 50)), Ok((5, 50)));
    assert_eq!(validate_setrlimit(old, (50, 200)), Ok((50, 200)));
    assert_eq!(validate_setrlimit(old, (51, 50)), Err(()));
}

#[test]
fn rlimit_format_unlimited() {
    use crate::rlimit::{format_rlim, INFINITY};
    let mut b = [0u8; 16];
    let n = format_rlim(&mut b, INFINITY).unwrap();
    assert_eq!(&b[..n], b"unlimited");
}

#[test]
fn rlimit_format_decimal() {
    use crate::rlimit::format_rlim;
    let mut b = [0u8; 16];
    assert_eq!(format_rlim(&mut b, 0).unwrap(), 1);
    assert_eq!(&b[..1], b"0");
    let n = format_rlim(&mut b, 1024).unwrap();
    assert_eq!(&b[..n], b"1024");
    let n = format_rlim(&mut b, 8388608).unwrap();
    assert_eq!(&b[..n], b"8388608");
}

#[test]
fn rlimit_format_buf_too_small_returns_none() {
    use crate::rlimit::{format_rlim, INFINITY};
    let mut b = [0u8; 3];
    assert_eq!(format_rlim(&mut b, INFINITY), None);
    assert_eq!(format_rlim(&mut b, 99999), None);
}

#[test]
fn rlimit_indices_match_linux_layout() {
    use crate::rlimit::rlim;
    assert_eq!(rlim::CPU, 0);
    assert_eq!(rlim::NOFILE, 7);
    assert_eq!(rlim::AS, 9);
    assert_eq!(rlim::NICE, 13);
    assert_eq!(rlim::COUNT, 16);
}

#[test]
fn clamp_nice_saturates_below_minus_20() {
    use crate::rlimit::clamp_nice;
    assert_eq!(clamp_nice(-100), -20);
    assert_eq!(clamp_nice(-21), -20);
}

#[test]
fn clamp_nice_saturates_above_19() {
    use crate::rlimit::clamp_nice;
    assert_eq!(clamp_nice(20), 19);
    assert_eq!(clamp_nice(100), 19);
}

#[test]
fn clamp_nice_passes_through_in_range() {
    use crate::rlimit::clamp_nice;
    assert_eq!(clamp_nice(-20), -20);
    assert_eq!(clamp_nice(0), 0);
    assert_eq!(clamp_nice(19), 19);
}

#[test]
fn settimeofday_offset_satisfies_apply() {
    use crate::clock::{apply_offset, settimeofday_offset};
    let mono = 1_000_000_000u64;
    let target = 1_700_000_000_000_000_000u64;
    let off = settimeofday_offset(mono, target);
    assert_eq!(apply_offset(mono, off), target);
}

#[test]
fn settimeofday_offset_zero_when_target_eq_mono() {
    use crate::clock::settimeofday_offset;
    assert_eq!(settimeofday_offset(42, 42), 0);
}

#[test]
fn settimeofday_offset_wraps_when_target_below_mono() {
    use crate::clock::{apply_offset, settimeofday_offset};
    let mono = 1_000u64;
    let target = 100u64;
    let off = settimeofday_offset(mono, target);
    assert_eq!(apply_offset(mono, off), target);
}

#[test]
fn ns_to_clk_tck_100hz() {
    use crate::clock::ns_to_clk_tck;
    assert_eq!(ns_to_clk_tck(0), 0);
    assert_eq!(ns_to_clk_tck(10_000_000), 1);
    assert_eq!(ns_to_clk_tck(1_000_000_000), 100);
    assert_eq!(ns_to_clk_tck(1_234_567_890), 123);
}

#[test]
fn ns_to_timespec_split() {
    use crate::clock::ns_to_timespec;
    assert_eq!(ns_to_timespec(0), (0, 0));
    assert_eq!(ns_to_timespec(1_500_000_000), (1, 500_000_000));
    assert_eq!(ns_to_timespec(999_999_999), (0, 999_999_999));
}

#[test]
fn ns_to_timeval_split() {
    use crate::clock::ns_to_timeval;
    assert_eq!(ns_to_timeval(0), (0, 0));
    assert_eq!(ns_to_timeval(1_500_000_000), (1, 500_000));
    assert_eq!(ns_to_timeval(1_999_999), (0, 1_999));
}

#[test]
fn preempt_count_default_zero() {
    crate::preempt::_test_reset();
    assert_eq!(crate::preempt::preempt_count(), 0);
    assert!(!crate::preempt::need_resched());
}

#[test]
fn preempt_disable_bumps_count() {
    crate::preempt::_test_reset();
    crate::preempt::preempt_disable();
    assert_eq!(crate::preempt::preempt_count(), 1);
    crate::preempt::preempt_enable_no_check();
    assert_eq!(crate::preempt::preempt_count(), 0);
}

#[test]
fn preempt_guard_pairs_balanced() {
    crate::preempt::_test_reset();
    {
        let _g = crate::preempt::PreemptGuard::new();
        assert_eq!(crate::preempt::preempt_count(), 1);
        let _g2 = crate::preempt::PreemptGuard::new();
        assert_eq!(crate::preempt::preempt_count(), 2);
    }
    assert_eq!(crate::preempt::preempt_count(), 0);
}

#[test]
fn need_resched_set_take_clears() {
    crate::preempt::_test_reset();
    crate::preempt::set_need_resched();
    assert!(crate::preempt::need_resched());
    assert!(crate::preempt::take_need_resched());
    assert!(!crate::preempt::need_resched());
    assert!(!crate::preempt::take_need_resched());
}

#[test]
fn preempt_enable_no_check_does_not_fire_hook() {
    crate::preempt::_test_reset();
    crate::preempt::preempt_disable();
    crate::preempt::set_need_resched();
    crate::preempt::preempt_enable_no_check();
    assert!(crate::preempt::need_resched());
}

#[test]
fn should_resched_only_when_requested_and_safe() {
    crate::preempt::_test_reset();
    assert!(!crate::preempt::should_resched(), "no request => false");
    crate::preempt::set_need_resched();
    assert!(crate::preempt::should_resched(), "requested + count 0 => true");
    crate::preempt::preempt_disable();
    assert!(!crate::preempt::should_resched(), "preempt-disabled => unsafe => false");
    crate::preempt::preempt_enable_no_check();
    assert!(crate::preempt::should_resched(), "re-enabled => true again");
    assert!(crate::preempt::need_resched(), "should_resched must not clear the flag");
    crate::preempt::_test_reset();
}

#[test]
fn should_resched_to_user_is_voluntary() {
    crate::preempt::_test_reset();
    crate::preempt::set_need_resched();
    assert!(crate::preempt::should_resched_to_user(true), "user + pending => resched");
    assert!(!crate::preempt::should_resched_to_user(false), "kernel => never (VOLUNTARY)");
    crate::preempt::_test_reset();
    assert!(!crate::preempt::should_resched_to_user(true), "no request => false even from user");
}

#[test]
fn switch_handoff_balances_preempt_count() {
    crate::preempt::_test_reset();
    assert_eq!(crate::preempt::preempt_count(), 0);
    crate::preempt::preempt_disable();
    assert_eq!(crate::preempt::preempt_count(), 1);
    crate::preempt::preempt_enable_no_check();
    assert_eq!(crate::preempt::preempt_count(), 0, "handoff net 0 per switch");
}

#[test]
#[should_panic(expected = "underflow")]
fn switch_handoff_underflow_guarded() {
    crate::preempt::_test_reset();
    crate::preempt::preempt_enable_no_check();
}

#[test]
fn call_rcu_callback_runs_after_grace_period() {
    use alloc::boxed::Box;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicBool, AtomicU32};

    static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());

    let ran = Arc::new(AtomicBool::new(false));
    let n = Arc::new(AtomicU32::new(0));
    let (r2, n2) = (ran.clone(), n.clone());
    crate::call_rcu(Box::new(move || { r2.store(true, Ordering::Release); n2.fetch_add(1, Ordering::AcqRel); }));

    crate::rcu_process_callbacks();
    assert!(!ran.load(Ordering::Acquire), "callback ran before any quiescent state");
    for _ in 0..6 {
        crate::rcu_note_qs();
        crate::rcu_process_callbacks();
    }
    assert!(ran.load(Ordering::Acquire), "callback runs after a grace period");
    assert_eq!(n.load(Ordering::Acquire), 1, "callback ran exactly once (no leak / no double-run)");
    crate::synchronize_rcu();
}

/// `06§3.1`: the hard-IRQ tick paths must not touch the global task registry.
///
/// `REG` is a plain `Spinlock` that fork/exit/execve hold with IRQs enabled, so
/// a tick landing on a holder wedges that CPU permanently — measured as an idle
/// CPU stuck at `preempt_count=0x10000`, unable to drain softirqs or reschedule.
///
/// The regression this pins: process-wide POSIX timer slots used to live on the
/// group *leader's* `Task`, so every access resolved the leader through
/// `registry::lookup` — on every tick, for any thread that is not its own
/// leader. They now live on `ThreadGroup`, which every member already holds an
/// `Arc` to. Linux keeps the same state in `signal_struct` for the same reason.
#[test]
fn hardirq_tick_paths_perform_no_registry_lookup() {
    use core::sync::atomic::Ordering;
    let _g = crate::tests::common::registry_test_lock();
    crate::registry::clear_for_tests();

    let leader = alloc::sync::Arc::new(crate::Task::new(0x7100, "leader", crate::SchedClass::Normal { weight: 1024 }));
    leader.tgid.store(0x7100, Ordering::Release);
    crate::registry::insert(&leader);
    // A non-leader thread: the case that used to force the lookup.
    let thread = alloc::sync::Arc::new(crate::Task::new(0x7101, "thread", crate::SchedClass::Normal { weight: 1024 }));
    thread.tgid.store(0x7100, Ordering::Release);
    crate::registry::insert(&thread);

    let before = crate::registry::LOOKUPS.load(Ordering::Relaxed);
    crate::timers::account_cpu_tick(&thread);
    let after = crate::registry::LOOKUPS.load(Ordering::Relaxed);
    assert_eq!(after, before,
        "account_cpu_tick performed {} registry lookup(s) from hard-IRQ context",
        after - before);
}

/// `preempt_count` must travel WITH the task, not stay on the CPU.
///
/// The regression this pins: the count was per-CPU and never swapped, so a task
/// that parked inside `do_softirq` — between the `SOFTIRQ_OFFSET` add and its
/// matching sub — left the softirq field set for whatever ran next on that CPU.
/// `in_interrupt()` then reported true there forever, so that CPU silently
/// stopped draining softirqs and stopped rescheduling, and the eventual
/// `preempt_count_sub` underflowed. Measured as an idle CPU pinned at
/// `preempt_count=0x00010000` with nothing runnable.
///
/// Linux keeps it in `thread_info`; x86 caches it per-CPU and swaps it in
/// `__switch_to`, which is the model here.
#[test]
fn preempt_count_travels_with_the_task_across_a_switch() {
    use core::sync::atomic::Ordering;
    use crate::preempt::{preempt_count, preempt_count_swap, SOFTIRQ_OFFSET};

    let parked = alloc::sync::Arc::new(crate::Task::new(
        0x7200, "parked", crate::SchedClass::Normal { weight: 1024 }));
    let fresh = alloc::sync::Arc::new(crate::Task::new(
        0x7201, "fresh", crate::SchedClass::Normal { weight: 1024 }));

    // A task parked mid-drain: preempt-off plus an in-progress softirq.
    let mid_drain = crate::preempt::PREEMPT_DISABLED + SOFTIRQ_OFFSET;
    parked.preempt_count.store(mid_drain, Ordering::Release);

    // Switch TO the parked task: the CPU picks up its count...
    let outgoing = preempt_count_swap(parked.preempt_count.load(Ordering::Acquire));
    assert_eq!(preempt_count(), mid_drain, "incoming task's count must become live");

    // ...and switching away hands it back to that task, not to the next one.
    let live = preempt_count_swap(fresh.preempt_count.load(Ordering::Acquire));
    parked.preempt_count.store(live, Ordering::Release);
    assert_eq!(parked.preempt_count.load(Ordering::Acquire), mid_drain,
        "the parked task must carry its own softirq field away with it");
    assert_eq!(preempt_count(), crate::preempt::PREEMPT_DISABLED,
        "the incoming task must NOT inherit the previous task's softirq field");

    // Restore whatever the harness was at so sibling tests are unaffected.
    preempt_count_swap(outgoing);
}
