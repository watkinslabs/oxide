//! The writable controls: what each takes, what each refuses, and that a
//! refusal changes nothing.
//!
//! A knob that silently clamps is worse than one that refuses: the tool that
//! wrote it goes on believing the value it asked for is in force. Every bound
//! below is therefore checked from both sides.

use crate::bg::knobs::{self, Knob};
use crate::bg::state::Bg;
use crate::opts::{BackgroundGc, DiscardUnit};
use syscall::errno::Errno;

fn bg() -> Bg { Bg::new(BackgroundGc::On, DiscardUnit::Block, 1) }

#[test]
fn every_control_reads_back_what_was_written_to_it() {
    let b = bg();
    for &k in knobs::ALL {
        let v = 1u64;
        if knobs::accepts(k, v, true).is_err() { continue; }
        knobs::store(&b, k, v, true).unwrap();
        assert_eq!(knobs::show(&b, k), v, "{}", knobs::name(k));
    }
}

#[test]
fn max_small_discards_is_distinct_from_per_round_request_limit() {
    let b = bg();
    knobs::store(&b, Knob::MaxSmallDiscards, 0, false).unwrap();
    assert_eq!(knobs::show(&b, Knob::MaxSmallDiscards), 0);
    assert_eq!(b.dcc.lock().max_discard_request, 8);
    assert!(knobs::store(&b, Knob::MaxSmallDiscards, u64::from(u32::MAX) + 1, false).is_err());
}

#[test]
fn the_discard_granularity_refuses_zero_and_more_than_the_longest_list() {
    let b = bg();
    assert_eq!(knobs::store(&b, Knob::DiscardGranularity, 0, false), Err(Errno::Einval));
    assert_eq!(knobs::store(&b, Knob::DiscardGranularity, 513, false), Err(Errno::Einval));
    assert!(knobs::store(&b, Knob::DiscardGranularity, 512, false).is_ok());
    assert_eq!(knobs::show(&b, Knob::DiscardGranularity), 512);
}

#[test]
fn a_refused_write_leaves_the_control_where_it_was() {
    let b = bg();
    knobs::store(&b, Knob::DiscardGranularity, 32, false).unwrap();
    assert!(knobs::store(&b, Knob::DiscardGranularity, 0, false).is_err());
    assert_eq!(knobs::show(&b, Knob::DiscardGranularity), 32, "not clamped, not zeroed");
}

#[test]
fn the_yielding_threshold_may_be_zero_but_not_more_than_the_longest_list() {
    let b = bg();
    assert!(knobs::store(&b, Knob::DiscardIoAwareGran, 0, false).is_ok());
    assert_eq!(knobs::store(&b, Knob::DiscardIoAwareGran, 513, false), Err(Errno::Einval));
}

#[test]
fn the_urgent_utilisation_is_a_percentage() {
    let b = bg();
    assert!(knobs::store(&b, Knob::DiscardUrgentUtil, 100, false).is_ok());
    assert_eq!(knobs::store(&b, Knob::DiscardUrgentUtil, 101, false), Err(Errno::Einval));
}

#[test]
fn the_yielding_setting_is_one_of_two() {
    let b = bg();
    assert!(knobs::store(&b, Knob::DiscardIoAware, 0, false).is_ok());
    assert_eq!(b.dcc.lock().io_aware, crate::bg::IoAware::Disable);
    assert!(knobs::store(&b, Knob::DiscardIoAware, 1, false).is_ok());
    assert_eq!(knobs::store(&b, Knob::DiscardIoAware, 2, false), Err(Errno::Einval));
}

#[test]
fn no_interval_may_be_zero() {
    // A thread that never sleeps is a filesystem that spends a core on
    // housekeeping.
    let b = bg();
    for k in [Knob::GcMinSleepTime, Knob::GcMaxSleepTime, Knob::GcNoGcSleepTime,
              Knob::GcUrgentSleepTime, Knob::MinDiscardIssueTime, Knob::MidDiscardIssueTime,
              Knob::MaxDiscardIssueTime, Knob::MaxDiscardRequest] {
        assert_eq!(knobs::store(&b, k, 0, false), Err(Errno::Einval), "{}", knobs::name(k));
    }
}

#[test]
fn the_urgency_control_sets_the_mode_and_wakes_the_cleaner() {
    let b = bg();
    let before = b.waits.gc_wakes();
    knobs::store(&b, Knob::GcUrgent, 1, false).unwrap();
    assert_eq!(b.gc_mode(), crate::bg::GcMode::UrgentHigh);
    assert!(b.gc.lock().gc_wake, "the pass was asked for, not merely enabled");
    assert!(b.waits.gc_wakes() > before, "and the cleaner was woken to take it");
}

#[test]
fn the_high_urgency_also_wakes_the_discard_thread() {
    // Urgent cleaning frees segments; the device only learns about them when
    // the discard thread runs, so leaving it asleep would hide the result.
    let b = bg();
    let before = b.waits.discard_wakes();
    knobs::store(&b, Knob::GcUrgent, 1, false).unwrap();
    assert!(b.waits.discard_wakes() > before);
}

#[test]
fn the_low_urgency_does_not_wake_anything() {
    let b = bg();
    let before = b.waits.gc_wakes();
    knobs::store(&b, Knob::GcUrgent, 2, false).unwrap();
    assert_eq!(b.gc_mode(), crate::bg::GcMode::UrgentLow);
    assert_eq!(b.waits.gc_wakes(), before, "it is a claim about idleness, not a request");
}

#[test]
fn turning_urgency_off_puts_the_cleaner_back_to_normal() {
    let b = bg();
    knobs::store(&b, Knob::GcUrgent, 1, false).unwrap();
    knobs::store(&b, Knob::GcUrgent, 0, false).unwrap();
    assert_eq!(b.gc_mode(), crate::bg::GcMode::Normal);
    assert_eq!(knobs::show(&b, Knob::GcUrgent), 0);
}

#[test]
fn the_urgency_control_refuses_a_number_that_names_no_mode() {
    let b = bg();
    assert_eq!(knobs::store(&b, Knob::GcUrgent, 4, false), Err(Errno::Einval));
    assert_eq!(b.gc_mode(), crate::bg::GcMode::Normal);
}

#[test]
fn the_ageing_cost_needs_a_volume_mounted_for_it() {
    // Without the ageing table the mode has no data to weigh, so accepting it
    // would leave the cleaner claiming a policy it cannot apply.
    let b = bg();
    let at = u64::from(crate::bg::GcMode::IdleAt.as_u32());
    assert_eq!(knobs::store(&b, Knob::GcIdle, at, false), Err(Errno::Einval));
    assert!(knobs::store(&b, Knob::GcIdle, at, true).is_ok());
    assert_eq!(b.gc_mode(), crate::bg::GcMode::IdleAt);
}

#[test]
fn the_idle_control_takes_the_two_costs() {
    let b = bg();
    knobs::store(&b, Knob::GcIdle, 1, false).unwrap();
    assert_eq!(b.gc_mode(), crate::bg::GcMode::IdleCb);
    knobs::store(&b, Knob::GcIdle, 2, false).unwrap();
    assert_eq!(b.gc_mode(), crate::bg::GcMode::IdleGreedy);
}

#[test]
fn a_written_number_may_carry_the_newline_a_shell_adds() {
    assert_eq!(knobs::parse_value(b"64\n"), Ok(64));
    assert_eq!(knobs::parse_value(b"  64 "), Ok(64));
    assert_eq!(knobs::parse_value(b"64"), Ok(64));
    assert_eq!(knobs::parse_value(b""), Err(Errno::Einval));
    assert_eq!(knobs::parse_value(b"sixty-four"), Err(Errno::Einval));
    assert_eq!(knobs::parse_value(b"-1"), Err(Errno::Einval));
}

#[test]
fn every_control_has_a_distinct_name() {
    let mut seen = alloc::vec::Vec::new();
    for &k in knobs::ALL {
        let n = knobs::name(k);
        assert!(!seen.contains(&n), "{n} is published twice");
        seen.push(n);
    }
    assert_eq!(seen.len(), knobs::ALL.len());
}

#[test]
fn a_turned_control_reaches_the_policy_that_reads_it() {
    // The point of the knob is not the field: it is that a round behaves
    // differently afterwards.
    let b = bg();
    b.dcc.lock().extend([(100, 4)]);
    let strict = {
        let d = b.dcc.lock();
        d.init_policy(crate::bg::DiscardType::Bg, d.granularity, 0)
    };
    assert_eq!(strict.granularity, 16, "a four-block run is below the default");
    knobs::store(&b, Knob::DiscardGranularity, 1, false).unwrap();
    let loose = {
        let d = b.dcc.lock();
        d.init_policy(crate::bg::DiscardType::Bg, d.granularity, 0)
    };
    let round = b.dcc.lock().issue_round(&loose, true);
    assert_eq!(round.runs, alloc::vec![(100, 4)], "now the run is worth announcing");
}

/// The ahead-of-demand search bound written through the knob is the one the
/// search itself is given.
#[test]
fn the_victim_search_bound_reaches_the_search() {
    let b = bg();
    assert_eq!(knobs::show(&b, Knob::MaxVictimSearch),
               u64::from(crate::volume::gc::victim::DEF_MAX_VICTIM_SEARCH));
    knobs::store(&b, Knob::MaxVictimSearch, 7, true).expect("accepted");
    assert_eq!(b.gc.lock().max_victim_search, 7);
    assert_eq!(knobs::show(&b, Knob::MaxVictimSearch), 7);
    // Zero would cost nothing and settle for nothing, so a pass with it set
    // would never find a victim at all.
    assert_eq!(knobs::store(&b, Knob::MaxVictimSearch, 0, true), Err(Errno::Einval));
    assert_eq!(b.gc.lock().max_victim_search, 7, "a refusal changed it");
}
