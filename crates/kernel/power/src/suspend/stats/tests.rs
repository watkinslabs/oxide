use super::*;

#[test]
fn a_success_records_no_errno() {
    let s = SuspendStats::new();
    s.save_errno(0);
    assert_eq!((s.success(), s.fail()), (1, 0));
    assert_eq!(s.last_failed_errno(), 0);
}

#[test]
fn a_failure_records_its_errno() {
    let s = SuspendStats::new();
    s.save_errno(-16);
    assert_eq!((s.success(), s.fail()), (0, 1));
    assert_eq!(s.last_failed_errno(), -16);
}

#[test]
fn the_errno_ring_keeps_the_newest() {
    let s = SuspendStats::new();
    for e in [-1, -2, -3] { s.save_errno(e); }
    assert_eq!(s.last_failed_errno(), -3);
    assert_eq!(s.fail(), 3);
}

#[test]
fn step_failures_count_per_step_and_name_the_newest() {
    let s = SuspendStats::new();
    s.save_failed_step(StatStep::Freeze);
    s.save_failed_step(StatStep::Freeze);
    s.save_failed_step(StatStep::SuspendNoirq);
    assert_eq!(s.step_failures(StatStep::Freeze), 2);
    assert_eq!(s.step_failures(StatStep::SuspendNoirq), 1);
    assert_eq!(s.step_failures(StatStep::Resume), 0);
    assert_eq!(s.last_failed_step(), StatStep::SuspendNoirq);
}

#[test]
fn working_is_not_a_failure_and_records_nothing() {
    let s = SuspendStats::new();
    s.save_failed_step(StatStep::Working);
    assert_eq!(s.last_failed_step(), StatStep::Working);
    for i in 0..NR_STEPS {
        let step = StatStep::from_index(i).unwrap();
        assert_eq!(s.step_failures(step), 0, "{step:?} counted a non-failure");
    }
}

#[test]
fn step_indices_round_trip() {
    for i in 0..NR_STEPS {
        let step = StatStep::from_index(i).expect("missing step");
        assert_eq!(step.index(), Some(i));
    }
    assert!(StatStep::from_index(NR_STEPS).is_none());
    assert!(StatStep::Working.index().is_none());
}

#[test]
fn every_step_has_a_distinct_name() {
    let names: [&str; NR_STEPS] =
        core::array::from_fn(|i| StatStep::from_index(i).unwrap().name());
    for i in 0..NR_STEPS {
        assert!(!names[i].is_empty());
        for j in (i + 1)..NR_STEPS { assert_ne!(names[i], names[j]); }
    }
}

#[test]
fn a_failed_device_name_is_kept_and_truncated() {
    let s = SuspendStats::new();
    s.save_failed_dev("virtio0");
    assert_eq!(s.last_failed_dev().as_str(), "virtio0");
    let long = "0123456789012345678901234567890123456789EXTRA";
    s.save_failed_dev(long);
    assert_eq!(s.last_failed_dev().as_str(), &long[..FAILED_DEV_NAME]);
}

#[test]
fn hw_sleep_accumulates_and_the_max_is_a_high_water_report() {
    let s = SuspendStats::new();
    s.report_hw_sleep(100);
    s.report_hw_sleep(250);
    assert_eq!(s.last_hw_sleep(), 250);
    assert_eq!(s.total_hw_sleep(), 350);
    s.report_max_hw_sleep(9_000);
    assert_eq!(s.max_hw_sleep(), 9_000);
}
