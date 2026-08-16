use super::*;

const FREQS: [u32; 3] = [800_000, 1_200_000, 2_400_000];

#[test]
fn occupancy_reports_hundredths_of_a_second() {
    assert_eq!(ns_to_clock_t(0), 0);
    assert_eq!(ns_to_clock_t(10_000_000), 1, "ten milliseconds is one tick");
    assert_eq!(ns_to_clock_t(1_000_000_000), 100, "a second is a hundred ticks");
    assert_eq!(ns_to_clock_t(9_999_999), 0, "truncates rather than rounding up");
    assert_ne!(ns_to_clock_t(1_000_000_000), 1_000_000_000,
               "raw nanoseconds here would overstate every figure a hundred-millionfold");
}

#[test]
fn occupancy_accrues_to_the_frequency_that_was_in_force() {
    let mut stats = Stats::new(&FREQS, 800_000);
    stats.record(1_200_000, 1_000_000_000);
    stats.record(2_400_000, 3_000_000_000);
    let times = stats.time_ns_at(6_000_000_000);
    assert_eq!(times[0], 1_000_000_000);
    assert_eq!(times[1], 2_000_000_000);
    assert_eq!(times[2], 3_000_000_000);
}

#[test]
fn re_recording_the_same_frequency_accrues_time_without_a_transition() {
    let mut stats = Stats::new(&FREQS, 800_000);
    stats.record(800_000, 5_000_000_000);
    assert_eq!(stats.total_trans, 0);
    assert_eq!(stats.time_ns_at(5_000_000_000)[0], 5_000_000_000);
}

#[test]
fn the_transition_table_records_the_pair_that_was_traversed() {
    let mut stats = Stats::new(&FREQS, 800_000);
    stats.record(2_400_000, 0);
    stats.record(1_200_000, 0);
    stats.record(2_400_000, 0);
    assert_eq!(stats.total_trans, 3);
    let width = FREQS.len();
    assert_eq!(stats.table[0 * width + 2], 1);
    assert_eq!(stats.table[2 * width + 1], 1);
    assert_eq!(stats.table[1 * width + 2], 1);
    assert_eq!(stats.table[2 * width + 0], 0);
}

#[test]
fn a_frequency_the_policy_does_not_have_is_not_recorded() {
    let mut stats = Stats::new(&FREQS, 800_000);
    stats.record(1_500_000, 1_000_000_000);
    assert_eq!(stats.total_trans, 0);
    assert_eq!(stats.current, 0);
}

#[test]
fn the_occupancy_body_names_each_frequency_with_its_ticks() {
    let mut stats = Stats::new(&FREQS, 800_000);
    stats.record(1_200_000, 2_000_000_000);
    let body = String::from_utf8(stats.time_in_state_body(2_000_000_000)).expect("utf8");
    assert_eq!(body, "800000 200\n1200000 0\n2400000 0\n");
}

#[test]
fn the_transition_table_body_is_square_over_every_frequency() {
    let mut stats = Stats::new(&FREQS, 800_000);
    stats.record(1_200_000, 0);
    let body = String::from_utf8(stats.trans_table_body()).expect("utf8");
    let lines: alloc::vec::Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 2 + FREQS.len());
    assert!(lines[0].contains("From"));
    for freq in FREQS { assert!(lines[1].contains(&alloc::format!("{freq}"))); }
    assert!(lines[2].starts_with("   800000:"));
}

#[test]
fn a_reset_clears_the_counters_and_restarts_the_occupancy_clock() {
    let mut stats = Stats::new(&FREQS, 800_000);
    stats.record(1_200_000, 1_000_000_000);
    stats.reset(4_000_000_000);
    assert_eq!(stats.total_trans, 0);
    assert!(stats.table.iter().all(|count| *count == 0));
    assert!(stats.time_ns.iter().all(|time| *time == 0));
    assert_eq!(stats.time_ns_at(9_000_000_000)[1], 5_000_000_000);
}
