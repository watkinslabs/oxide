use super::*;

#[test]
fn a_repeated_ordinal_owes_the_log_one_line() {
    let reports = OrdinalReports::new();
    assert!(reports.claim(0x50, 0x02));
    for _ in 0..295 { assert!(!reports.claim(0x50, 0x02)); }
}

#[test]
fn the_startup_ordinal_set_costs_one_line_each() {
    // The ordinal/service pairs one measured PE startup issued, with the call
    // counts that made the ungated trace 667 console writes.
    const STARTUP: [(u32, u32, u32); 8] = [
        (0x50, 0x002, 296), (0x72, 0x255, 44), (0x0f, 0x006, 34), (0x33, 0x00b, 24),
        (0x60, 0x142, 47), (0x1d, 0x02a, 9), (0x12, 0x02b, 4), (0x4a, 0x012, 14),
    ];
    let reports = OrdinalReports::new();
    let mut lines = 0;
    for (ordinal, service, calls) in STARTUP {
        for _ in 0..calls { if reports.claim(ordinal, service) { lines += 1; } }
    }
    assert_eq!(lines, STARTUP.len(), "the trace must be a mapping, one line per distinct pair");
}

#[test]
fn a_misroute_of_an_already_named_ordinal_still_prints() {
    let reports = OrdinalReports::new();
    assert!(reports.claim(0x50, 0x02));
    assert!(!reports.claim(0x50, 0x02));
    assert!(reports.claim(0x50, 0x03), "the same ordinal answering a different service is a new mapping entry");
    assert!(!reports.claim(0x50, 0x03));
}

#[test]
fn ordinal_zero_answering_service_zero_is_a_real_pair() {
    let reports = OrdinalReports::new();
    assert!(reports.claim(0, 0));
    assert!(!reports.claim(0, 0));
}

#[test]
fn a_sweep_of_the_ordinal_space_is_bounded_and_never_silences_seated_pairs() {
    let reports = OrdinalReports::new();
    let mut lines = 0;
    for ordinal in 0..(PAIR_SLOTS as u32 * 4) { if reports.claim(ordinal, 1) { lines += 1; } }
    assert!(lines <= PAIR_SLOTS + OVERFLOW_REPORTS as usize, "a sweeping caller must not become the boot log");
    assert!(lines >= PAIR_SLOTS, "every seatable pair must be named once");
    let overflowed = (0..(PAIR_SLOTS as u32 * 4)).filter(|ordinal| reports.claim(*ordinal, 1)).count();
    assert_eq!(overflowed, 0, "the overflow budget is spent and every seated pair stays quiet");
}

#[test]
fn concurrent_claims_of_one_pair_name_it_exactly_once() {
    // A CAS loser must read the winner's key rather than seating a duplicate.
    let reports = OrdinalReports::new();
    let mut lines = 0;
    for _ in 0..64 { if reports.claim(0x99, 0x11) { lines += 1; } }
    assert_eq!(lines, 1);
    let seated = reports.slots.iter().filter(|slot| slot.load(Ordering::Relaxed) != EMPTY).count();
    assert_eq!(seated, 1, "one pair seats one slot");
}
