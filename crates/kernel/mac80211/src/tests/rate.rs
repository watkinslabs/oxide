// Rate selection and the supported-rate set.

use alloc::vec;

use wireless::uapi::enums::Band;
use wireless::wiphy::caps::standard_bitrates;

use crate::limits;
use crate::rate::{self, RateCtl};
use crate::uapi::{elem_to_rate, rate_to_elem, RATE_BASIC};

#[test]
fn the_usable_set_is_the_intersection_of_both_ends() {
    let local = standard_bitrates(Band::Band2Ghz);
    // A peer that supports only the three lowest rates and one this radio
    // does not have at all.
    let peer = vec![10u32, 20, 55, 9999];
    let usable = rate::intersect(&local, &peer);
    assert_eq!(usable.len(), 3);
    assert!(usable.iter().all(|b| peer.contains(&b.bitrate)));
    assert!(!usable.iter().any(|b| b.bitrate == 9999),
            "a rate this radio cannot produce is not a degraded link, it is no link");
}

#[test]
fn rates_are_read_out_of_both_elements() {
    // The split between the element and its extension is a length limit, not
    // two different rate sets.
    let supp = [rate_to_elem(10), rate_to_elem(20) | RATE_BASIC];
    let ext = [rate_to_elem(540)];
    let rates = rate::rates_from_elements(&supp, &ext);
    assert_eq!(rates, vec![10, 20, 540]);
}

#[test]
fn the_basic_rate_mask_names_only_the_marked_rates() {
    let local = standard_bitrates(Band::Band2Ghz);
    let supp = [rate_to_elem(10) | RATE_BASIC, rate_to_elem(20),
                rate_to_elem(110) | RATE_BASIC];
    let mask = rate::basic_rate_mask(&local, &supp, &[]);
    let idx = |r: u32| local.iter().position(|b| b.bitrate == r).unwrap();
    assert_ne!(mask & (1 << idx(10)), 0);
    assert_eq!(mask & (1 << idx(20)), 0);
    assert_ne!(mask & (1 << idx(110)), 0);
}

#[test]
fn a_built_element_round_trips_through_its_own_reader() {
    let local = standard_bitrates(Band::Band5Ghz);
    let bytes = rate::rates_element(&local, 0b0011);
    let rates = rate::rates_from_elements(&bytes, &[]);
    assert_eq!(rates.len(), local.len());
    for (b, l) in rates.iter().zip(local.iter()) { assert_eq!(*b, l.bitrate); }
    assert_ne!(bytes[0] & RATE_BASIC, 0);
    assert_ne!(bytes[1] & RATE_BASIC, 0);
    assert_eq!(bytes[2] & RATE_BASIC, 0);
}

#[test]
fn a_long_rate_list_is_split_across_the_element_and_its_extension() {
    let local = standard_bitrates(Band::Band2Ghz);
    let bytes = rate::rates_element(&local, 0);
    let (supp, ext) = rate::split_rates(&bytes);
    assert_eq!(supp.len(), rate::MAX_SUPP_RATES);
    assert_eq!(supp.len() + ext.len(), bytes.len());
    // A short list needs no extension.
    let (short, none) = rate::split_rates(&bytes[..3]);
    assert_eq!(short.len(), 3);
    assert!(none.is_empty());
}

#[test]
fn the_element_unit_is_half_megabits() {
    assert_eq!(rate_to_elem(10), 2);
    assert_eq!(rate_to_elem(540), 108);
    assert_eq!(elem_to_rate(2), 10);
    assert_eq!(elem_to_rate(108 | RATE_BASIC), 540);
}

#[test]
fn selection_starts_at_the_lowest_usable_rate() {
    let usable = standard_bitrates(Band::Band2Ghz);
    let mut r = RateCtl::default();
    r.start(&usable);
    assert_eq!(r.current(), 0);
    assert_eq!(r.bitrate, usable[0].bitrate);
}

#[test]
fn consecutive_failures_step_the_rate_down() {
    let usable = standard_bitrates(Band::Band2Ghz);
    let mut r = RateCtl::default();
    r.start(&usable);
    for _ in 0..limits::RATE_UP_SUCCESSES { r.report(true, &usable); }
    assert_eq!(r.current(), 1);
    for _ in 0..limits::RATE_DOWN_FAILURES { r.report(false, &usable); }
    assert_eq!(r.current(), 0);
}

#[test]
fn a_single_failure_does_not_step_down() {
    let usable = standard_bitrates(Band::Band2Ghz);
    let mut r = RateCtl::default();
    r.start(&usable);
    for _ in 0..limits::RATE_UP_SUCCESSES { r.report(true, &usable); }
    let at = r.current();
    r.report(false, &usable);
    assert_eq!(r.current(), at, "one lost frame is not a worse link");
}

#[test]
fn a_run_of_successes_steps_the_rate_up() {
    let usable = standard_bitrates(Band::Band2Ghz);
    let mut r = RateCtl::default();
    r.start(&usable);
    for _ in 0..limits::RATE_UP_SUCCESSES { r.report(true, &usable); }
    assert_eq!(r.current(), 1);
    assert_eq!(r.bitrate, usable[1].bitrate);
}

#[test]
fn the_rate_never_leaves_the_usable_set() {
    let usable = standard_bitrates(Band::Band2Ghz);
    let mut r = RateCtl::default();
    r.start(&usable);
    // A long run of successes must stop at the top rather than index past it.
    for _ in 0..1000 { r.report(true, &usable); }
    assert_eq!(r.current() as usize, usable.len() - 1);
    // And a long run of failures must stop at the bottom.
    for _ in 0..1000 { r.report(false, &usable); }
    assert_eq!(r.current(), 0);
}

#[test]
fn a_link_that_settled_low_still_probes_upward() {
    // Without a probe a link that dropped to the floor during one bad minute
    // never discovers that conditions improved.
    let usable = standard_bitrates(Band::Band2Ghz);
    let mut r = RateCtl::default();
    r.start(&usable);
    // Alternate so the success run never reaches the climb threshold on its
    // own; only the probe interval can move the rate.
    let mut moved = false;
    for i in 0..limits::RATE_PROBE_INTERVAL * 2 {
        r.report(i % 3 != 0, &usable);
        if r.current() > 0 { moved = true; break; }
    }
    assert!(moved, "a link with occasional losses must still try a higher rate");
}

#[test]
fn an_empty_usable_set_changes_nothing() {
    let mut r = RateCtl::default();
    r.start(&[]);
    r.report(true, &[]);
    r.report(false, &[]);
    assert_eq!(r.current(), 0);
}
