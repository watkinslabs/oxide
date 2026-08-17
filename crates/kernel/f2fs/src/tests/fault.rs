//! Injected failures: the site list is an ABI, the rate is a period, and off
//! costs nothing.

use crate::fault::attr::Which;
use crate::fault::{apply, build, time_to_inject, Cfg, Fault, Info, ALL_TYPES, FAULT_MAX,
                   TIMEOUT_MAX};
use crate::fault::types::Timeout;

fn armed(rate: u32, types: u32) -> Info {
    let i = Info::new();
    build(&i, rate, 0, Which::RATE).unwrap();
    build(&i, 0, types, Which::TYPE).unwrap();
    i
}

// -------------------------------------------------------------- the site list

#[test]
fn the_site_list_is_the_width_the_mask_claims() {
    assert_eq!(FAULT_MAX, 26);
    assert_eq!(ALL_TYPES, (1u32 << 26) - 1);
}

#[test]
fn every_site_has_a_distinct_bit_at_its_own_index() {
    // The bit position is what a test writes by hand into `fault_type=`, so a
    // site that moved would silently re-aim every existing mount line.
    for i in 0..FAULT_MAX {
        let f = Fault::from_index(i).expect("a site at every index below the end");
        assert_eq!(f.bit(), 1u32 << i);
        assert_eq!(f as u32, i);
    }
    assert!(Fault::from_index(FAULT_MAX).is_none());
}

#[test]
fn the_first_and_last_sites_are_where_the_interface_says() {
    assert_eq!(Fault::from_index(0), Some(Fault::Kmalloc));
    assert_eq!(Fault::from_index(FAULT_MAX - 1), Some(Fault::SkipWrite));
}

#[test]
fn no_two_sites_share_a_name() {
    for i in 0..FAULT_MAX {
        for j in (i + 1)..FAULT_MAX {
            let (a, b) = (Fault::from_index(i).unwrap(), Fault::from_index(j).unwrap());
            assert_ne!(a.name(), b.name(), "{i} and {j} share a name");
        }
    }
}

// ------------------------------------------------------------------ the rate

#[test]
fn a_rate_of_zero_never_injects() {
    let i = armed(0, ALL_TYPES);
    for _ in 0..1000 { assert!(!time_to_inject(&i, Fault::Kmalloc)); }
}

#[test]
fn an_unarmed_site_never_injects_however_high_the_rate() {
    let i = armed(1, Fault::Kmalloc.bit());
    for _ in 0..100 { assert!(!time_to_inject(&i, Fault::ReadIo)); }
    assert_eq!(i.count(Fault::ReadIo), 0);
}

#[test]
fn a_rate_of_one_injects_every_time() {
    let i = armed(1, Fault::Block.bit());
    for _ in 0..10 { assert!(time_to_inject(&i, Fault::Block)); }
    assert_eq!(i.count(Fault::Block), 10);
}

#[test]
fn the_rate_is_a_period_not_a_probability() {
    // Every fourth consultation fails, and the three before it do not.
    let i = armed(4, Fault::Orphan.bit());
    for round in 0..5 {
        assert!(!time_to_inject(&i, Fault::Orphan), "round {round} first");
        assert!(!time_to_inject(&i, Fault::Orphan), "round {round} second");
        assert!(!time_to_inject(&i, Fault::Orphan), "round {round} third");
        assert!(time_to_inject(&i, Fault::Orphan), "round {round} fourth");
    }
    assert_eq!(i.count(Fault::Orphan), 5);
}

#[test]
fn the_counter_is_shared_across_armed_sites() {
    // Two sites armed at a period of two: the failures interleave rather than
    // each site keeping its own count, which is what makes an injected run
    // look like a real allocator failing under pressure.
    let i = armed(2, Fault::Kmalloc.bit() | Fault::ReadIo.bit());
    assert!(!time_to_inject(&i, Fault::Kmalloc));
    assert!(time_to_inject(&i, Fault::ReadIo));
    assert_eq!(i.count(Fault::ReadIo), 1);
    assert_eq!(i.count(Fault::Kmalloc), 0);
}

#[test]
fn an_unarmed_consultation_does_not_advance_the_counter() {
    let i = armed(2, Fault::Kmalloc.bit());
    for _ in 0..50 { assert!(!time_to_inject(&i, Fault::Truncate)); }
    assert!(!time_to_inject(&i, Fault::Kmalloc));
    assert!(time_to_inject(&i, Fault::Kmalloc));
}

// -------------------------------------------------------------- what changes

#[test]
fn a_refused_rate_changes_nothing() {
    let i = armed(3, Fault::Block.bit());
    assert!(build(&i, i32::MAX as u32 + 1, 0, Which::RATE).is_err());
    assert_eq!(i.rate(), 3);
    assert_eq!(i.types(), Fault::Block.bit());
}

#[test]
fn the_widest_rate_the_interface_admits_is_accepted() {
    let i = Info::new();
    assert!(build(&i, i32::MAX as u32, 0, Which::RATE).is_ok());
    assert_eq!(i.rate(), i32::MAX as u32);
}

#[test]
fn a_mask_past_the_last_site_is_refused() {
    let i = Info::new();
    assert!(build(&i, 0, ALL_TYPES, Which::TYPE).is_ok());
    assert!(build(&i, 0, ALL_TYPES + 1, Which::TYPE).is_err());
    assert_eq!(i.types(), ALL_TYPES);
}

#[test]
fn one_field_is_written_without_disturbing_the_other() {
    let i = armed(7, Fault::Checkpoint.bit());
    build(&i, 9, 0, Which::RATE).unwrap();
    assert_eq!(i.types(), Fault::Checkpoint.bit());
    build(&i, 0, Fault::ReadIo.bit(), Which::TYPE).unwrap();
    assert_eq!(i.rate(), 9);
}

#[test]
fn writing_the_rate_restarts_the_period() {
    let i = armed(4, Fault::Block.bit());
    assert!(!time_to_inject(&i, Fault::Block));
    assert!(!time_to_inject(&i, Fault::Block));
    // Two consultations in; a fresh rate starts the count again, so the next
    // failure is four away rather than two.
    build(&i, 4, 0, Which::RATE).unwrap();
    assert!(!time_to_inject(&i, Fault::Block));
    assert!(!time_to_inject(&i, Fault::Block));
    assert!(!time_to_inject(&i, Fault::Block));
    assert!(time_to_inject(&i, Fault::Block));
}

#[test]
fn a_reset_clears_the_counts_as_well_as_the_settings() {
    let i = armed(1, Fault::Kmalloc.bit());
    assert!(time_to_inject(&i, Fault::Kmalloc));
    build(&i, 0, 0, Which::ALL).unwrap();
    assert_eq!(i.rate(), 0);
    assert_eq!(i.types(), 0);
    assert_eq!(i.count(Fault::Kmalloc), 0);
    assert_eq!(i.timeout(), Timeout::None);
}

#[test]
fn a_timeout_kind_past_the_last_one_is_refused() {
    let i = Info::new();
    assert!(build(&i, 0, TIMEOUT_MAX - 1, Which::TIMEOUT).is_ok());
    assert_eq!(i.timeout(), Timeout::Runnable);
    assert!(build(&i, 0, TIMEOUT_MAX, Which::TIMEOUT).is_err());
    assert_eq!(i.timeout(), Timeout::Runnable);
}

// -------------------------------------------------- what a mount asks for

#[test]
fn a_mount_that_asked_for_nothing_arms_nothing() {
    let i = Info::new();
    apply(&i, &Cfg::default());
    assert_eq!(i.rate(), 0);
    assert_eq!(i.types(), 0);
    assert!(!time_to_inject(&i, Fault::Kmalloc));
}

#[test]
fn a_rate_without_a_site_list_injects_nowhere() {
    let i = Info::new();
    apply(&i, &Cfg { rate: Some(1), types: None });
    assert_eq!(i.rate(), 1);
    for idx in 0..FAULT_MAX {
        assert!(!time_to_inject(&i, Fault::from_index(idx).unwrap()));
    }
}

#[test]
fn a_mount_naming_both_fields_arms_exactly_them() {
    let i = Info::new();
    apply(&i, &Cfg { rate: Some(1), types: Some(Fault::WriteIo.bit()) });
    assert!(i.armed(Fault::WriteIo));
    assert!(!i.armed(Fault::ReadIo));
    assert!(time_to_inject(&i, Fault::WriteIo));
}

#[test]
fn a_field_the_builder_refuses_leaves_the_mount_running_without_it() {
    // The mount succeeds: the two values are range-checked where they are
    // stored, not where they are spelled, and a value past either range
    // produces a mount with that field unset rather than a failed mount.
    let i = Info::new();
    apply(&i, &Cfg { rate: Some(-5), types: Some(ALL_TYPES + 1) });
    assert_eq!(i.rate(), 0);
    assert_eq!(i.types(), 0);
}
