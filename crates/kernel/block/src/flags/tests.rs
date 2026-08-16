// The op-flags word: what combines, what reads back, and which flags make a
// request urgent.

use super::*;

#[test]
fn an_empty_word_is_an_ordinary_request() {
    let f = RequestFlags::NONE;
    assert!(!f.is_hiprio());
    assert!(!f.contains(PRIO));
    assert!(!f.contains(META));
    assert_eq!(RequestFlags::default(), RequestFlags::NONE);
}

#[test]
fn flags_combine_without_losing_each_other() {
    let both = PRIO | META;
    assert!(both.contains(PRIO));
    assert!(both.contains(META));
    // A single flag does not read back as the pair.
    assert!(!PRIO.contains(META));
    assert!(!META.contains(PRIO));
    assert!(both.contains(PRIO | META));
}

#[test]
fn assigning_a_flag_keeps_the_ones_already_set() {
    let mut f = META;
    f |= PRIO;
    assert_eq!(f, PRIO | META);
}

#[test]
fn both_urgency_hints_mark_a_request_urgent() {
    // Metadata gates the data below it, and an explicit boost says the
    // submitter decided; either one is enough on its own.
    assert!(PRIO.is_hiprio());
    assert!(META.is_hiprio());
    assert!((PRIO | META).is_hiprio());
    assert!(!RequestFlags::NONE.is_hiprio());
}

#[test]
fn the_flags_occupy_distinct_bits() {
    // A word carrying one flag must never answer for the other, which is the
    // whole reason this is a bit set and not a count.
    assert_ne!(PRIO, META);
    assert_ne!(PRIO, RequestFlags::NONE);
    assert_ne!(META, RequestFlags::NONE);
}
