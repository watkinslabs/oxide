//! The four controls: what each takes, what each refuses, and that a refusal
//! changes nothing.
//!
//! A knob that silently clamps — or silently truncates — is worse than one
//! that refuses: the tool that wrote it goes on believing the value it asked
//! for is in force. Both bounds are therefore checked from both sides.

use super::*;
use crate::atgc::knobs::{self, Knob};
use syscall::errno::Errno;

#[test]
fn every_control_reads_back_what_was_written_to_it() {
    let mut a = Atgc::new();
    for &k in knobs::ALL {
        knobs::store(&mut a, k, 7).unwrap();
        assert_eq!(knobs::show(&a, k), 7, "{}", knobs::name(k));
    }
}

#[test]
fn the_two_percentages_refuse_more_than_the_whole() {
    for k in [Knob::CandidateRatio, Knob::AgeWeight] {
        let mut a = Atgc::new();
        let before = knobs::show(&a, k);
        assert_eq!(knobs::store(&mut a, k, 101), Err(Errno::Einval), "{}", knobs::name(k));
        assert_eq!(knobs::show(&a, k), before, "a refusal changes nothing");
        knobs::store(&mut a, k, 100).unwrap();
        assert_eq!(knobs::show(&a, k), 100, "the whole is allowed");
        knobs::store(&mut a, k, 0).unwrap();
        assert_eq!(knobs::show(&a, k), 0, "and so is none of it");
    }
}

#[test]
fn the_candidate_count_refuses_more_than_it_can_hold() {
    let mut a = Atgc::new();
    let before = knobs::show(&a, Knob::CandidateCount);
    let past = u64::from(u32::MAX) + 1;
    assert_eq!(knobs::store(&mut a, Knob::CandidateCount, past), Err(Errno::Einval));
    assert_eq!(knobs::show(&a, Knob::CandidateCount), before,
               "refused rather than wrapped to one");
    knobs::store(&mut a, Knob::CandidateCount, u64::from(u32::MAX)).unwrap();
    assert_eq!(knobs::show(&a, Knob::CandidateCount), u64::from(u32::MAX));
}

#[test]
fn the_age_threshold_takes_any_age_the_volume_can_record() {
    let mut a = Atgc::new();
    knobs::store(&mut a, Knob::AgeThreshold, u64::MAX).unwrap();
    assert_eq!(knobs::show(&a, Knob::AgeThreshold), u64::MAX);
    knobs::store(&mut a, Knob::AgeThreshold, 0).unwrap();
    assert_eq!(knobs::show(&a, Knob::AgeThreshold), 0);
}

#[test]
fn each_control_is_published_under_its_own_name() {
    let mut seen = alloc::vec::Vec::new();
    for &k in knobs::ALL {
        let n = knobs::name(k);
        assert!(n.starts_with("atgc_"), "{n}");
        assert!(!seen.contains(&n), "two controls under one name: {n}");
        seen.push(n);
    }
    assert_eq!(seen.len(), 4);
}

#[test]
fn a_refused_write_leaves_the_search_behaving_as_it_did() {
    let mut a = Atgc::new();
    a.age_threshold = 0;
    a.begin();
    a.add_candidate(1, 20, 50, false);
    a.add_candidate(2, 0, 50, false);
    let before = a.dirty_threshold();
    assert_eq!(knobs::store(&mut a, Knob::CandidateRatio, 1_000), Err(Errno::Einval));
    assert_eq!(a.dirty_threshold(), before);
}
