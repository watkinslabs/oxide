//! What a mount says about the chain it found.

use super::*;
use crate::volume::recover::{Recovery, Replayed};

#[test]
fn a_clean_mount_says_nothing() {
    assert_eq!(announce_for(Recovery::Clean), Announce::Silent);
}

#[test]
fn a_dropped_chain_is_announced() {
    // The case most worth saying: writes an `fsync` promised are gone, and
    // nothing else on the volume records that they ever existed.
    assert_eq!(announce_for(Recovery::Skipped), Announce::Skipped);
}

#[test]
fn every_count_reaches_the_announcement() {
    let d = Replayed { nodes: 4, inodes: 3, dentries: 2, blocks: 9 };
    assert_eq!(announce_for(Recovery::Replayed(d)), Announce::Replayed([4, 3, 2, 9]));
}

#[test]
fn the_counts_are_announced_in_the_order_the_fields_name() {
    // A silent transposition of two counts is the failure this pins: both are
    // small integers, so a swapped pair reads as a plausible report.
    let d = Replayed { nodes: 1, inodes: 2, dentries: 3, blocks: 4 };
    let Announce::Replayed(counts) = announce_for(Recovery::Replayed(d)) else {
        panic!("a replay announces its counts")
    };
    assert_eq!(FIELDS.len(), counts.len());
    for (field, want) in FIELDS.iter().zip([1u32, 2, 3, 4]) {
        let at = counts.iter().position(|&c| c == want).expect("count present");
        assert_eq!(counts[at], want, "{:?} carries its own count", core::str::from_utf8(field));
    }
    assert_eq!(counts, [1, 2, 3, 4]);
}

#[test]
fn a_replay_that_put_nothing_back_is_still_announced() {
    // The pass ran and found nothing to restore, which is a different fact
    // from having found no chain at all.
    let a = announce_for(Recovery::Replayed(Replayed::default()));
    assert_eq!(a, Announce::Replayed([0; 4]));
    assert_ne!(a, Announce::Silent, "a pass that ran is not a mount that found nothing");
}

#[test]
fn emitting_every_shape_is_harmless_without_a_sink() {
    // The emit is the consumer the counts exist for; running it here proves
    // the call compiles and terminates for each shape.
    emit(Announce::Silent);
    emit(Announce::Skipped);
    emit(Announce::Replayed([u32::MAX; 4]));
}
