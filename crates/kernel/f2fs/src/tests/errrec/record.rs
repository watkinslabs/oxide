//! The two arrays: what dirties them, what saturates, and the bytes they
//! become.

use super::*;
use crate::errrec::uapi::{ERROR_MAX, MAX_F2FS_ERRORS, MAX_STOP_REASON, STOP_REASON_MAX};
use crate::uapi::{SB_S_ERRORS, SB_S_STOP_REASON, SUPER_SIZE};
use alloc::vec;

fn blank() -> alloc::vec::Vec<u8> { vec![0u8; SUPER_SIZE] }

#[test]
fn a_fresh_record_holds_nothing_and_owes_nothing() {
    let r = ErrorRecord::empty();
    assert!(!r.dirty());
    for e in Error::ALL { assert!(!r.has_error(e)); }
    assert_eq!(r.stops(StopReason::WriteFail), 0);
}

#[test]
fn every_kind_lands_in_its_own_bit() {
    // The bitmap is the ABI, so two kinds sharing a bit would report the wrong
    // fault to every checker that reads it.
    let mut seen = alloc::vec::Vec::new();
    for e in Error::ALL {
        let mut r = ErrorRecord::empty();
        assert!(r.save_error(e));
        let mut b = blank();
        r.into_super(&mut b);
        let bits = &b[SB_S_ERRORS..SB_S_ERRORS + MAX_F2FS_ERRORS];
        assert_eq!(bits.iter().map(|x| x.count_ones()).sum::<u32>(), 1, "{e:?} set one bit");
        assert!(!seen.contains(&bits.to_vec()), "{e:?} shares a bit with an earlier kind");
        seen.push(bits.to_vec());
    }
    assert_eq!(seen.len(), ERROR_MAX);
}

#[test]
fn the_widest_kind_still_fits_the_array() {
    assert!(ERROR_MAX <= MAX_F2FS_ERRORS * 8);
    assert!(STOP_REASON_MAX <= MAX_STOP_REASON);
}

#[test]
fn the_second_occurrence_of_a_kind_is_not_news() {
    let mut r = ErrorRecord::empty();
    assert!(r.save_error(Error::CorruptedInode));
    assert!(r.error_dirty());
    let mut b = blank();
    r.into_super(&mut b);
    assert!(!r.error_dirty(), "the write settled it");
    assert!(!r.save_error(Error::CorruptedInode), "already recorded");
    assert!(!r.error_dirty(), "and dirtied nothing");
    assert!(r.save_error(Error::CorruptedXattr), "a different kind is news");
}

#[test]
fn a_stop_reason_counts_and_dirties_every_time() {
    let mut r = ErrorRecord::empty();
    r.save_stop_reason(StopReason::WriteFail);
    assert_eq!(r.stops(StopReason::WriteFail), 1);
    assert!(r.stop_dirty());
    let mut b = blank();
    assert!(r.into_super(&mut b), "the push reports the stop");
    assert!(!r.stop_dirty());
    r.save_stop_reason(StopReason::WriteFail);
    assert_eq!(r.stops(StopReason::WriteFail), 2);
    assert!(r.stop_dirty(), "a second stop is a second thing to record");
}

#[test]
fn a_count_saturates_rather_than_wrapping() {
    // A wrap would take the volume that has failed most and report it as one
    // that has never failed.
    let mut r = ErrorRecord::empty();
    for _ in 0..300 { r.save_stop_reason(StopReason::FlushFail); }
    assert_eq!(r.stops(StopReason::FlushFail), u8::MAX);
}

#[test]
fn each_reason_counts_in_its_own_slot() {
    let mut r = ErrorRecord::empty();
    r.save_stop_reason(StopReason::ReadNode);
    r.save_stop_reason(StopReason::ReadNode);
    r.save_stop_reason(StopReason::ReadData);
    let mut b = blank();
    r.into_super(&mut b);
    let a = &b[SB_S_STOP_REASON..SB_S_STOP_REASON + MAX_STOP_REASON];
    assert_eq!(a[StopReason::ReadNode as usize], 2);
    assert_eq!(a[StopReason::ReadData as usize], 1);
    assert_eq!(a[StopReason::Shutdown as usize], 0);
}

#[test]
fn a_record_read_back_out_of_the_bytes_is_the_one_that_was_written() {
    let mut r = ErrorRecord::empty();
    r.save_error(Error::InconsistentNat);
    r.save_error(Error::CorruptedDirent);
    r.save_stop_reason(StopReason::NoSegment);
    let mut b = blank();
    r.into_super(&mut b);
    let back = ErrorRecord::from_super(&b);
    assert!(back.has_error(Error::InconsistentNat));
    assert!(back.has_error(Error::CorruptedDirent));
    assert!(!back.has_error(Error::CorruptedXattr));
    assert_eq!(back.stops(StopReason::NoSegment), 1);
    assert!(!back.dirty(), "what the medium already holds is not owed");
}

#[test]
fn an_unchanged_bitmap_is_not_rewritten_over_a_later_one() {
    // The record only ever ADDS, so a mount whose bitmap did not change must
    // not write its copy over one another writer already widened.
    let mut b = blank();
    let mut r = ErrorRecord::empty();
    r.save_stop_reason(StopReason::MetaPage);
    b[SB_S_ERRORS] = 0xFF;
    r.into_super(&mut b);
    assert_eq!(b[SB_S_ERRORS], 0xFF, "an unchanged bitmap left the bytes alone");
}

#[test]
fn only_the_metadata_kinds_report_as_structural() {
    assert!(Error::InvalidBlkaddr.is_metadata());
    assert!(Error::InconsistentNat.is_metadata());
    assert!(!Error::CorruptedCluster.is_metadata());
    assert!(!Error::FailDecompression.is_metadata());
    assert!(!Error::CorruptedVerityXattr.is_metadata());
}
