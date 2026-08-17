//! The flag view: what a query reports and what a set may change.
//!
//! The four derived bits are the point. Each describes something the inode
//! says elsewhere — a stored context, a sealing attribute, data inside the
//! inode, a pin — and a query that reported only the stored word would make
//! every one of them invisible to `lsattr`. Each has its own test, and each
//! test is a positive control for dropping that bit from the report.

use syscall::errno::Errno;

use crate::flags::*;
use crate::ioctl::fileattr::*;

fn plain() -> View { View::default() }

#[test]
fn a_stored_flag_the_view_maps_is_reported_unchanged() {
    let v = View { stored: F2FS_APPEND_FL | F2FS_NODUMP_FL, ..plain() };
    assert_eq!(report(&v), F2FS_APPEND_FL | F2FS_NODUMP_FL);
}

/// A stored bit nothing reports must not leak into the reported word: a tool
/// that wrote the reported word back would then be asking for a flag it never
/// meant to set.
#[test]
fn a_stored_flag_the_view_does_not_map_is_not_reported() {
    // The device-alias bit is stored and is not part of the reported set.
    let v = View { stored: 0x8000_0000, ..plain() };
    assert_eq!(report(&v), 0);
}

#[test]
fn an_encrypted_inode_reports_encrypted_though_no_stored_flag_says_so() {
    let v = View { encrypted: true, ..plain() };
    assert_eq!(report(&v), FS_ENCRYPT_FL);
    assert_eq!(report(&plain()) & FS_ENCRYPT_FL, 0);
}

#[test]
fn a_sealed_inode_reports_sealed() {
    let v = View { verity: true, ..plain() };
    assert_eq!(report(&v), FS_VERITY_FL);
    assert_eq!(report(&plain()) & FS_VERITY_FL, 0);
}

#[test]
fn an_inode_holding_its_own_data_reports_inline() {
    let v = View { inline_data: true, ..plain() };
    assert_eq!(report(&v), FS_INLINE_DATA_FL);
    assert_eq!(report(&plain()) & FS_INLINE_DATA_FL, 0);
}

#[test]
fn a_pinned_inode_reports_that_its_blocks_do_not_move() {
    let v = View { pinned: true, ..plain() };
    assert_eq!(report(&v), FS_NOCOW_FL);
    assert_eq!(report(&plain()) & FS_NOCOW_FL, 0);
}

/// The four derived bits are reported and are NOT settable. A caller reading
/// the whole word and writing it straight back must not be refused, and must
/// not clear them either.
#[test]
fn reading_the_whole_word_and_writing_it_back_changes_nothing() {
    let held = F2FS_APPEND_FL | F2FS_NODUMP_FL;
    let v = View { stored: held, encrypted: true, verity: true, inline_data: true,
                   pinned: true };
    let reported = report(&v);
    assert_eq!(apply(held, reported, Kind::Reg), Ok(held));
}

#[test]
fn a_bit_nothing_reports_is_refused_rather_than_dropped() {
    // The topmost bit is in neither the reported nor the settable set.
    assert_eq!(apply(0, 0x8000_0000, Kind::Reg), Err(Errno::Eopnotsupp));
}

#[test]
fn a_directory_only_flag_is_refused_on_a_regular_file() {
    assert_eq!(apply(0, F2FS_CASEFOLD_FL, Kind::Dir), Ok(F2FS_CASEFOLD_FL));
    assert_eq!(apply(0, F2FS_CASEFOLD_FL, Kind::Reg), Err(Errno::Eopnotsupp));
    assert_eq!(apply(0, F2FS_DIRSYNC_FL, Kind::Reg), Err(Errno::Eopnotsupp));
    assert_eq!(apply(0, F2FS_PROJINHERIT_FL, Kind::Reg), Err(Errno::Eopnotsupp));
}

#[test]
fn anything_that_is_neither_a_directory_nor_a_regular_file_takes_only_two_flags() {
    assert_eq!(apply(0, F2FS_NODUMP_FL, Kind::Other), Ok(F2FS_NODUMP_FL));
    assert_eq!(apply(0, F2FS_NOATIME_FL, Kind::Other), Ok(F2FS_NOATIME_FL));
    assert_eq!(apply(0, F2FS_APPEND_FL, Kind::Other), Err(Errno::Eopnotsupp));
    assert_eq!(apply(0, F2FS_IMMUTABLE_FL, Kind::Other), Err(Errno::Eopnotsupp));
}

/// Bits outside the settable set that the inode already carries survive: the
/// set replaces only what it owns.
#[test]
fn a_set_leaves_the_bits_it_does_not_own_alone() {
    let held = F2FS_ENCRYPT_FL | F2FS_VERITY_FL | F2FS_APPEND_FL;
    let out = apply(held, F2FS_NODUMP_FL, Kind::Reg).unwrap();
    assert_eq!(out & F2FS_ENCRYPT_FL, F2FS_ENCRYPT_FL);
    assert_eq!(out & F2FS_VERITY_FL, F2FS_VERITY_FL);
    // …and does clear a settable bit the caller left out.
    assert_eq!(out & F2FS_APPEND_FL, 0);
    assert_eq!(out & F2FS_NODUMP_FL, F2FS_NODUMP_FL);
}

#[test]
fn the_settable_set_is_a_subset_of_the_reported_set() {
    assert_eq!(SETTABLE & !GETTABLE, 0);
}

/// The index flag is reported and never settable: it describes how the
/// directory is laid out, which a caller cannot choose.
#[test]
fn the_index_flag_is_reported_and_not_settable() {
    assert_ne!(GETTABLE & F2FS_INDEX_FL, 0);
    assert_eq!(SETTABLE & F2FS_INDEX_FL, 0);
    assert_eq!(apply(0, F2FS_INDEX_FL, Kind::Dir), Ok(0));
}

#[test]
fn the_kind_mask_keeps_what_each_kind_allows() {
    assert_eq!(mask_for(Kind::Dir, u32::MAX), u32::MAX);
    assert_eq!(mask_for(Kind::Reg, DIR_ONLY), 0);
    assert_eq!(mask_for(Kind::Other, u32::MAX), OTHER_ALLOWED);
}
