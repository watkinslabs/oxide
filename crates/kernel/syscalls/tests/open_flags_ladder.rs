//! `open(2)` / `openat(2)` / `openat2(2)` flag normalisation, the decode of an
//! open's flag word into the `may_open` flag rungs, and the placement of the
//! mount write admission relative to the permission ladder.
//!
//! Every rule here is observable only as an errno or an errno ORDER, and the
//! slot files that consume them are kernel-gated — a `#[cfg(test)]` block
//! beside them would compile out and report nothing.

use syscalls::open_flags::*;
use vfs::types::FileType;

const EINVAL: i64 = -(syscall::errno::Errno::Einval.as_i32() as i64);

/// Legacy `open`/`openat` normalisation.
fn legacy(flags: u64, mode: u64) -> Result<(u32, u32), i64> {
    normalize_open_flags(flags, mode, false)
}
/// `openat2` normalisation (strict).
fn at2(flags: u64, mode: u64) -> Result<(u32, u32), i64> {
    normalize_open_flags(flags, mode, true)
}

// ---- unknown bits: the whole legacy/openat2 split -------------------------

/// A bit no `open` flag claims. Chosen above every defined flag and below the
/// openat2-only carrier, so it is unknown to BOTH entry points.
const UNKNOWN_BIT: u64 = 1 << 34;

#[test]
fn legacy_silently_masks_an_unknown_bit_and_openat2_rejects_it() {
    // The legacy numbers shipped before unknown bits were checked, so programs
    // exist that pass junk; masking is the compatible answer.
    assert_eq!(legacy(UNKNOWN_BIT | O_CLOEXEC as u64, 0), Ok((O_CLOEXEC, 0)));
    // openat2 was introduced with a strictly-validated argument struct, which
    // is what lets a new flag be feature-detected instead of silently ignored.
    assert_eq!(at2(UNKNOWN_BIT | O_CLOEXEC as u64, 0), Err(EINVAL));
}

#[test]
fn the_openat2_only_carrier_is_unknown_to_the_legacy_entry_points() {
    // OPENAT2_REGULAR lives above the 32-bit flag word precisely so it cannot
    // alias an open(2) flag; a legacy caller's copy of it is masked away.
    assert_eq!(legacy(OPENAT2_REGULAR | O_RDONLY as u64, 0), Ok((0, 0)));
    assert_eq!(at2(OPENAT2_REGULAR, 0).map(|(f, _)| f as u64 & OPENAT2_REGULAR as u64), Ok(0),
        "the carrier does not survive the 32-bit truncation");
}

// ---- mode masking --------------------------------------------------------

#[test]
fn legacy_masks_the_mode_and_openat2_rejects_out_of_range_bits() {
    assert_eq!(legacy(O_CREAT as u64, 0o7777 | 0o10000), Ok((O_CREAT, 0o7777)));
    assert_eq!(at2(O_CREAT as u64, 0o7777 | 0o10000), Err(EINVAL));
    assert_eq!(at2(O_CREAT as u64, 0o7777), Ok((O_CREAT, 0o7777)));
}

#[test]
fn a_mode_without_a_creating_flag_is_dropped_by_legacy_and_refused_by_openat2() {
    // Nothing is being created, so the mode has no meaning. The legacy answer
    // is to ignore it; the strict answer is to say the argument is wrong.
    assert_eq!(legacy(O_RDONLY as u64, 0o644), Ok((0, 0)));
    assert_eq!(at2(O_RDONLY as u64, 0o644), Err(EINVAL));
    // O_TMPFILE creates too, so it keeps its mode.
    let tmp = O_TMPFILE as u64 | O_DIRECTORY as u64 | O_WRONLY as u64;
    assert_eq!(legacy(tmp, 0o600).map(|(_, m)| m), Ok(0o600));
    assert_eq!(at2(tmp, 0o600).map(|(_, m)| m), Ok(0o600));
}

// ---- O_PATH --------------------------------------------------------------

#[test]
fn legacy_strips_every_non_path_flag_beside_o_path_and_openat2_refuses_them() {
    let f = O_PATH as u64 | O_CLOEXEC as u64 | O_NONBLOCK as u64;
    assert_eq!(legacy(f, 0), Ok((O_PATH | O_CLOEXEC, 0)), "O_NONBLOCK is not an O_PATH flag");
    assert_eq!(at2(f, 0), Err(EINVAL));
}

#[test]
fn the_o_path_companion_flags_survive_both_entry_points() {
    let f = O_PATH as u64 | O_CLOEXEC as u64 | O_DIRECTORY as u64 | O_NOFOLLOW as u64;
    assert_eq!(legacy(f, 0), Ok((f as u32, 0)));
    assert_eq!(at2(f, 0), Ok((f as u32, 0)));
}

#[test]
fn an_access_mode_beside_o_path_is_stripped_by_legacy_and_refused_by_openat2() {
    // The access mode is not an O_PATH flag: an O_PATH fd has no read and no
    // write capability at all.
    assert_eq!(legacy(O_PATH as u64 | O_WRONLY as u64, 0), Ok((O_PATH, 0)));
    assert_eq!(at2(O_PATH as u64 | O_WRONLY as u64, 0), Err(EINVAL));
}

// ---- rules shared by both entry points -----------------------------------

#[test]
fn o_directory_with_o_creat_is_einval_on_both() {
    let f = O_DIRECTORY as u64 | O_CREAT as u64;
    assert_eq!(legacy(f, 0o755), Err(EINVAL), "creating a directory through open(2) never worked");
    assert_eq!(at2(f, 0o755), Err(EINVAL));
}

#[test]
fn o_tmpfile_requires_o_directory_and_a_writable_access_mode() {
    // O_DIRECTORY must be raised alongside so that a kernel without O_TMPFILE
    // gives an explicit error instead of opening the directory.
    assert_eq!(legacy(O_TMPFILE as u64 | O_WRONLY as u64, 0o600), Err(EINVAL));
    assert_eq!(at2(O_TMPFILE as u64 | O_WRONLY as u64, 0o600), Err(EINVAL));
    // A read-only unnamed file could never be written, so it is refused.
    let dir_tmp = O_TMPFILE as u64 | O_DIRECTORY as u64;
    assert_eq!(legacy(dir_tmp | O_RDONLY as u64, 0o600), Err(EINVAL));
    assert!(legacy(dir_tmp | O_WRONLY as u64, 0o600).is_ok());
    assert!(legacy(dir_tmp | O_RDWR as u64, 0o600).is_ok());
    assert!(at2(dir_tmp | O_RDWR as u64, 0o600).is_ok());
}

#[test]
fn the_o_directory_rejection_is_decided_before_the_o_tmpfile_rungs() {
    // O_TMPFILE|O_CREAT would otherwise reach the O_TMPFILE rungs with
    // O_DIRECTORY raised and be accepted as a create of a directory.
    assert_eq!(at2(O_TMPFILE as u64 | O_DIRECTORY as u64 | O_CREAT as u64 | O_RDWR as u64, 0o600),
        Err(EINVAL));
}

#[test]
fn o_directory_with_the_regular_file_demand_is_contradictory() {
    assert_eq!(at2(O_DIRECTORY as u64 | OPENAT2_REGULAR, 0), Err(EINVAL));
}

#[test]
fn the_sync_flag_folds_the_data_sync_bit_in() {
    // Callers that test only the data-sync bit must still see a full-sync
    // request, so the fold happens once here rather than at every reader.
    let (f, _) = legacy(O_SYNC, 0).unwrap();
    assert_ne!(f as u64 & O_DSYNC, 0, "O_SYNC implies O_DSYNC");
    let (f, _) = at2(__O_SYNC, 0).unwrap();
    assert_ne!(f as u64 & O_DSYNC, 0, "the bare sync bit alone still folds");
}

#[test]
fn the_ordinary_flags_pass_through_unchanged() {
    let f = O_RDWR as u64 | O_CREAT as u64 | O_TRUNC as u64 | O_APPEND as u64
        | O_CLOEXEC as u64 | O_NONBLOCK as u64 | O_NOATIME;
    assert_eq!(legacy(f, 0o644), Ok((f as u32, 0o644)));
    assert_eq!(at2(f, 0o644), Ok((f as u32, 0o644)));
}

// ---- flag-word decode into the permission rungs --------------------------

#[test]
fn the_access_mode_decides_write_mode_not_o_trunc() {
    // The append-only rung asks "is this a WRITE-MODE open", which O_TRUNC on a
    // read-only access mode is not — that combination is refused by the
    // truncate rung instead.
    assert!(!open_intent(O_RDONLY, false).write_mode);
    assert!(open_intent(O_WRONLY, false).write_mode);
    assert!(open_intent(O_RDWR, false).write_mode);
    assert!(!open_intent(O_RDONLY | O_TRUNC, false).write_mode);
    assert!(open_intent(O_RDONLY | O_TRUNC, false).trunc);
}

#[test]
fn a_created_file_declares_no_truncate() {
    // There is nothing yet to truncate, so a fresh file must not trip the
    // append-only truncate rung on a mode it inherited.
    assert!(open_intent(O_WRONLY | O_TRUNC, true).trunc == false);
    assert!(open_intent(O_WRONLY | O_TRUNC, false).trunc);
}

#[test]
fn append_and_noatime_reach_the_rungs_that_gate_them() {
    let i = open_intent(O_WRONLY | O_APPEND, false);
    assert!(i.write_mode && i.append && !i.noatime);
    let i = open_intent(O_RDONLY | O_NOATIME as u32, false);
    assert!(i.noatime && !i.write_mode, "O_NOATIME is decided independently of the access mode");
}

// ---- where the mount write admission stands ------------------------------

#[test]
fn only_a_truncating_regular_open_takes_mount_write_before_the_permission_ladder() {
    // The one case that must report EROFS ahead of EACCES.
    assert!(trunc_needs_mount_write(O_WRONLY | O_TRUNC, FileType::Regular, false));
    // A plain write-open does NOT: its admission runs after the ladder, so a
    // caller who also lacks permission is told EACCES.
    assert!(!trunc_needs_mount_write(O_WRONLY, FileType::Regular, false));
    assert!(!trunc_needs_mount_write(O_RDWR, FileType::Regular, false));
    // A read-only open takes no write admission at all.
    assert!(!trunc_needs_mount_write(O_RDONLY, FileType::Regular, false));
}

#[test]
fn a_created_file_does_not_take_the_early_mount_write_admission() {
    assert!(!trunc_needs_mount_write(O_WRONLY | O_TRUNC, FileType::Regular, true));
}

#[test]
fn special_file_types_are_exempt_from_the_early_mount_write_admission() {
    // An open of a device or FIFO addresses the driver; a read-only bind mount
    // of /dev must not stop a sandboxed service opening a device node.
    for ftype in [FileType::CharDev, FileType::BlockDev, FileType::Fifo, FileType::Socket] {
        assert!(!trunc_needs_mount_write(O_WRONLY | O_TRUNC, ftype, false),
            "special file types ignore O_TRUNC outright");
    }
    // A directory cannot be write-opened at all.
    assert!(!trunc_needs_mount_write(O_WRONLY | O_TRUNC, FileType::Directory, false));
}
