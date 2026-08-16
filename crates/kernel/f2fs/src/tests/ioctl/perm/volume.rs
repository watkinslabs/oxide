//! Whole-volume commands: the prologue, the administrative ladder, and
//! the two range-bearing collectors.
//!
//! Each ordering test is its own positive control: it arranges a caller
//! that fails TWO checks at once and requires the earlier one to be the
//! answer. Reversing the two checks in the ladder makes exactly these
//! tests go red while every single-fault test stays green.

use syscall::errno::Errno;

use crate::flags::{FEATURE_COMPRESSION, FEATURE_ENCRYPT, FEATURE_VERITY};
use crate::ioctl::perm::{admit, prologue, Ctx, FileFacts, VolFacts};
use crate::ioctl::req::Req;
use crate::ioctl::uapi::*;

/// A caller with everything: every capability, both access modes, a writable
/// mount, sole ownership.
fn root() -> Ctx {
    Ctx {
        cap_sys_admin: true, fmode_read: true, fmode_write: true, o_direct: false,
        owner_or_capable: true, mnt_writable: true, writecount: 1, dirty_pages: 0,
        mmapped: false,
    }
}

/// A healthy writable volume with every feature.
fn vol() -> VolFacts {
    VolFacts {
        features: FEATURE_ENCRYPT | FEATURE_VERITY | FEATURE_COMPRESSION,
        writable: true, cp_error: false, cp_disabled: false, checkpoint_ready: true,
        supports_discard: true, device_count: 1, large_section: false,
        compress_mode_user: true, compress_backend_ready: true,
        main_blkaddr: 1024, max_blkaddr: 65536, max_file_blocks: 1 << 20,
    }
}

/// An ordinary writable regular file.
fn reg() -> FileFacts {
    FileFacts { is_reg: true, size: 4096, ..FileFacts::default() }
}

// ---- the prologue ---------------------------------------------------------

#[test]
fn a_volume_whose_checkpoint_recorded_an_error_answers_nothing() {
    let mut v = vol();
    v.cp_error = true;
    assert_eq!(prologue(&v), Err(Errno::Eio));
}

/// The error comes FIRST: a volume that is both damaged and out of room is a
/// damaged volume, and a caller told it is merely full would retry forever.
#[test]
fn damage_is_reported_ahead_of_no_room() {
    let mut v = vol();
    v.cp_error = true;
    v.checkpoint_ready = false;
    assert_eq!(prologue(&v), Err(Errno::Eio));
}

#[test]
fn a_volume_with_no_room_to_checkpoint_answers_nothing() {
    let mut v = vol();
    v.checkpoint_ready = false;
    assert_eq!(prologue(&v), Err(Errno::Enospc));
}

// ---- the commands that need nothing --------------------------------------

#[test]
fn the_query_commands_admit_an_unprivileged_caller_on_a_read_only_mount() {
    let c = Ctx { cap_sys_admin: false, mnt_writable: false, ..Ctx::default() };
    let mut v = vol();
    v.writable = false;
    for r in [Req::GetFeatures, Req::GetPinFile, Req::GetDevAliasFile, Req::GetVersion,
              Req::GetFsLabel] {
        assert_eq!(admit(&r, &c, &v, &reg()), Ok(()), "{r:?}");
    }
}

// ---- capability before shape ---------------------------------------------

/// A caller with no capability sending a range that is also out of bounds is
/// told it may not, not that the range is wrong. Swapping the two checks
/// makes this red and leaves every other range test green.
#[test]
fn the_capability_is_reported_ahead_of_a_bad_range() {
    let c = Ctx { cap_sys_admin: false, ..root() };
    let bad = Req::GcRange { sync: true, start: 0, len: 0 };
    assert_eq!(admit(&bad, &c, &vol(), &reg()), Err(Errno::Eperm));
    // With the capability, the same request is refused for its range.
    assert_eq!(admit(&bad, &root(), &vol(), &reg()), Err(Errno::Einval));
}

/// A read-only mount is reported ahead of a bad range for the same reason.
#[test]
fn the_read_only_mount_is_reported_ahead_of_a_bad_range() {
    let mut v = vol();
    v.writable = false;
    let bad = Req::GcRange { sync: true, start: 0, len: 0 };
    assert_eq!(admit(&bad, &root(), &v, &reg()), Err(Errno::Erofs));
}

#[test]
fn a_range_inside_the_main_area_is_admitted() {
    let ok = Req::GcRange { sync: true, start: 2048, len: 1024 };
    assert_eq!(admit(&ok, &root(), &vol(), &reg()), Ok(()));
}

#[test]
fn a_range_that_wraps_is_refused() {
    let wrap = Req::GcRange { sync: true, start: 2048, len: u64::MAX };
    assert_eq!(admit(&wrap, &root(), &vol(), &reg()), Err(Errno::Einval));
}

// ---- the checkpoint commands ---------------------------------------------

#[test]
fn writing_a_checkpoint_needs_the_capability_a_writable_volume_and_checkpointing_on() {
    assert_eq!(admit(&Req::WriteCheckpoint, &root(), &vol(), &reg()), Ok(()));
    let c = Ctx { cap_sys_admin: false, ..root() };
    assert_eq!(admit(&Req::WriteCheckpoint, &c, &vol(), &reg()), Err(Errno::Eperm));
    let mut v = vol();
    v.writable = false;
    assert_eq!(admit(&Req::WriteCheckpoint, &root(), &v, &reg()), Err(Errno::Erofs));
    let mut v = vol();
    v.cp_disabled = true;
    assert_eq!(admit(&Req::WriteCheckpoint, &root(), &v, &reg()), Err(Errno::Einval));
}

/// The read-only mount comes before the checkpoint switch: one is about the
/// mount, the other about the volume, and a caller that can remount writable
/// needs to know which it hit.
#[test]
fn the_read_only_mount_is_reported_ahead_of_checkpointing_being_off() {
    let mut v = vol();
    v.writable = false;
    v.cp_disabled = true;
    assert_eq!(admit(&Req::WriteCheckpoint, &root(), &v, &reg()), Err(Errno::Erofs));
}

// ---- shutdown -------------------------------------------------------------

#[test]
fn shutting_down_needs_the_capability_and_a_defined_mode() {
    assert_eq!(admit(&Req::Shutdown(GOING_DOWN_FULLSYNC), &root(), &vol(), &reg()), Ok(()));
    assert_eq!(admit(&Req::Shutdown(GOING_DOWN_NEED_FSCK), &root(), &vol(), &reg()), Ok(()));
    assert_eq!(admit(&Req::Shutdown(GOING_DOWN_MAX), &root(), &vol(), &reg()),
               Err(Errno::Einval));
    let c = Ctx { cap_sys_admin: false, ..root() };
    assert_eq!(admit(&Req::Shutdown(GOING_DOWN_FULLSYNC), &c, &vol(), &reg()),
               Err(Errno::Eperm));
}

/// The capability is reported ahead of the undefined mode: an unprivileged
/// caller learns nothing about which modes exist.
#[test]
fn the_capability_is_reported_ahead_of_an_undefined_shutdown_mode() {
    let c = Ctx { cap_sys_admin: false, ..root() };
    assert_eq!(admit(&Req::Shutdown(999), &c, &vol(), &reg()), Err(Errno::Eperm));
}

/// A full-sync shutdown freezes the device rather than writing through the
/// mount, so it is the one mode a read-only mount still admits.
#[test]
fn a_full_sync_shutdown_is_admitted_on_a_read_only_mount() {
    let c = Ctx { mnt_writable: false, ..root() };
    assert_eq!(admit(&Req::Shutdown(GOING_DOWN_FULLSYNC), &c, &vol(), &reg()), Ok(()));
}
