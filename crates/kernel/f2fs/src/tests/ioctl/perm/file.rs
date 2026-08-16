//! Per-file commands: staging, pinning, sealing, trimming one file, and
//! the small single-word ones.
//!
//! Each ordering test is its own positive control: it arranges a caller
//! that fails TWO checks at once and requires the earlier one to be the
//! answer. Reversing the two checks in the ladder makes exactly these
//! tests go red while every single-fault test stays green.

use syscall::errno::Errno;

use crate::flags::{FEATURE_COMPRESSION, FEATURE_ENCRYPT, FEATURE_VERITY};
use crate::ioctl::perm::{admit, Ctx, FileFacts, VolFacts};
use crate::ioctl::req::Req;
use crate::ioctl::uapi::*;

/// A caller with everything: every capability, both access modes, a writable
/// mount, sole ownership.
fn root() -> Ctx {
    Ctx {
        cap_sys_admin: true, fmode_read: true, fmode_write: true, o_direct: false,
        owner_or_capable: true, mnt_writable: true, writecount: 1, dirty_pages: 0,
        mmapped: false, dst: crate::ioctl::DstFd::Unusable,
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

// ---- atomic writes --------------------------------------------------------

#[test]
fn starting_an_atomic_write_needs_a_writable_owned_regular_buffered_file() {
    let r = Req::StartAtomicWrite { replace: false };
    assert_eq!(admit(&r, &root(), &vol(), &reg()), Ok(()));
    assert_eq!(admit(&r, &Ctx { fmode_write: false, ..root() }, &vol(), &reg()),
               Err(Errno::Ebadf));
    assert_eq!(admit(&r, &Ctx { owner_or_capable: false, ..root() }, &vol(), &reg()),
               Err(Errno::Eacces));
    assert_eq!(admit(&r, &root(), &vol(), &FileFacts { is_reg: false, ..reg() }),
               Err(Errno::Einval));
    assert_eq!(admit(&r, &Ctx { o_direct: true, ..root() }, &vol(), &reg()),
               Err(Errno::Einval));
    assert_eq!(admit(&r, &Ctx { mnt_writable: false, ..root() }, &vol(), &reg()),
               Err(Errno::Erofs));
}

/// The descriptor's access mode is reported ahead of ownership, and both
/// ahead of the file's kind. A caller holding a read-only descriptor on
/// someone else's directory is told about the descriptor.
#[test]
fn the_access_mode_is_reported_ahead_of_ownership_and_kind() {
    let c = Ctx { fmode_write: false, owner_or_capable: false, ..root() };
    let f = FileFacts { is_reg: false, ..reg() };
    assert_eq!(admit(&Req::StartAtomicWrite { replace: false }, &c, &vol(), &f),
               Err(Errno::Ebadf));
    let c = Ctx { owner_or_capable: false, ..root() };
    assert_eq!(admit(&Req::StartAtomicWrite { replace: false }, &c, &vol(), &f),
               Err(Errno::Eacces));
}

/// A pinned or compressed file cannot be staged, and that is decided AFTER
/// the mount's write reference — the write reference is what a read-only
/// mount refuses, and it refuses every file equally.
#[test]
fn the_mount_is_reported_ahead_of_the_file_being_unstageable() {
    let c = Ctx { mnt_writable: false, ..root() };
    let f = FileFacts { pinned: true, ..reg() };
    assert_eq!(admit(&Req::StartAtomicWrite { replace: false }, &c, &vol(), &f),
               Err(Errno::Erofs));
    assert_eq!(admit(&Req::StartAtomicWrite { replace: false }, &root(), &vol(), &f),
               Err(Errno::Einval));
}

/// The format kept a number for the volatile-write commands and no
/// implementation anywhere; the refusal IS the contract, not a gap.
#[test]
fn a_volatile_write_is_refused_by_definition() {
    assert_eq!(admit(&Req::VolatileWrite, &root(), &vol(), &reg()), Err(Errno::Eopnotsupp));
}

// ---- turning verity on ----------------------------------------------------

fn enable() -> Req {
    Req::EnableVerity {
        head: crate::ioctl::arg::VerityEnableHead {
            hash_algorithm: 1, block_size: 4096, salt_size: 0, salt_ptr: 0,
            sig_size: 0, sig_ptr: 0,
        },
        salt: alloc::vec::Vec::new(),
        sig: alloc::vec::Vec::new(),
    }
}

#[test]
fn sealing_needs_both_access_modes_a_regular_file_and_no_other_writer() {
    assert_eq!(admit(&enable(), &root(), &vol(), &reg()), Ok(()));
    assert_eq!(admit(&enable(), &Ctx { fmode_write: false, ..root() }, &vol(), &reg()),
               Err(Errno::Eacces));
    assert_eq!(admit(&enable(), &Ctx { fmode_read: false, ..root() }, &vol(), &reg()),
               Err(Errno::Ebadf));
    assert_eq!(admit(&enable(), &root(), &vol(),
                     &FileFacts { append_only: true, ..reg() }), Err(Errno::Eperm));
    assert_eq!(admit(&enable(), &root(), &vol(),
                     &FileFacts { is_reg: false, is_dir: true, ..reg() }), Err(Errno::Eisdir));
    assert_eq!(admit(&enable(), &root(), &vol(),
                     &FileFacts { is_reg: false, ..reg() }), Err(Errno::Einval));
    assert_eq!(admit(&enable(), &Ctx { writecount: 2, ..root() }, &vol(), &reg()),
               Err(Errno::Etxtbsy));
}

/// A directory is reported as a directory, not as "not a regular file": the
/// two are different answers and a tool walking a tree branches on them.
#[test]
fn a_directory_is_reported_as_a_directory_rather_than_as_the_wrong_kind() {
    let d = FileFacts { is_reg: false, is_dir: true, ..reg() };
    assert_eq!(admit(&enable(), &root(), &vol(), &d), Err(Errno::Eisdir));
    let other = FileFacts { is_reg: false, is_dir: false, ..reg() };
    assert_eq!(admit(&enable(), &root(), &vol(), &other), Err(Errno::Einval));
}

/// A second writer is reported LAST, after the mount: a read-only mount
/// refuses whether or not anything else has the file open.
#[test]
fn the_mount_is_reported_ahead_of_a_second_writer() {
    let c = Ctx { mnt_writable: false, writecount: 5, ..root() };
    assert_eq!(admit(&enable(), &c, &vol(), &reg()), Err(Errno::Erofs));
}

// ---- pinning --------------------------------------------------------------

#[test]
fn pinning_needs_a_regular_file_on_a_writable_volume_with_no_blocks_yet() {
    assert_eq!(admit(&Req::SetPinFile(1), &root(), &vol(), &reg()), Ok(()));
    assert_eq!(admit(&Req::SetPinFile(1), &root(), &vol(),
                     &FileFacts { is_reg: false, ..reg() }), Err(Errno::Einval));
    assert_eq!(admit(&Req::SetPinFile(1), &root(), &vol(),
                     &FileFacts { has_blocks: true, ..reg() }), Err(Errno::Efbig));
    assert_eq!(admit(&Req::SetPinFile(1), &root(), &vol(),
                     &FileFacts { compressed: true, ..reg() }), Err(Errno::Eopnotsupp));
}

/// Unpinning has none of the block conditions: they are about the promise
/// being made, and unpinning withdraws it.
#[test]
fn unpinning_a_file_that_holds_blocks_is_admitted() {
    let f = FileFacts { has_blocks: true, pinned: true, ..reg() };
    assert_eq!(admit(&Req::SetPinFile(0), &root(), &vol(), &f), Ok(()));
}

/// Pinning a file that is ALREADY pinned is how a tool makes sure of it, and
/// must not be refused for blocks the earlier pin allowed.
#[test]
fn re_pinning_an_already_pinned_file_is_admitted() {
    let f = FileFacts { has_blocks: true, pinned: true, ..reg() };
    assert_eq!(admit(&Req::SetPinFile(1), &root(), &vol(), &f), Ok(()));
}

// ---- trimming one file ----------------------------------------------------

#[test]
fn trimming_a_file_needs_a_writable_description_and_a_defined_flag() {
    let f = FileFacts { size: 8192, ..reg() };
    let ok = Req::SecTrimFile { start: 0, len: 4096, flags: TRIM_FILE_DISCARD };
    assert_eq!(admit(&ok, &root(), &vol(), &f), Ok(()));
    assert_eq!(admit(&ok, &Ctx { fmode_write: false, ..root() }, &vol(), &f),
               Err(Errno::Ebadf));
    let none = Req::SecTrimFile { start: 0, len: 4096, flags: 0 };
    assert_eq!(admit(&none, &root(), &vol(), &f), Err(Errno::Einval));
    let unknown = Req::SecTrimFile { start: 0, len: 4096, flags: TRIM_FILE_MASK + 1 };
    assert_eq!(admit(&unknown, &root(), &vol(), &f), Err(Errno::Einval));
}

#[test]
fn discarding_needs_a_device_that_discards() {
    let mut v = vol();
    v.supports_discard = false;
    let f = FileFacts { size: 8192, ..reg() };
    let r = Req::SecTrimFile { start: 0, len: 4096, flags: TRIM_FILE_DISCARD };
    assert_eq!(admit(&r, &root(), &v, &f), Err(Errno::Eopnotsupp));
    // Zeroing does not, so the same volume answers it.
    let z = Req::SecTrimFile { start: 0, len: 4096, flags: TRIM_FILE_ZEROOUT };
    assert_eq!(admit(&z, &root(), &v, &f), Ok(()));
}

#[test]
fn a_trim_starting_past_the_end_or_unaligned_is_refused() {
    let f = FileFacts { size: 8192, ..reg() };
    let past = Req::SecTrimFile { start: 8192, len: 4096, flags: TRIM_FILE_DISCARD };
    assert_eq!(admit(&past, &root(), &vol(), &f), Err(Errno::Einval));
    let unaligned = Req::SecTrimFile { start: 1, len: 4096, flags: TRIM_FILE_DISCARD };
    assert_eq!(admit(&unaligned, &root(), &vol(), &f), Err(Errno::Einval));
}

/// A zero-length trim is a no-op, not an error: a caller looping over a file
/// hits it at the end.
#[test]
fn a_zero_length_trim_is_admitted() {
    let f = FileFacts { size: 8192, ..reg() };
    let r = Req::SecTrimFile { start: 0, len: 0, flags: TRIM_FILE_DISCARD };
    assert_eq!(admit(&r, &root(), &vol(), &f), Ok(()));
}

// ---- the small ones -------------------------------------------------------

#[test]
fn a_priority_outside_the_defined_set_is_refused() {
    assert_eq!(admit(&Req::IoPrio(IOPRIO_WRITE), &root(), &vol(), &reg()), Ok(()));
    assert_eq!(admit(&Req::IoPrio(IOPRIO_MAX), &root(), &vol(), &reg()), Err(Errno::Einval));
    assert_eq!(admit(&Req::IoPrio(IOPRIO_WRITE), &root(), &vol(),
                     &FileFacts { is_reg: false, ..reg() }), Err(Errno::Einval));
}

#[test]
fn precaching_a_file_with_extent_caching_off_is_refused() {
    assert_eq!(admit(&Req::PrecacheExtents, &root(), &vol(), &reg()), Ok(()));
    assert_eq!(admit(&Req::PrecacheExtents, &root(), &vol(),
                     &FileFacts { no_extent: true, ..reg() }), Err(Errno::Eopnotsupp));
}

#[test]
fn resizing_needs_the_capability_and_a_writable_volume() {
    assert_eq!(admit(&Req::ResizeFs(1 << 20), &root(), &vol(), &reg()), Ok(()));
    assert_eq!(admit(&Req::ResizeFs(1 << 20), &Ctx { cap_sys_admin: false, ..root() },
                     &vol(), &reg()), Err(Errno::Eperm));
    let mut v = vol();
    v.writable = false;
    assert_eq!(admit(&Req::ResizeFs(1 << 20), &root(), &v, &reg()), Err(Errno::Erofs));
}

#[test]
fn setting_the_label_needs_the_capability_and_a_writable_mount() {
    let label = Req::SetFsLabel(alloc::vec![b'a']);
    assert_eq!(admit(&label, &root(), &vol(), &reg()), Ok(()));
    assert_eq!(admit(&label, &Ctx { cap_sys_admin: false, ..root() }, &vol(), &reg()),
               Err(Errno::Eperm));
    assert_eq!(admit(&label, &Ctx { mnt_writable: false, ..root() }, &vol(), &reg()),
               Err(Errno::Erofs));
}

#[test]
fn trimming_free_space_needs_the_capability_and_a_device_that_discards() {
    let r = Req::Fitrim { start: 0, len: u64::MAX, minlen: 0 };
    assert_eq!(admit(&r, &root(), &vol(), &reg()), Ok(()));
    assert_eq!(admit(&r, &Ctx { cap_sys_admin: false, ..root() }, &vol(), &reg()),
               Err(Errno::Eperm));
    let mut v = vol();
    v.supports_discard = false;
    assert_eq!(admit(&r, &root(), &v, &reg()), Err(Errno::Eopnotsupp));
}

#[test]
fn changing_the_version_needs_ownership_and_a_writable_mount() {
    assert_eq!(admit(&Req::SetVersion(7), &root(), &vol(), &reg()), Ok(()));
    assert_eq!(admit(&Req::SetVersion(7), &Ctx { owner_or_capable: false, ..root() },
                     &vol(), &reg()), Err(Errno::Eperm));
    assert_eq!(admit(&Req::SetVersion(7), &Ctx { mnt_writable: false, ..root() },
                     &vol(), &reg()), Err(Errno::Erofs));
}
