//! The feature gates and the commands behind them: encryption,
//! compression, and the multi-device movers.
//!
//! Each ordering test is its own positive control: it arranges a caller
//! that fails TWO checks at once and requires the earlier one to be the
//! answer. Reversing the two checks in the ladder makes exactly these
//! tests go red while every single-fault test stays green.

use syscall::errno::Errno;

use crate::flags::{FEATURE_COMPRESSION, FEATURE_ENCRYPT, FEATURE_VERITY};
use crate::ioctl::arg::KeySpec;
use crate::ioctl::perm::{admit, Ctx, FileFacts, VolFacts};
use crate::ioctl::req::Req;

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

// ---- the feature gates ----------------------------------------------------

#[test]
fn a_volume_without_encryption_answers_no_encryption_command() {
    let mut v = vol();
    v.features = 0;
    let specifier = KeySpec::Identifier([0u8; 16]);
    for r in [Req::GetEncryptionPolicy, Req::GetEncryptionNonce, Req::GetEncryptionPwsalt,
              Req::GetEncryptionKeyStatus { spec: specifier },
              Req::RemoveEncryptionKey { spec: specifier, all_users: false }] {
        assert_eq!(admit(&r, &root(), &v, &reg()), Err(Errno::Eopnotsupp), "{r:?}");
    }
}

/// The feature comes FIRST, ahead of the mount's write reference: a volume
/// that never had encryption gives the same answer writable or not.
#[test]
fn the_missing_feature_is_reported_ahead_of_the_read_only_mount() {
    let mut v = vol();
    v.features = 0;
    let c = Ctx { mnt_writable: false, ..root() };
    assert_eq!(admit(&Req::GetEncryptionPwsalt, &c, &v, &reg()), Err(Errno::Eopnotsupp));
    // With the feature, the same caller is refused for the mount.
    assert_eq!(admit(&Req::GetEncryptionPwsalt, &c, &vol(), &reg()), Err(Errno::Erofs));
}

#[test]
fn a_volume_without_verity_answers_no_verity_command() {
    let mut v = vol();
    v.features = 0;
    assert_eq!(admit(&Req::MeasureVerity { capacity: 64 }, &root(), &v, &reg()),
               Err(Errno::Eopnotsupp));
}

#[test]
fn measuring_a_file_that_is_not_sealed_reports_no_such_data() {
    assert_eq!(admit(&Req::MeasureVerity { capacity: 64 }, &root(), &vol(), &reg()),
               Err(Errno::Enodata));
    let sealed = FileFacts { verity: true, ..reg() };
    assert_eq!(admit(&Req::MeasureVerity { capacity: 64 }, &root(), &vol(), &sealed), Ok(()));
}

// ---- compression ----------------------------------------------------------

#[test]
fn the_compression_feature_gates_every_compression_command() {
    let mut v = vol();
    v.features = 0;
    for r in [Req::GetCompressBlocks, Req::GetCompressOption, Req::ReleaseCompressBlocks,
              Req::ReserveCompressBlocks, Req::CompressFile, Req::DecompressFile] {
        assert_eq!(admit(&r, &root(), &v, &reg()), Err(Errno::Eopnotsupp), "{r:?}");
    }
}

/// Asking a file that is not compressed for its saved blocks and for its
/// codec give DIFFERENT answers, and tools branch on the difference.
#[test]
fn the_two_compression_queries_refuse_an_uncompressed_file_differently() {
    assert_eq!(admit(&Req::GetCompressBlocks, &root(), &vol(), &reg()), Err(Errno::Einval));
    assert_eq!(admit(&Req::GetCompressOption, &root(), &vol(), &reg()), Err(Errno::Enodata));
}

#[test]
fn releasing_the_saved_blocks_needs_to_be_the_only_writer() {
    let f = FileFacts { compressed: true, compr_blocks: 4, ..reg() };
    assert_eq!(admit(&Req::ReleaseCompressBlocks, &root(), &vol(), &f), Ok(()));
    let busy = Ctx { writecount: 2, ..root() };
    assert_eq!(admit(&Req::ReleaseCompressBlocks, &busy, &vol(), &f), Err(Errno::Ebusy));
    // On a read-only description any writer at all is one too many.
    let ro = Ctx { fmode_write: false, writecount: 1, ..root() };
    assert_eq!(admit(&Req::ReleaseCompressBlocks, &ro, &vol(), &f), Err(Errno::Ebusy));
    let ro_idle = Ctx { fmode_write: false, writecount: 0, ..root() };
    assert_eq!(admit(&Req::ReleaseCompressBlocks, &ro_idle, &vol(), &f), Ok(()));
}

/// Nothing saved means nothing to hand back; marking the file released would
/// only make it unwritable for no gain.
#[test]
fn releasing_a_compressed_file_that_saved_nothing_is_refused() {
    let f = FileFacts { compressed: true, compr_blocks: 0, ..reg() };
    assert_eq!(admit(&Req::ReleaseCompressBlocks, &root(), &vol(), &f), Err(Errno::Eperm));
}

/// The busy test comes BEFORE the file's own state: a second writer makes the
/// answer wrong whatever the file is.
#[test]
fn a_second_writer_is_reported_ahead_of_the_file_not_being_compressed() {
    let busy = Ctx { writecount: 3, ..root() };
    assert_eq!(admit(&Req::ReleaseCompressBlocks, &busy, &vol(), &reg()), Err(Errno::Ebusy));
    assert_eq!(admit(&Req::ReleaseCompressBlocks, &root(), &vol(), &reg()),
               Err(Errno::Einval));
}

#[test]
fn reserving_needs_a_released_compressed_file() {
    let released = FileFacts { compressed: true, compress_released: true, ..reg() };
    assert_eq!(admit(&Req::ReserveCompressBlocks, &root(), &vol(), &released), Ok(()));
    let live = FileFacts { compressed: true, ..reg() };
    assert_eq!(admit(&Req::ReserveCompressBlocks, &root(), &vol(), &live), Err(Errno::Einval));
}

#[test]
fn setting_the_codec_refuses_an_unknown_one_and_a_cluster_out_of_bounds() {
    use crate::compress::algo::{COMPRESS_MAX, MAX_COMPRESS_LOG_SIZE, MIN_COMPRESS_LOG_SIZE};
    let f = FileFacts { compressed: true, ..reg() };
    let ok = Req::SetCompressOption { algorithm: 0, log_cluster_size: MIN_COMPRESS_LOG_SIZE };
    assert_eq!(admit(&ok, &root(), &vol(), &f), Ok(()));
    let bad_alg = Req::SetCompressOption {
        algorithm: COMPRESS_MAX, log_cluster_size: MIN_COMPRESS_LOG_SIZE,
    };
    assert_eq!(admit(&bad_alg, &root(), &vol(), &f), Err(Errno::Einval));
    let small = Req::SetCompressOption {
        algorithm: 0, log_cluster_size: MIN_COMPRESS_LOG_SIZE - 1,
    };
    assert_eq!(admit(&small, &root(), &vol(), &f), Err(Errno::Einval));
    let large = Req::SetCompressOption {
        algorithm: 0, log_cluster_size: MAX_COMPRESS_LOG_SIZE + 1,
    };
    assert_eq!(admit(&large, &root(), &vol(), &f), Err(Errno::Einval));
}

#[test]
fn setting_the_codec_refuses_a_mapped_or_dirty_or_already_written_file() {
    let f = FileFacts { compressed: true, ..reg() };
    let ok = Req::SetCompressOption { algorithm: 0, log_cluster_size: 4 };
    assert_eq!(admit(&ok, &Ctx { mmapped: true, ..root() }, &vol(), &f), Err(Errno::Ebusy));
    assert_eq!(admit(&ok, &Ctx { dirty_pages: 1, ..root() }, &vol(), &f), Err(Errno::Ebusy));
    let written = FileFacts { compressed: true, has_blocks: true, ..reg() };
    assert_eq!(admit(&ok, &root(), &vol(), &written), Err(Errno::Efbig));
}

/// Rewriting clusters by hand only means anything when the mount is not doing
/// it, and that is decided ahead of the descriptor's access mode.
#[test]
fn rewriting_clusters_is_refused_when_the_mount_drives_compression() {
    let mut v = vol();
    v.compress_mode_user = false;
    let c = Ctx { fmode_write: false, ..root() };
    assert_eq!(admit(&Req::CompressFile, &c, &v, &reg()), Err(Errno::Eopnotsupp));
    assert_eq!(admit(&Req::CompressFile, &c, &vol(), &reg()), Err(Errno::Ebadf));
}

// ---- defragment, move, flush ---------------------------------------------

#[test]
fn defragmenting_needs_block_aligned_bounds_inside_the_file_ceiling() {
    let ok = Req::Defragment { start: 0, len: 4096 };
    assert_eq!(admit(&ok, &root(), &vol(), &reg()), Ok(()));
    let unaligned = Req::Defragment { start: 1, len: 4096 };
    assert_eq!(admit(&unaligned, &root(), &vol(), &reg()), Err(Errno::Einval));
    let huge = Req::Defragment { start: 0, len: (1u64 << 20) * 4096 * 2 };
    assert_eq!(admit(&huge, &root(), &vol(), &reg()), Err(Errno::Einval));
}

/// The kind of file is reported ahead of the read-only mount here, which is
/// the reverse of the atomic-write ladder — the two orders differ upstream
/// and a caller on a read-only mount sending a directory sees the difference.
#[test]
fn defragmenting_reports_the_wrong_kind_ahead_of_the_read_only_volume() {
    let mut v = vol();
    v.writable = false;
    let d = FileFacts { is_reg: false, is_dir: true, ..reg() };
    assert_eq!(admit(&Req::Defragment { start: 0, len: 0 }, &root(), &v, &d),
               Err(Errno::Einval));
    assert_eq!(admit(&Req::Defragment { start: 0, len: 0 }, &root(), &v, &reg()),
               Err(Errno::Erofs));
}

#[test]
fn moving_a_range_needs_a_description_open_both_ways() {
    let r = Req::MoveRange { dst_fd: 3, pos_in: 0, pos_out: 0, len: 4096 };
    let ok = Ctx { dst: crate::ioctl::DstFd::Ours(9), ..root() };
    assert_eq!(admit(&r, &ok, &vol(), &reg()), Ok(()));
    assert_eq!(admit(&r, &Ctx { fmode_read: false, ..ok }, &vol(), &reg()),
               Err(Errno::Ebadf));
    assert_eq!(admit(&r, &Ctx { fmode_write: false, ..ok }, &vol(), &reg()),
               Err(Errno::Ebadf));
}

/// The two ways a destination can be wrong are refused at DIFFERENT rungs, and
/// which rung decides which errno the caller is told.
///
/// A descriptor that cannot be written is not a destination at all and is
/// refused before the mount's write reference is taken — so a read-only MOUNT
/// with a bad destination still reports the bad descriptor. One naming another
/// mount is a good descriptor pointing somewhere else, and is refused after,
/// so the same read-only mount reports the mount instead.
#[test]
fn a_destination_that_cannot_be_written_is_refused_ahead_of_the_mount() {
    use crate::ioctl::DstFd;
    let r = Req::MoveRange { dst_fd: 3, pos_in: 0, pos_out: 0, len: 4096 };
    let ro = Ctx { mnt_writable: false, ..root() };

    assert_eq!(admit(&r, &Ctx { dst: DstFd::Unusable, ..root() }, &vol(), &reg()),
               Err(Errno::Ebadf));
    assert_eq!(admit(&r, &Ctx { dst: DstFd::Unusable, ..ro }, &vol(), &reg()),
               Err(Errno::Ebadf), "a bad descriptor outranks the mount");

    assert_eq!(admit(&r, &Ctx { dst: DstFd::Foreign, ..root() }, &vol(), &reg()),
               Err(Errno::Exdev));
    assert_eq!(admit(&r, &Ctx { dst: DstFd::Foreign, ..ro }, &vol(), &reg()),
               Err(Errno::Erofs), "the mount outranks a destination elsewhere");

    assert_eq!(admit(&r, &Ctx { dst: DstFd::Ours(9), ..ro }, &vol(), &reg()),
               Err(Errno::Erofs));
}

/// Emptying a device needs another device to empty it onto, which a
/// single-device volume does not have.
#[test]
fn flushing_a_device_needs_more_than_one_device() {
    let r = Req::FlushDevice { dev_num: 0, segments: 1 };
    assert_eq!(admit(&r, &root(), &vol(), &reg()), Err(Errno::Einval));
    let mut v = vol();
    v.device_count = 2;
    assert_eq!(admit(&r, &root(), &v, &reg()), Ok(()));
    // The last device has nowhere to go.
    let last = Req::FlushDevice { dev_num: 1, segments: 1 };
    assert_eq!(admit(&last, &root(), &v, &reg()), Err(Errno::Einval));
    // A section of several segments cannot express a per-segment move.
    let mut big = v;
    big.large_section = true;
    assert_eq!(admit(&r, &root(), &big, &reg()), Err(Errno::Einval));
}
