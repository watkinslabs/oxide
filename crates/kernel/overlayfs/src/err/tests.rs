//! Every errno overlayfs decides on survives the trip in both directions.

use syscall::errno::Errno;
use vfs::VfsError;

use super::{to_errno, to_vfs};

/// The errnos this filesystem's behaviour is DEFINED by: each one is a
/// distinct answer some caller acts on, so collapsing any of them into a
/// generic failure changes what happens next.
const CARRIED: &[(Errno, VfsError)] = &[
    (Errno::Eperm, VfsError::Eperm),
    (Errno::Enoent, VfsError::Enoent),
    (Errno::Eio, VfsError::Eio),
    (Errno::Enomem, VfsError::Enomem),
    (Errno::Eacces, VfsError::Eacces),
    (Errno::Ebusy, VfsError::Ebusy),
    (Errno::Eexist, VfsError::Eexist),
    (Errno::Exdev, VfsError::Exdev),
    (Errno::Enotdir, VfsError::Enotdir),
    (Errno::Eisdir, VfsError::Eisdir),
    (Errno::Einval, VfsError::Einval),
    (Errno::Enospc, VfsError::Enospc),
    (Errno::Erofs, VfsError::Erofs),
    (Errno::Emlink, VfsError::Emlink),
    (Errno::Enametoolong, VfsError::Enametoolong),
    (Errno::Enotempty, VfsError::Enotempty),
    (Errno::Eloop, VfsError::Eloop),
    (Errno::Enodata, VfsError::Enodata),
    (Errno::Eopnotsupp, VfsError::Eopnotsupp),
    (Errno::Estale, VfsError::Estale),
    (Errno::Eoverflow, VfsError::Eoverflow),
];

#[test]
fn every_carried_errno_round_trips() {
    for &(e, v) in CARRIED {
        assert_eq!(to_vfs(e), v, "{e:?}");
        assert_eq!(to_errno(v), e, "{v:?}");
    }
}

#[test]
fn the_two_that_decide_whether_a_record_is_written_are_distinct() {
    // ENODATA means nothing is recorded and one may be written; ESTALE means
    // something else is, and the merge must be refused instead.
    assert_ne!(to_vfs(Errno::Enodata), to_vfs(Errno::Estale));
    assert_eq!(to_errno(VfsError::Enodata), Errno::Enodata);
    assert_eq!(to_errno(VfsError::Estale), Errno::Estale);
}

#[test]
fn an_unmapped_failure_becomes_an_io_error_rather_than_a_wrong_answer() {
    assert_eq!(to_errno(VfsError::Epipe), Errno::Eio);
}
