//! Quota accounting, read out of files built byte by byte from the format.
//!
//! Module manifest:
//! - `image`:  a quota file assembled by hand.
//! - `format`: the two headers, and the tree shape they imply.
//! - `record`: one identity's record, in both revisions.
//! - `walk`:   finding a record, and refusing a tree that cannot be walked.
//! - `decide`: whether an allocation fits.
//! - `kinds`:  which kinds a volume offers this mount.

#[path = "quota/image.rs"] mod image;
#[path = "quota/format.rs"] mod format;
#[path = "quota/record.rs"] mod record;
#[path = "quota/walk.rs"] mod walk;
#[path = "quota/decide.rs"] mod decide;
#[path = "quota/kinds.rs"] mod kinds;

use crate::quota::QuotaError;
use syscall::errno::Errno;

#[test]
fn a_corrupt_file_is_reported_as_corruption_and_a_wrong_one_as_a_bad_argument() {
    assert_eq!(QuotaError::BadMagic.errno(), Errno::Einval);
    assert_eq!(QuotaError::BlockOutOfRange.errno(), Errno::Euclean);
    assert_eq!(QuotaError::BlocksPastEnd.errno(), Errno::Euclean);
    assert_eq!(QuotaError::Cycle.errno(), Errno::Eio);
    assert_eq!(QuotaError::NoProjectQuota.errno(), Errno::Einval);
    assert_eq!(QuotaError::NoEntry.errno(), Errno::Enoent);
}
