//! Whether the compression the line asked for can be true of this volume.

use syscall::errno::Errno;

use crate::opts::compress::{check_lists, Compress};
use crate::opts::Options;

/// Settle the compression group against the volume.
///
/// A volume with no compression feature DROPS the group rather than refusing
/// the mount. That is not leniency: the settings have nowhere on such a volume
/// to be recorded, so no file created on it can carry them and there is
/// nothing for the mount to get wrong. Refusing instead would make one option
/// line unusable across a set of volumes where only some were formatted for
/// compression — and the caller loses nothing it could have had.
///
/// The group is dropped WHOLE, back to its defaults, so nothing is left behind
/// to be reported back through the mount table or picked up by a later
/// remount that lands on a volume which does have the feature.
///
/// The read-side cache goes with it. It is not part of the group and is not a
/// setting a file carries, but a volume with no compression feature has no
/// compressed cluster for it to hold — so a mount left with it on would report
/// a cache that can never take an entry, and the remount refusal below would
/// then hold a mount to an option it never got.
/// # C: O(entries^2)
pub fn check_compression(feature: u32, o: &mut Options) -> Result<(), Errno> {
    if !crate::features::has_compression(feature) {
        o.compress = Compress::defaults();
        o.compress_cache = false;
        return Ok(());
    }
    check_lists(&o.compress)
}
