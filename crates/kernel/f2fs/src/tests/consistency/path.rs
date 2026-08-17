//! That the pass beside this one RUNS, on every path a volume is mounted by.
//!
//! The clauses are tested one at a time next door, over facts and a line, with
//! no volume. None of that shows anything calls them. A caller that assembles
//! an option set itself and hands it to the mount takes no line at all, and
//! before this the pair was never checked on that path — the mount succeeded
//! and ran with an option the volume cannot honour.

use sectors::MemImage;
use syscall::errno::Errno;

use crate::opts::{Mode, Options};
use crate::test_image as image;
use crate::volume::Volume;

fn img() -> MemImage { image::with_root().image() }

/// The age-threshold cleaner rewrites old blocks somewhere warmer; a volume
/// that never overwrites in place has no such choice to make. The pair is
/// refused however the option set was assembled.
#[test]
fn an_option_pair_the_volume_cannot_honour_is_refused_at_the_mount() {
    let opts = Options { atgc: true, mode: Mode::Lfs, ..Options::defaults() };
    assert_eq!(Volume::mount_with(img(), opts, true).err(), Some(Errno::Einval));
    // Either half alone is fine, so it is the PAIR that is refused and not
    // one of them.
    let a = Options { atgc: true, ..Options::defaults() };
    assert!(Volume::mount_with(img(), a, true).is_ok());
    let b = Options { mode: Mode::Lfs, ..Options::defaults() };
    assert!(Volume::mount_with(img(), b, true).is_ok());
}

/// There are no flushes to merge when nothing may be written.
#[test]
fn a_write_side_option_is_refused_on_a_mount_that_cannot_write() {
    let opts = Options { flush_merge: true, ..Options::defaults() };
    assert_eq!(Volume::mount_with(img(), opts.clone(), false).err(), Some(Errno::Einval));
    assert!(Volume::mount_with(img(), opts, true).is_ok());
}

/// Sizing an inline attribute region that the volume cannot reserve reserves
/// nothing, so naming a size on a volume without the fields is refused.
#[test]
fn a_size_for_a_region_the_volume_has_no_fields_for_is_refused() {
    let mut b = image::with_root();
    b.feature &= !crate::flags::FEATURE_FLEXIBLE_INLINE_XATTR;
    let opts = Options { inline_xattr_size: Some(40), ..Options::defaults() };
    assert_eq!(Volume::mount_with(b.image(), opts, true).err(), Some(Errno::Einval));
}
