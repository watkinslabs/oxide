//! `/proc/fs/f2fs/<dev>/` — the reports too wide to be sysfs attributes.
//!
//! A sysfs attribute is one value. These are tables: every segment's type and
//! occupancy, every segment's validity bitmap, the address layout, the depth
//! of the pending-discard queue. Upstream puts exactly these in `/proc/fs`
//! for that reason, and the formats below are the ones its tools parse.
//!
//! Module manifest:
//! - `segment`:  `segment_info` and `segment_bits`, over the segment table.
//! - `disk_map`: where each area of the volume begins, and how big it is.
//! - `discard`:  `discard_plist_info`, the pending queue by request length.
//! - `iostat`:   `iostat_info`, bytes and requests by the layer that made them.
//! - `victim`:   `victim_bits`, the sections the cleaner has already chosen.
//! - `inject`:   `inject_stats`, operations failed on purpose, per site.

mod disk_map;
mod discard;
mod inject;
mod iostat;
mod segment;
mod victim;

#[cfg(test)]
#[path = "tests/procfs.rs"]
mod tests;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fsattr::{dev_id, Attr};
use crate::mount::F2fs;

pub use disk_map::disk_map_body;
pub use discard::{discard_plist_body, plist_idx, MAX_PLIST_NUM};
pub use segment::{segment_bits_body, segment_info_body};
pub use victim::victim_bits_body;

/// The name this filesystem claims under `/proc/fs`. # C: O(1)
pub const FS_NAME: &str = crate::mount::F2FS_NAME;

/// The directory one mount's files live under. # C: O(len)
pub fn mount_dir(source: &str) -> String { dev_id(source) }

/// Every file one mount publishes.
///
/// One of upstream's eight is absent. `donation_list` reports the files that
/// have handed their cached pages to the reclaim machinery, with each one's
/// donated range and how much of it is still cached — a list this build has
/// nothing to fill, because it has no page-donation machinery at all: no
/// interface for a file to donate a range, no per-inode donated span, and no
/// reclaim path that consumes one. An empty file under that name would report
/// that no file has donated, which is a different statement from the one that
/// is true, so the name is left unpublished until the machinery exists.
/// # C: O(1)
pub fn mount_files(fs: &Arc<F2fs>) -> Vec<Attr> {
    let dev = mount_dir(fs.source());
    alloc::vec![
        segment::info_file(fs, &dev),
        segment::bits_file(fs, &dev),
        disk_map::file(fs, &dev),
        discard::file(fs, &dev),
        iostat::file(fs, &dev),
        victim::file(fs, &dev),
        inject::file(fs, &dev),
    ]
}
