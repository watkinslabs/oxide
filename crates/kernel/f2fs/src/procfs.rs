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

mod disk_map;
mod discard;
mod segment;

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

/// The name this filesystem claims under `/proc/fs`. # C: O(1)
pub const FS_NAME: &str = crate::mount::F2FS_NAME;

/// The directory one mount's files live under. # C: O(len)
pub fn mount_dir(source: &str) -> String { dev_id(source) }

/// Every file one mount publishes.
///
/// Four of upstream's eight are absent, each because the state behind it does
/// not exist in this build rather than because it was skipped:
///
/// - `iostat_info`: no per-type byte accounting is kept anywhere.
/// - `victim_bits`: the cleaner recomputes candidates per search and keeps no
///   victim bitmap to print.
/// - `donation_list`: there is no page-donation list.
/// - `inject_stats`: the fault-injection counters exist as a type but no
///   mount holds one, so there is nothing to count.
/// # C: O(1)
pub fn mount_files(fs: &Arc<F2fs>) -> Vec<Attr> {
    let dev = mount_dir(fs.source());
    alloc::vec![
        segment::info_file(fs, &dev),
        segment::bits_file(fs, &dev),
        disk_map::file(fs, &dev),
        discard::file(fs, &dev),
    ]
}
