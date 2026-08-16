//! `/sys/fs/ext4/features/` — what this build can do, whatever is mounted.
//!
//! Each entry is a name that exists and reads `supported`. There is no
//! `unsupported` value in this directory: the reference publishes a name only
//! when the code behind it was compiled in, so a tool decides by asking
//! whether the FILE is there. Publishing a name for something this build does
//! not implement would answer that question wrongly, which is worse than the
//! absence — a program would take a path that cannot work.
//!
//! What is deliberately absent, and why:
//!
//! - `batched_discard`: the range-trim request is refused, so nothing here
//!   could act on it.
//! - `meta_bg_resize`: there is no online resize.
//! - `encryption`, `verity`, `casefold`, `encrypted_casefold`: no per-file
//!   encryption, no verity trees, no case-insensitive lookup.
//! - `fast_commit`: the journal has no fast-commit path.
//! - `blocksize_gt_pagesize`: a block larger than a page is refused at mount.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fsattr::{line_str, Attr};

/// The directory the feature names live in.
const DIR: &str = "features";

/// What a present feature name reads.
const SUPPORTED: &str = "supported";

/// Feature names this build implements.
///
/// `lazy_itable_init` — a volume formatted with uninitialised inode tables is
/// zeroed group by group, paced, after it is mounted.
/// `metadata_csum_seed` — the checksum seed stored in the superblock is
/// honoured, so a volume keeps its checksums when its identifier changes.
pub const IMPLEMENTED: &[&str] = &["lazy_itable_init", "metadata_csum_seed"];

/// One entry per implemented feature. # C: O(N features)
pub fn attrs() -> Vec<Attr> {
    IMPLEMENTED.iter()
        .map(|name| Attr::ro(DIR, name, Arc::new(|| Ok(line_str(SUPPORTED)))))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tool decides by whether the name is there, so a name must not appear
    /// for a feature this build cannot perform.
    #[test]
    fn only_implemented_features_are_named() {
        let names: Vec<&str> = attrs().iter().map(|a| a.name).collect();
        assert!(names.contains(&"lazy_itable_init"));
        assert!(names.contains(&"metadata_csum_seed"));
        for absent in ["batched_discard", "meta_bg_resize", "encryption", "verity",
                       "casefold", "fast_commit", "encrypted_casefold",
                       "test_dummy_encryption_v2", "blocksize_gt_pagesize"] {
            assert!(!names.contains(&absent), "{absent} is published but not implemented");
        }
    }

    /// A feature file that is present says so in the one word a reader parses.
    #[test]
    fn a_present_feature_reads_supported() {
        for a in attrs() {
            assert_eq!(a.dir, DIR);
            assert_eq!(a.mode, crate::fsattr::RO);
            assert_eq!((a.show)().unwrap(), b"supported\n");
        }
    }

    /// The trim request is refused by the one path that would perform it, so
    /// the feature name must stay absent until it is not.
    #[test]
    fn the_trim_feature_tracks_the_trim_path() {
        assert!(!IMPLEMENTED.contains(&"batched_discard"));
    }
}
