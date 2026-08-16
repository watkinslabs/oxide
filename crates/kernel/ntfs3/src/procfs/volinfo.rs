//! `volinfo` — seven lines about the mounted volume.
//!
//! The renderer takes a SNAPSHOT rather than the volume, so the format is a
//! decision answerable with no device behind it, and so the volume's lock is
//! held for the read of it and not for the formatting.

use alloc::format;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::fsattr::Attr;
use crate::mount::NtfsFs;

/// What the report is rendered from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VolInfo {
    /// The NTFS version the volume was formatted at.
    pub version: (u8, u8),
    pub cluster_bytes: u32,
    /// Clusters the volume holds.
    pub clusters: u64,
    /// Records the MFT holds, and how many of them are in use — roughly the
    /// number of files and directories on the volume.
    pub records: u64,
    pub records_used: u64,
    /// Whether the volume needed a check when this mount found it.
    pub real_dirty: bool,
    /// Whether its flag reads dirty now.
    pub flagged_dirty: bool,
}

/// What a dirty line says, and what a clean one says.
const DIRTY: &str = "dirty";
const CLEAN: &str = "clean";

/// The seven lines, in the order a reader takes them. # C: O(1)
pub fn volinfo_body(v: &VolInfo) -> Vec<u8> {
    let (major, minor) = v.version;
    format!("ntfs{major}.{minor}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            v.cluster_bytes, v.clusters, v.records, v.records_used,
            if v.real_dirty { DIRTY } else { CLEAN },
            if v.flagged_dirty { DIRTY } else { CLEAN }).into_bytes()
}

/// The live volume's own snapshot. # C: O(bitmap bits)
pub fn snapshot(fs: &NtfsFs) -> VolInfo {
    let v = fs.volume.lock();
    let space = v.space();
    VolInfo {
        version: v.version(),
        cluster_bytes: v.geometry().cluster_size,
        clusters: space.total,
        records: space.records,
        records_used: space.records.saturating_sub(space.records_free),
        real_dirty: v.real_dirty(),
        flagged_dirty: v.was_dirty(),
    }
}

/// The published entry. # C: O(1)
pub fn file(fs: &Arc<NtfsFs>, dev: &str) -> Attr {
    let fs = Arc::clone(fs);
    Attr::ro(dev, "volinfo", Arc::new(move || Ok(volinfo_body(&snapshot(&fs)))))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> VolInfo {
        VolInfo { version: (3, 1), cluster_bytes: 4096, clusters: 262_144,
                  records: 1024, records_used: 40, real_dirty: false, flagged_dirty: true }
    }

    /// A reader takes these lines by POSITION, so the order and the count are
    /// the format. A line inserted or moved silently re-labels every value
    /// after it.
    #[test]
    fn the_report_is_seven_lines_in_one_order() {
        let body = volinfo_body(&sample());
        let text = core::str::from_utf8(&body).expect("utf8");
        let lines: Vec<&str> = text.trim_end_matches('\n').split('\n').collect();
        assert_eq!(lines, alloc::vec!["ntfs3.1", "4096", "262144", "1024", "40",
                                      "clean", "dirty"]);
        assert!(text.ends_with('\n'));
    }

    /// The two dirty lines answer different questions: whether the volume
    /// needs a check, and what its flag reads now. A renderer that printed one
    /// twice would tell an administrator a volume needing chkdsk is fine.
    #[test]
    fn the_two_dirty_lines_are_independent() {
        let mut v = sample();
        v.real_dirty = true;
        v.flagged_dirty = false;
        let body = volinfo_body(&v);
        let text = core::str::from_utf8(&body).expect("utf8");
        let lines: Vec<&str> = text.trim_end_matches('\n').split('\n').collect();
        assert_eq!((lines[5], lines[6]), ("dirty", "clean"));
    }

    /// The version is the volume's, spelled the way the on-disk format is
    /// named.
    #[test]
    fn the_first_line_names_the_format_version() {
        let mut v = sample();
        v.version = (1, 2);
        assert!(volinfo_body(&v).starts_with(b"ntfs1.2\n"));
    }
}
