//! The two entries a directory begins with, and reading them back.
//!
//! `.` and `..` are ordinary records on FAT, not something the reader invents:
//! a subdirectory's first two entries name itself and its parent, and a
//! directory that lacks them is one nothing can walk out of. The root has
//! neither, which is why `..` in a directory of the root names cluster ZERO
//! rather than the root's own cluster — the root has no first cluster to
//! name, on any width, and a FAT32 root's cluster number is deliberately not
//! used here.
//!
//! A directory is EMPTY when these two are all it holds. Nothing else counts:
//! a freed record is not an entry, a long-name slot belongs to whatever
//! follows it, and a volume label is not a file.

use crate::dirent::{ATTR_DIR, ATTR_VOLUME, ENTRY_BYTES, Record, RecordTimes, ShortEntry};
use crate::name::flags::SHORT_NAME_LEN;
use crate::time::FatTime;

use super::find::is_free_record;

/// The eleven bytes each of the two carries, padded as every name is.
pub const DOT: [u8; SHORT_NAME_LEN] = *b".          ";
pub const DOTDOT: [u8; SHORT_NAME_LEN] = *b"..         ";

/// Offsets within a record this module reads.
const NAME: usize = 0;
const ATTR: usize = 11;

/// The two records a new directory's first cluster begins with.
///
/// `parent_start` is the parent's own first cluster, and ZERO when the parent
/// is the root. `extras` says whether the creation and access fields are
/// written, which the 8.3-only type leaves alone.
/// # C: O(1)
pub fn dot_records(cluster: u32, parent_start: u32, when: FatTime, extras: bool)
    -> [[u8; ENTRY_BYTES]; 2] {
    [record(DOT, cluster, when, extras), record(DOTDOT, parent_start, when, extras)]
}

/// One of the two. # C: O(1)
fn record(raw_name: [u8; SHORT_NAME_LEN], cluster: u32, when: FatTime, extras: bool)
    -> [u8; ENTRY_BYTES] {
    let modify = FatTime { time: when.time, date: when.date, cs: 0 };
    let times = if extras {
        RecordTimes { create: when, access_date: when.date, modify }
    } else {
        RecordTimes { create: FatTime::default(), access_date: 0, modify }
    };
    Record {
        short: ShortEntry { raw_name, attr: ATTR_DIR, cluster, size: 0 },
        lcase: 0,
        times,
    }.encode()
}

/// Whether `bytes` holds nothing but `.` and `..`. # C: O(directory bytes)
pub fn dir_is_empty(bytes: &[u8]) -> bool {
    for record in short_records(bytes) {
        let name = &record[NAME..NAME + SHORT_NAME_LEN];
        if name != DOT.as_slice() && name != DOTDOT.as_slice() { return false; }
    }
    true
}

/// Offset of the `..` record. # C: O(directory bytes)
pub fn find_dotdot(bytes: &[u8]) -> Option<u64> {
    for (index, record) in bytes.chunks_exact(ENTRY_BYTES).enumerate() {
        if record[NAME] == 0 { return None; }
        if is_free_record(record) || record[ATTR] & ATTR_VOLUME != 0 { continue; }
        if record[NAME..NAME + SHORT_NAME_LEN] == DOTDOT { return Some((index * ENTRY_BYTES) as u64); }
    }
    None
}

/// Every record that is a file, directory or dot entry, up to the end of the
/// directory. Free slots, long-name slots and the volume label are not.
/// # C: O(directory bytes)
fn short_records(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    bytes.chunks_exact(ENTRY_BYTES)
        .take_while(|r| r[NAME] != 0)
        .filter(|r| !is_free_record(r) && r[ATTR] & ATTR_VOLUME == 0)
}
