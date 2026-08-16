//! Finding room for a name, and finding a name that is already there.
//!
//! A name's records must be CONTIGUOUS: the long-name slots and the short
//! entry they belong to are read as one run, and a used entry between them
//! ends the run at that point. So the search is for a run of free slots long
//! enough, restarting at every used entry, and a directory with plenty of free
//! slots scattered about can still have no room for a long name.
//!
//! One check exists only to catch a damaged directory: past the end-of-
//! directory marker every record is unused by definition, so a USED record
//! after it means the directory disagrees with itself. Filling free slots
//! beyond that point would publish a name a scan stops before ever reaching.

use syscall::errno::Errno;

use crate::dirent::{ATTR_VOLUME, DELETED_FLAG, ENTRY_BYTES};

use super::limits::FAT_MAX_DIR_SIZE;

/// Offsets within a record this search reads. The rest of the record is the
/// caller's business.
const NAME: usize = 0;
const NAME_LEN: usize = 11;
const ATTR: usize = 11;

/// Where a run of free slots was found.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum FreeRun {
    /// The whole run fits inside the directory as it stands, starting here.
    Found { at: u64 },
    /// The directory ran out with `have` free slots at its tail, beginning at
    /// `at`. The remainder needs the directory to grow, which a fixed root
    /// cannot do.
    Grow { at: u64, have: usize },
}

/// Whether a record's slot is available: never used, or used and released.
/// # C: O(1)
pub fn is_free_record(record: &[u8]) -> bool {
    record[NAME] == 0 || record[NAME] == DELETED_FLAG
}

/// A run of `need` free slots in `bytes`.
///
/// `EIO` when a used record follows the end-of-directory marker; `ENOSPC` when
/// the directory would have to pass its ceiling to hold the run.
/// # C: O(directory bytes)
pub fn find_free_run(bytes: &[u8], need: usize) -> Result<FreeRun, Errno> {
    if need == 0 { return Ok(FreeRun::Found { at: 0 }); }
    let mut run = 0usize;
    let mut start = 0u64;
    let mut saw_end = false;
    for (index, record) in bytes.chunks_exact(ENTRY_BYTES).enumerate() {
        let at = (index * ENTRY_BYTES) as u64;
        if at >= FAT_MAX_DIR_SIZE { return Err(Errno::Enospc); }
        if is_free_record(record) {
            if record[NAME] == 0 { saw_end = true; }
            if run == 0 { start = at; }
            run += 1;
            if run == need { return Ok(FreeRun::Found { at: start }); }
        } else {
            if saw_end { return Err(Errno::Eio); }
            run = 0;
        }
    }
    let end = (bytes.len() / ENTRY_BYTES * ENTRY_BYTES) as u64;
    if end >= FAT_MAX_DIR_SIZE { return Err(Errno::Enospc); }
    // The tail run continues into whatever the directory grows by, so the
    // group starts where that run started.
    Ok(FreeRun::Grow { at: if run == 0 { end } else { start }, have: run })
}

/// Offset of the short record whose eleven bytes are `raw_name`.
///
/// Free records and the volume label are skipped, and the scan stops at the
/// end-of-directory marker: a name may not be matched against a slot nothing
/// occupies, or against the label, which is not a file.
/// # C: O(directory bytes)
pub fn find_short(bytes: &[u8], raw_name: &[u8; NAME_LEN]) -> Option<u64> {
    for (index, record) in bytes.chunks_exact(ENTRY_BYTES).enumerate() {
        if record[NAME] == 0 { return None; }
        if is_free_record(record) { continue; }
        if record[ATTR] & ATTR_VOLUME != 0 { continue; }
        if &record[NAME..NAME + NAME_LEN] == raw_name.as_slice() {
            return Some((index * ENTRY_BYTES) as u64);
        }
    }
    None
}
