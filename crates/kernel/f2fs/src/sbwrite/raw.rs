//! Both copies read, which one this mount believes, and whether the other is
//! bad.
//!
//! A mount that only remembers the FIELDS of the copy it believed cannot
//! repair the other one, cannot change a field without re-encoding every other
//! field from scratch, and cannot say which of the two positions its own copy
//! came from — and that position decides the order a later write takes. So the
//! bytes, the position and the verdict on the other copy are all kept.

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::sb::{self, SuperBlock};
use crate::uapi::*;

/// One superblock copy's bytes, and where they came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawSuper {
    bytes: Vec<u8>,
    valid: u64,
    recovery: bool,
    realigned: bool,
}

impl RawSuper {
    /// Take bytes that have already been read and checked. # C: O(1)
    pub fn new(bytes: Vec<u8>, valid: u64, recovery: bool) -> Self {
        Self { bytes, valid, recovery, realigned: false }
    }

    /// The copy's bytes, from its magic onward. # C: O(1)
    pub fn bytes(&self) -> &[u8] { &self.bytes }

    /// Which of the two positions this copy was read from. A later write puts
    /// the OTHER one down first. # C: O(1)
    pub fn valid(&self) -> u64 { self.valid }

    /// Whether a copy failed to read or failed its checks, and so is owed a
    /// repair. # C: O(1)
    pub fn recovery(&self) -> bool { self.recovery }

    /// Whether the main area was found short of the volume's end and the
    /// segment count corrected in memory. Correcting it is not optional — the
    /// count is what every address bound is computed against — but writing the
    /// correction down is, and that is the caller's decision. # C: O(1)
    pub fn realigned(&self) -> bool { self.realigned }

    /// The fields, read out of these bytes. # C: O(SUPER_SIZE)
    pub fn parse(&self) -> Option<SuperBlock> { sb::parse(&self.bytes) }

    /// The bytes, to patch a field. # C: O(1)
    pub(crate) fn bytes_mut(&mut self) -> &mut [u8] { &mut self.bytes }

    /// Record that the segment count was corrected. # C: O(1)
    pub(crate) fn mark_realigned(&mut self) { self.realigned = true; }
}

/// Read whichever superblock copy validates, and judge them both.
///
/// Both copies are always examined, even once one has validated: the second
/// copy's verdict is what says whether a repair is owed, and a reader that
/// stopped at the first good copy would leave a broken one broken forever.
/// Only a volume where NEITHER validates is refused.
/// # C: O(2 blocks)
#[inline(never)]
pub fn read_raw<S: SectorSource>(source: &S) -> Result<(RawSuper, SuperBlock), Errno> {
    let mut first_err = None;
    let mut found: Option<(Vec<u8>, u64)> = None;
    let mut recovery = false;
    for block in 0..SUPER_COPIES {
        let mut buf = vec![0u8; BLKSIZE];
        if source.read_sectors(block, &mut buf).is_err() {
            recovery = true;
            first_err.get_or_insert(Errno::Eio);
            continue;
        }
        let Some(raw) = buf.get(SUPER_OFFSET..SUPER_OFFSET + SUPER_SIZE) else {
            recovery = true;
            first_err.get_or_insert(Errno::Einval);
            continue;
        };
        let good = matches!(sb::parse(raw), Some(parsed) if sb::check(&parsed, raw).is_ok());
        if !good {
            recovery = true;
            first_err.get_or_insert(Errno::Einval);
            continue;
        }
        if found.is_none() { found = Some((raw.to_vec(), block)); }
    }
    let (bytes, valid) = found.ok_or(first_err.unwrap_or(Errno::Einval))?;
    let mut raw = RawSuper::new(bytes, valid, recovery);
    super::edit::realign(&mut raw);
    let parsed = raw.parse().ok_or(Errno::Einval)?;
    Ok((raw, parsed))
}

#[cfg(test)]
#[path = "../tests/sbwrite.rs"]
mod tests;
