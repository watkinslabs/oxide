//! The runlist: where a non-resident attribute's clusters are.
//!
//! A run is a length and a cluster number, packed as tightly as each will go:
//! one header byte says how many bytes each of the two occupies, low nibble
//! for the length and high nibble for the offset. The offset is a SIGNED
//! DELTA from the previous run's cluster, not an absolute number — which is
//! what keeps a fragmented file's runlist small, and what makes reading it as
//! unsigned put every run after the first in the wrong place.
//!
//! A run with an offset width of ZERO is a HOLE: the file has those clusters
//! but nothing is allocated for them, and reading them returns zeros. Treating
//! a hole as cluster zero reads the boot sector into the middle of a file.

use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::uapi::SPARSE_LCN;

/// One run of a file's clusters.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Run {
    /// First cluster of the FILE this run covers.
    pub vcn: u64,
    /// First cluster of the VOLUME it maps to, or `SPARSE_LCN` for a hole.
    pub lcn: u64,
    pub len: u64,
}

impl Run {
    /// Whether this run is a hole. # C: O(1)
    pub fn is_hole(&self) -> bool { self.lcn == SPARSE_LCN }
}

/// A whole attribute's runs, in file order.
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct Runs {
    pub runs: Vec<Run>,
}

impl Runs {
    /// # C: O(1)
    pub fn new() -> Self { Self { runs: Vec::new() } }

    /// Clusters the runs cover. # C: O(runs)
    pub fn clusters(&self) -> u64 { self.runs.iter().map(|r| r.len).sum() }

    /// Clusters actually ALLOCATED, which a sparse file has fewer of than it
    /// covers. # C: O(runs)
    pub fn allocated(&self) -> u64 {
        self.runs.iter().filter(|r| !r.is_hole()).map(|r| r.len).sum()
    }

    /// The volume cluster holding file cluster `vcn`, or `None` when the file
    /// does not reach that far. A hole answers `Some(SPARSE_LCN)`.
    /// # C: O(runs)
    pub fn lookup(&self, vcn: u64) -> Option<u64> {
        for run in &self.runs {
            if vcn >= run.vcn && vcn < run.vcn + run.len {
                if run.is_hole() { return Some(SPARSE_LCN); }
                return Some(run.lcn + (vcn - run.vcn));
            }
        }
        None
    }

    /// The run holding file cluster `vcn`. # C: O(runs)
    pub fn run_at(&self, vcn: u64) -> Option<&Run> {
        self.runs.iter().find(|r| vcn >= r.vcn && vcn < r.vcn + r.len)
    }

    /// Append a run, merging it with the last when the two are adjacent in
    /// both the file and the volume.
    ///
    /// Merging is not cosmetic: an unmerged list grows a run per append, and
    /// the packed form of a long list no longer fits the record it must be
    /// written back into.
    /// # C: O(1)
    pub fn push(&mut self, run: Run) {
        if let Some(last) = self.runs.last_mut() {
            let contiguous = last.vcn + last.len == run.vcn
                && ((last.is_hole() && run.is_hole())
                    || (!last.is_hole() && !run.is_hole() && last.lcn + last.len == run.lcn));
            if contiguous { last.len += run.len; return; }
        }
        self.runs.push(run);
    }
}

/// Why a packed runlist was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RunError {
    /// A header byte's widths reach past the packed bytes.
    Truncated,
    /// A width larger than eight bytes.
    BadWidth,
    /// A run of no clusters.
    ZeroLength,
    /// The runs do not cover the range the attribute declared.
    Mismatch,
    /// A cluster number outside the volume.
    OutOfRange,
}

impl RunError {
    /// # C: O(1)
    pub fn errno(self) -> Errno { Errno::Eio }
}

/// Read `width` bytes as an unsigned value. # C: O(width)
fn unsigned(bytes: &[u8], width: usize) -> u64 {
    let mut out = 0u64;
    for i in (0..width).rev() { out = (out << 8) | u64::from(bytes[i]); }
    out
}

/// Read `width` bytes as a SIGNED value, sign-extended from its top byte.
/// # C: O(width)
fn signed(bytes: &[u8], width: usize) -> i64 {
    if width == 0 { return 0; }
    let mut out: i64 = if bytes[width - 1] & 0x80 != 0 { -1 } else { 0 };
    for i in (0..width).rev() {
        out = (out << 8) | i64::from(bytes[i]);
    }
    out
}

/// Decode a packed runlist covering file clusters `svcn`..=`evcn`.
///
/// `clusters` bounds the volume, so a run naming clusters the medium does not
/// have is refused rather than read later as a device error in the middle of a
/// file.
/// # C: O(packed bytes)
pub fn unpack(packed: &[u8], svcn: u64, evcn: u64, clusters: u64) -> Result<Runs, RunError> {
    let mut out = Runs::new();
    if evcn + 1 == svcn { return Ok(out); }
    if evcn < svcn { return Err(RunError::Mismatch); }

    let mut at = 0usize;
    let mut vcn = svcn;
    let mut prev_lcn: i64 = 0;
    while at < packed.len() {
        let header = packed[at];
        at += 1;
        let len_width = usize::from(header & 0x0F);
        let off_width = usize::from(header >> 4);
        // A zero length width ends the list, which is how a runlist that
        // does not fill its attribute terminates.
        if len_width == 0 { break; }
        if len_width > 8 || off_width > 8 { return Err(RunError::BadWidth); }
        if at + len_width > packed.len() { return Err(RunError::Truncated); }
        let len = unsigned(&packed[at..], len_width);
        at += len_width;
        if len == 0 { return Err(RunError::ZeroLength); }

        let lcn = if off_width == 0 {
            // No offset at all: the run is a hole.
            SPARSE_LCN
        } else {
            if at + off_width > packed.len() { return Err(RunError::Truncated); }
            let delta = signed(&packed[at..], off_width);
            at += off_width;
            let next = prev_lcn.checked_add(delta).ok_or(RunError::OutOfRange)?;
            if next < 0 { return Err(RunError::OutOfRange); }
            prev_lcn = next;
            next as u64
        };
        if lcn != SPARSE_LCN {
            let end = lcn.checked_add(len).ok_or(RunError::OutOfRange)?;
            if clusters != 0 && end > clusters { return Err(RunError::OutOfRange); }
        }
        let next_vcn = vcn.checked_add(len).ok_or(RunError::OutOfRange)?;
        if next_vcn > evcn + 1 { return Err(RunError::Mismatch); }
        out.push(Run { vcn, lcn, len });
        vcn = next_vcn;
    }
    Ok(out)
}

/// The narrowest number of bytes an unsigned value needs. # C: O(1)
fn unsigned_width(value: u64) -> usize {
    let mut width = 1usize;
    let mut v = value >> 8;
    while v != 0 { width += 1; v >>= 8; }
    // A value whose top bit is set needs one more byte, or it reads back
    // negative — the packed form has no unsigned marker.
    if value >> ((width * 8) - 1) & 1 == 1 { width += 1; }
    width
}

/// The narrowest number of bytes a signed value needs. # C: O(1)
fn signed_width(value: i64) -> usize {
    let mut width = 1usize;
    while width < 8 {
        let bits = width * 8;
        let min = -(1i64 << (bits - 1));
        let max = (1i64 << (bits - 1)) - 1;
        if value >= min && value <= max { return width; }
        width += 1;
    }
    8
}

/// Pack a runlist back into the form an attribute stores.
///
/// The inverse of [`unpack`], and the reason it exists: a runlist that only
/// decodes is a read-only filesystem. A run's offset is written as the delta
/// from the previous run's, so the two directions must agree about which run
/// "previous" means — a hole is skipped rather than resetting it.
/// # C: O(runs)
pub fn pack(runs: &Runs) -> Vec<u8> {
    let mut out = Vec::new();
    let mut prev_lcn: i64 = 0;
    for run in &runs.runs {
        let len_width = unsigned_width(run.len);
        let (off_width, delta) = if run.is_hole() {
            (0usize, 0i64)
        } else {
            let delta = run.lcn as i64 - prev_lcn;
            prev_lcn = run.lcn as i64;
            (signed_width(delta), delta)
        };
        out.push(((off_width as u8) << 4) | len_width as u8);
        for i in 0..len_width { out.push(((run.len >> (i * 8)) & 0xFF) as u8); }
        for i in 0..off_width { out.push(((delta >> (i * 8)) & 0xFF) as u8); }
    }
    // The terminator: a header byte of zero, which ends the walk.
    out.push(0);
    out
}

#[cfg(test)]
#[path = "tests/run.rs"]
mod tests;
