//! Splitting one submitted I/O across the targets that cover it.
//!
//! A submission to a mapped device may span a target boundary, and a target
//! may additionally refuse to see an I/O that crosses one of its own internal
//! boundaries — a stripe chunk, a snapshot chunk, a thin block. Both limits
//! are applied here, before anything is remapped, because a piece that
//! straddles either boundary lands partly on the wrong device: the worst
//! failure this subsystem has, since it writes the right bytes to the wrong
//! place and reports success.

extern crate alloc;
use alloc::vec::Vec;

use crate::table::Table;

/// One piece of a split submission.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Piece {
    /// Index of the target in the table.
    pub target: usize,
    /// First sector of the piece, relative to the mapped device.
    pub sector: u64,
    /// Length of the piece in sectors.
    pub n_sectors: u64,
    /// Byte offset of this piece within the submission's payload.
    pub data_offset: usize,
}

/// Sectors left before `offset` crosses the next multiple of `boundary`.
/// A zero boundary means the caller imposes none, reported as no limit.
/// # C: O(1)
pub fn boundary_sectors_left(offset: u64, boundary: u64) -> u64 {
    if boundary == 0 { return u64::MAX; }
    boundary - (offset % boundary)
}

/// Longest run starting at `sector` that stays inside target `index` and
/// inside that target's own splitting boundary. # C: O(1)
pub fn max_io_len(table: &Table, index: usize, sector: u64) -> Option<u64> {
    let ti = table.target(index)?;
    let target_offset = sector.checked_sub(ti.begin)?;
    let to_target_end = ti.len.checked_sub(target_offset)?;
    let granularity = ti.target.max_io_len();
    if granularity == 0 { return Some(to_target_end); }
    Some(to_target_end.min(boundary_sectors_left(target_offset, granularity)))
}

/// Split `[sector, sector + n_sectors)` into the pieces the table's targets
/// will each accept. `bytes_per_sector` converts a sector run into the payload
/// slice that carries it; a payload-free operation passes zero.
///
/// `None` when any part of the range falls outside the table — a submission
/// past the end of the device is refused whole, never truncated, because a
/// short write that reports success is indistinguishable from a complete one.
/// # C: O(N_pieces * log N_targets)
pub fn split(table: &Table, sector: u64, n_sectors: u64, bytes_per_sector: usize) -> Option<Vec<Piece>> {
    // A zero-length submission — a flush — is placed on the target covering
    // its start sector and nothing is split.
    if n_sectors == 0 {
        let target = index_of(table, sector)?;
        return Some(alloc::vec![Piece { target, sector, n_sectors: 0, data_offset: 0 }]);
    }
    let end = sector.checked_add(n_sectors)?;
    if end > table.size() { return None; }

    let mut out = Vec::new();
    let mut cur = sector;
    while cur < end {
        let target = index_of(table, cur)?;
        let run = max_io_len(table, target, cur)?.min(end - cur);
        if run == 0 { return None; }
        out.push(Piece {
            target, sector: cur, n_sectors: run,
            data_offset: ((cur - sector) as usize) * bytes_per_sector,
        });
        cur += run;
    }
    Some(out)
}

fn index_of(table: &Table, sector: u64) -> Option<usize> { table.find_index(sector) }
