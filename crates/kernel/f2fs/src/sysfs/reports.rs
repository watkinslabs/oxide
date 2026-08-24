//! `/sys/fs/f2fs/<dev>/` — reports the volume computes, plus the atomic-write peak control.
//!
//! Each of these is derived on the read, from state some other module owns, and
//! that is deliberate: a stored copy is a second answer to the same question and
//! the two drift the moment one side changes. So the atomic-write total is
//! summed from the open spans the volume is actually holding rather than from a
//! counter kept beside them, and the zone figures come from the geometry the
//! members reported at mount rather than from a copy taken here.

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::fsattr::Attr;
use crate::mount::F2fs;
use crate::zoned::geom::OPEN_ZONES_UNBOUNDED;

use super::volume::{num, num_rw, Vol};

/// The reports one mount publishes, including the atomic-write peak control.
/// # C: O(1)
pub(crate) fn attrs(fs: &Arc<F2fs>, dev: &str) -> Vec<Attr> {
    alloc::vec![
        num(fs, dev, "avg_vblocks", avg_vblocks),
        num(fs, dev, "cp_foreground_calls", cp_foreground_calls),
        num(fs, dev, "cp_background_calls", cp_background_calls),
        num(fs, dev, "current_atomic_write", current_atomic_write),
        num_rw(fs, dev, "peak_atomic_write", |v| v.peak_atomic_write(), reset_peak_atomic_write),
        num(fs, dev, "defrag_blocks", defrag_blocks),
        num(fs, dev, "unusable_blocks_per_sec", unusable_blocks_per_sec),
        num(fs, dev, "max_open_zones", max_open_zones),
    ]
}

/// Checkpoint requests made by foreground callers. # C: O(1)
fn cp_foreground_calls(v: &mut Vol) -> Result<u64, Errno> {
    Ok(u64::from(v.counters().cp_call_count[crate::stats::counters::call::TOTAL]))
}

/// Checkpoint requests served by background work. # C: O(1)
fn cp_background_calls(v: &mut Vol) -> Result<u64, Errno> {
    Ok(u64::from(v.counters().cp_call_count[crate::stats::counters::call::BACKGROUND]))
}

/// Mean live blocks across the sections that are neither full nor empty.
///
/// Recomputed from the segment table on every read, which is what makes it an
/// answer about the volume as it stands. A log-structured volume wants its
/// sections at one end or the other, so the interesting number is the average
/// over the ones that are in between; a stored value would report the shape the
/// volume had when it was last sampled.
/// # C: O(main segments), plus the table read on the first call
fn avg_vblocks(v: &mut Vol) -> Result<u64, Errno> {
    let counters = v.counters();
    Ok(crate::stats::General::sample(v, &counters)?.avg_vblocks)
}

/// Blocks inside spans that are open and not yet committed.
///
/// Summed across the open spans, not counted alongside them. A span's block
/// count is already maintained where the writes land, so a second total raised
/// beside it would be a number that can disagree with the spans it describes —
/// and it would disagree exactly when a span was abandoned rather than closed.
/// # C: O(open spans)
fn current_atomic_write(v: &mut Vol) -> Result<u64, Errno> {
    Ok(v.atomic_files().into_iter()
        .map(|ino| v.atomic_write_count(ino))
        .fold(0u64, u64::saturating_add))
}

/// Linux permits only zero, which clears the peak rather than accepting a
/// replacement value. # C: O(1)
fn reset_peak_atomic_write(v: &mut Vol, n: u64) -> Result<(), Errno> {
    if n != 0 { return Err(Errno::Einval); }
    v.reset_peak_atomic_write();
    Ok(())
}

/// Defragmentation blocks moved by successful range operations. # C: O(1)
fn defrag_blocks(v: &mut Vol) -> Result<u64, Errno> {
    Ok(u64::from(v.counters().defrag_blks))
}

/// Blocks a section holds that no write can ever be placed in.
///
/// A zoned drive's zone may have less usable capacity than the space it spans,
/// and the difference is per-section dead room the volume must account for but
/// can never fill. Zero on a volume that is not zoned, which is the honest
/// answer rather than an absent attribute: the question has a value there.
/// # C: O(1)
fn unusable_blocks_per_sec(v: &mut Vol) -> Result<u64, Errno> {
    Ok(v.zones().map_or(0, |g| u64::from(g.unusable_blocks_per_sec)))
}

/// Zones the drives will let the volume hold open at once.
///
/// A drive that names no limit, and a volume that is not zoned, both read as
/// zero — the sentinel the geometry carries for "unbounded" is an internal
/// value and publishing it would tell a tool the limit is four billion.
/// # C: O(1)
fn max_open_zones(v: &mut Vol) -> Result<u64, Errno> {
    Ok(match v.zones().map(|g| g.max_open_zones) {
        None | Some(OPEN_ZONES_UNBOUNDED) => 0,
        Some(n) => u64::from(n),
    })
}

#[cfg(test)]
#[path = "../tests/sysfs/reports.rs"]
mod tests;
