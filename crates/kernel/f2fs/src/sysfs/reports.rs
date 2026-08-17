//! `/sys/fs/f2fs/<dev>/` — reports the volume computes rather than stores.
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

use super::volume::{num, Vol};

/// The reports one mount publishes that are neither a control nor stored.
/// # C: O(1)
pub(crate) fn attrs(fs: &Arc<F2fs>, dev: &str) -> Vec<Attr> {
    alloc::vec![
        num(fs, dev, "avg_vblocks", avg_vblocks),
        num(fs, dev, "current_atomic_write", current_atomic_write),
        num(fs, dev, "unusable_blocks_per_sec", unusable_blocks_per_sec),
        num(fs, dev, "max_open_zones", max_open_zones),
    ]
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
