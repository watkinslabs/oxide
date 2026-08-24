//! `/sys/fs/f2fs/<dev>/` — the controls the VOLUME owns.
//!
//! `knobs` next door publishes the background threads' controls; these turn
//! machinery that lives inside the volume itself: the two extent caches, the
//! free-node-id cache, and age-threshold victim selection. The split follows
//! the lock, not the naming — a thread's knob must not have to wait behind a
//! read fetching a block, and a volume's knob has to take that very lock.
//!
//! Every entry here reads a value some decision consults on its next round.
//! Bounds are refusals, not clamps, and each bound is owned by the module the
//! value belongs to rather than restated here, so the published surface cannot
//! come to accept a value the machinery would reject.

use alloc::sync::Arc;
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::atgc;
use crate::fsattr::Attr;
use crate::mount::F2fs;

use super::volume::{num_rw, Vol};

/// Every volume-owned control one mount publishes. # C: O(N controls)
pub(crate) fn attrs(fs: &Arc<F2fs>, dev: &str) -> Vec<Attr> {
    let mut out = alloc::vec![
        num_rw(fs, dev, "ram_thresh", |v| u64::from(v.nid_ram_thresh()), set_ram_thresh),
        num_rw(fs, dev, "max_read_extent_count",
               |v| u64::from(v.extents().max_read_extent_count()), set_max_read_extent_count),
        num_rw(fs, dev, "last_age_weight",
               |v| u64::from(v.extents().last_age_weight()), set_last_age_weight),
        num_rw(fs, dev, "hot_data_age_threshold",
               |v| u64::from(v.extents().hot_data_age_threshold()), set_hot_age),
        num_rw(fs, dev, "warm_data_age_threshold",
               |v| u64::from(v.extents().warm_data_age_threshold()), set_warm_age),
        num_rw(fs, dev, "iostat_enable",
               |v| u64::from(v.iostat_enabled()), set_iostat_enable),
        num_rw(fs, dev, "readdir_ra",
               |v| u64::from(v.readdir_ra()), set_readdir_ra),
        num_rw(fs, dev, "dirty_nats_ratio",
               |v| u64::from(v.dirty_nats_ratio()), set_dirty_nats_ratio),
        num_rw(fs, dev, "gc_segment_mode",
               |v| v.gc_segment_mode() as u64, set_gc_segment_mode),
        num_rw(fs, dev, "gc_reclaimed_segments",
               |v| u64::from(v.gc_reclaimed_segments()), set_gc_reclaimed_segments),
    ];
    out.extend(atgc::knobs::ALL.iter().map(|&k| atgc_knob(fs, dev, k)));
    out
}

/// One age-threshold control, bound to the mount whose policy it tunes.
///
/// Bound by name rather than by a stored index: the four differ only in which
/// field they reach, and a table of closures per field would be four places to
/// forget one.
/// # C: O(1)
fn atgc_knob(fs: &Arc<F2fs>, dir: &str, k: atgc::Knob) -> Attr {
    let show_fs = Arc::clone(fs);
    let store_fs = Arc::clone(fs);
    Attr::rw(
        dir,
        atgc::knobs::name(k),
        Arc::new(move || {
            let v = show_fs.volume.lock();
            Ok(crate::fsattr::line_u64(atgc::knobs::show(v.atgc(), k)))
        }),
        Arc::new(move |bytes: &[u8]| {
            let n = crate::bg::knobs::parse_value(bytes).map_err(crate::mount::errno_to_vfs)?;
            let mut v = store_fs.volume.lock();
            atgc::knobs::store(v.atgc_mut(), k, n).map_err(crate::mount::errno_to_vfs)?;
            Ok(bytes.len())
        }),
    )
}

/// The memory budget the free-id cache is held within, as a percentage.
///
/// Refused past a whole share of memory: the value is a percentage and a
/// budget of two hundred percent is a misunderstanding of the unit, not a
/// larger budget.
/// # C: O(1)
fn set_ram_thresh(v: &mut Vol, n: u64) -> Result<(), Errno> {
    if n == 0 || n > PERCENT { return Err(Errno::Einval); }
    v.set_nid_ram_thresh(n as u32);
    Ok(())
}

/// Runs one inode's read cache may hold before a split stops adding more.
/// # C: O(1)
fn set_max_read_extent_count(v: &mut Vol, n: u64) -> Result<(), Errno> {
    if n == 0 || n > u64::from(u32::MAX) { return Err(Errno::Einval); }
    v.extents_mut().set_max_read_extent_count(n as u32);
    Ok(())
}

/// How much of a block's carried-forward age is the age it already had.
/// # C: O(1)
fn set_last_age_weight(v: &mut Vol, n: u64) -> Result<(), Errno> {
    if n > PERCENT { return Err(Errno::Einval); }
    v.extents_mut().set_last_age_weight(n as u32);
    Ok(())
}

/// The age below which data counts as hot.
///
/// Refused at or above the warm boundary, and refused at zero: the two
/// thresholds cut the age line into three parts, and a pair that crosses would
/// leave one of the three empty and the other two overlapping.
/// # C: O(1)
fn set_hot_age(v: &mut Vol, n: u64) -> Result<(), Errno> {
    let warm = u64::from(v.extents().warm_data_age_threshold());
    if n == 0 || n >= warm { return Err(Errno::Einval); }
    v.extents_mut().set_hot_data_age_threshold(n as u32);
    Ok(())
}

/// The age below which data counts as warm and above which it counts as cold.
/// # C: O(1)
fn set_warm_age(v: &mut Vol, n: u64) -> Result<(), Errno> {
    let hot = u64::from(v.extents().hot_data_age_threshold());
    if n <= hot || n > u64::from(u32::MAX) { return Err(Errno::Einval); }
    v.extents_mut().set_warm_data_age_threshold(n as u32);
    Ok(())
}

/// Whether the mount charges every request to the layer that asked for it.
///
/// Any non-zero value turns it on, which is what a tool writing `1` expects
/// and what a tool writing `2` gets rather than a refusal. Turning it OFF
/// forgets the totals: a window is measured by switching off and on again, and
/// totals carried across the switch would make a fresh count impossible.
/// # C: O(N kinds)
fn set_iostat_enable(v: &mut Vol, n: u64) -> Result<(), Errno> {
    v.set_iostat_enabled(n != 0);
    Ok(())
}

/// Whether a directory listing prefetches the node block of every inode it
/// names. Any non-zero value turns it on, as the reference's own boolean
/// control does.
/// # C: O(1)
fn set_readdir_ra(v: &mut Vol, n: u64) -> Result<(), Errno> {
    v.set_readdir_ra(n != 0);
    Ok(())
}

/// Share of the node table that may be dirty before the caches are worth a
/// checkpoint on their own.
///
/// Refused past a whole share and at zero: the value is a percentage, and zero
/// would make every cached entry excessive and every operation owe a checkpoint.
/// # C: O(1)
fn set_dirty_nats_ratio(v: &mut Vol, n: u64) -> Result<(), Errno> {
    if n == 0 || n > PERCENT { return Err(Errno::Einval); }
    v.set_dirty_nats_ratio(n as u32);
    Ok(())
}

/// Selects which cleaner-policy total `gc_reclaimed_segments` reports.
/// # C: O(1)
fn set_gc_segment_mode(v: &mut Vol, n: u64) -> Result<(), Errno> {
    if n > usize::MAX as u64 { return Err(Errno::Einval); }
    v.set_gc_segment_mode(n as usize)
}

/// Linux permits only a write of zero, which resets the selected total.
/// # C: O(1)
fn set_gc_reclaimed_segments(v: &mut Vol, n: u64) -> Result<(), Errno> {
    if n != 0 { return Err(Errno::Einval); }
    v.reset_gc_reclaimed_segments()
}

/// A whole share, which is what every percentage control is bounded by.
const PERCENT: u64 = 100;

#[cfg(test)]
#[path = "../tests/sysfs/tunables.rs"]
mod tests;
