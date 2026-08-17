//! The two live VM tunables the per-zone watermarks are a function of.
//!
//! A write here is not a stored preference: it re-runs the one watermark
//! producer, so the allocation gate and the reclaim policy both move with it.
//! Reading `min_free_kbytes` reports the EFFECTIVE value — the kernel-derived
//! default until an operator sets one — because that is the number the
//! watermarks were actually derived from.

use super::{default_min_free_kbytes, WatermarkTunables, DEFAULT_WATERMARK_SCALE_FACTOR};
use core::sync::atomic::{AtomicU64, Ordering};

/// Smallest scale factor an operator may set; zero would erase the low/high
/// distance the scale factor exists to widen.
pub const SCALE_FACTOR_MIN: u64 = 1;
/// Largest scale factor an operator may set.
pub const SCALE_FACTOR_MAX: u64 = 3_000;

/// Operator-set `min_free_kbytes`, or zero while none has been set.
static USER_MIN_FREE_KBYTES: AtomicU64 = AtomicU64::new(0);
static SCALE_FACTOR: AtomicU64 = AtomicU64::new(DEFAULT_WATERMARK_SCALE_FACTOR);

/// The tunables every watermark derivation reads. # C: O(1)
pub fn current() -> WatermarkTunables {
    let user = USER_MIN_FREE_KBYTES.load(Ordering::Acquire);
    WatermarkTunables {
        min_free_kbytes: if user == 0 { None } else { Some(user) },
        watermark_scale_factor: SCALE_FACTOR.load(Ordering::Acquire),
    }
}

/// The `min_free_kbytes` the derivation would use over `total_managed_pages`.
/// # C: O(1)
pub fn effective_min_free_kbytes(total_managed_pages: u64, page_bytes: u64) -> u64 {
    match current().min_free_kbytes {
        Some(kb) => kb,
        None => default_min_free_kbytes(total_managed_pages, page_bytes),
    }
}

/// Clamp an operator-supplied scale factor to the range the leaf accepts.
/// # C: O(1)
pub const fn clamp_scale_factor(value: u64) -> u64 {
    if value < SCALE_FACTOR_MIN { SCALE_FACTOR_MIN } else if value > SCALE_FACTOR_MAX { SCALE_FACTOR_MAX } else { value }
}

/// Set `min_free_kbytes` and re-derive every zone's watermarks. Zero restores
/// the kernel-derived default. # C: O(NR_ZONES^2)
pub fn set_min_free_kbytes(kbytes: u64) {
    USER_MIN_FREE_KBYTES.store(kbytes, Ordering::Release);
    refresh();
}

/// Set `watermark_scale_factor` and re-derive every zone's watermarks.
/// # C: O(NR_ZONES^2)
pub fn set_watermark_scale_factor(value: u64) {
    SCALE_FACTOR.store(clamp_scale_factor(value), Ordering::Release);
    refresh();
}

/// Re-run the watermark producer against the current tunables. Silently does
/// nothing before the allocator exists, which is the only state in which no
/// watermark can be derived. # C: O(NR_ZONES^2)
pub fn refresh() {
    if let Some(p) = crate::setup::pmm_static() { p.refresh_watermarks(current()); }
}

/// Pages every zone manages, summed — the total the per-zone minimum is
/// apportioned from. # C: O(NR_ZONES)
pub fn total_managed_pages() -> u64 {
    let Some(p) = crate::setup::pmm_static() else { return 0 };
    p.zone_snapshot().iter().map(|z| z.managed_pages).sum()
}

/// The `min_free_kbytes` a reader of the live system should see. # C: O(NR_ZONES)
pub fn live_min_free_kbytes() -> u64 {
    effective_min_free_kbytes(total_managed_pages(), hal::PAGE_SIZE_BYTES)
}

/// The `watermark_scale_factor` a reader of the live system should see.
/// # C: O(1)
pub fn live_watermark_scale_factor() -> u64 { SCALE_FACTOR.load(Ordering::Acquire) }

#[cfg(test)]
mod tests;
