// Handing part of the reserved region back.
//
// A machine reserves for the worst case at boot and learns later that it does
// not need it; the alternative to shrinking is a reboot, which is exactly what
// the region exists to make unnecessary.
//
// The arithmetic is ungated so every refusal below is decided in a hosted
// test. The page-release half is a two-line loop over that decision.

use crate::crashk::{crash_base, crash_size, publish, CRASH_SHRINK_ALIGN};
use crate::uapi::PAGE_SIZE;

/// Why a shrink was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ShrinkError {
    /// A crash image is staged in the region. Reported as `ENOENT`: the
    /// region's tail is not free to give back while an image occupies it, and
    /// the caller's remedy is to unload the image first.
    Loaded,
    /// The request is larger than what is reserved. Reported as `EINVAL` —
    /// this interface only ever gives memory back, because growing would have
    /// to take pages the page allocator has already handed out.
    Grow,
    /// Nothing is reserved. Reported as `EINVAL`.
    NoRegion,
}

/// What a shrink to `want` bytes does to a region of `cur` bytes.
///
/// `Ok(n)` is the new size: `n == cur` when the request rounds back to what is
/// already reserved, which is a no-op rather than a refusal.
/// # C: O(1)
pub fn shrink_target(cur: u64, want: u64, loaded: bool) -> Result<u64, ShrinkError> {
    // Ahead of the size arithmetic: a caller with an image staged is told the
    // reason it cannot shrink, not the reason its number was wrong.
    if loaded { return Err(ShrinkError::Loaded); }
    if cur == 0 { return Err(ShrinkError::NoRegion); }
    let a = CRASH_SHRINK_ALIGN;
    let rounded = match want.checked_add(a - 1) { Some(v) => (v / a) * a, None => return Err(ShrinkError::Grow) };
    if rounded > cur { return Err(ShrinkError::Grow); }
    Ok(rounded)
}

/// Give the tail of the reserved region back to the page allocator and
/// republish the shorter one.
///
/// The publish happens BEFORE the pages are released: a crash load that ran
/// between the two would otherwise be bounded by a range whose upper half was
/// already back in general circulation.
/// # C: O(released bytes / page size)
pub fn shrink(want: u64) -> Result<(), ShrinkError> {
    let (base, cur) = (crash_base(), crash_size());
    let new = shrink_target(cur, want, crate::store::kexec_crash_loaded())?;
    if new == cur { return Ok(()); }
    publish(if new == 0 { 0 } else { base }, new);
    release_tail(base + new, cur - new);
    Ok(())
}

/// Return `[start, start+len)` to the page allocator one page at a time.
/// # C: O(len / page size)
fn release_tail(start: u64, len: u64) {
    let mut pa = start;
    while pa < start + len {
        // SAFETY: the range was removed from the page allocator by the boot
        // reservation and has been published as no longer part of the crash
        // region, so nothing holds a reference to it and no live page table
        // maps it.
        unsafe { pmm::setup::free_one_frame(pa) };
        pa += PAGE_SIZE;
    }
}
