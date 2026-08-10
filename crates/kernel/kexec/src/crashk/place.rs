// Where the reserved region physically lands.
//
// Ungated and global-free: the search is handed the memory ranges and the
// bounds, so every rule below — the alignment, the two search orders, the
// fixed-base exactness, and the all-or-nothing low companion — is decided in a
// hosted test rather than inferred from a machine that did or did not panic
// correctly six months later.

use crate::crashk::parse::{CrashKernelSpec, Pref};
use crate::crashk::CRASH_ALIGN;

/// Ceiling for a region that must be addressable by a 32-bit device.
pub const CRASH_ADDR_LOW_MAX: u64 = 4 * 1024 * 1024 * 1024;

/// Ceiling for the search as a whole. The identity tables the relocation runs
/// under are built to cover the addresses the image actually uses, and a
/// reservation beyond this is outside the range those tables are sized for.
pub const CRASH_ADDR_HIGH_MAX: u64 = 64 * 1024 * 1024 * 1024 * 1024;

/// A half-open range of usable physical memory, `[start, end)`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct RamRange {
    pub start: u64,
    pub end: u64,
}

/// The regions a spec resolves to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Placement {
    /// Base of the region a crash image lands in.
    pub base: u64,
    /// Its length.
    pub size: u64,
    /// Base of the companion region below the 32-bit boundary; zero when none
    /// was asked for or none was needed.
    pub low_base: u64,
    /// Its length; zero when there is none.
    pub low_size: u64,
}

/// Why no region could be placed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PlaceError {
    /// The command line asked for nothing.
    NotRequested,
    /// No window of usable memory could hold the main region.
    NoSpace,
    /// The main region landed high and the companion below the 32-bit
    /// boundary would not fit. Nothing is reserved: a high-only reservation
    /// would leave a device that cannot address above the boundary with
    /// nowhere to put its buffers in the kernel that has to read the dump.
    NoLowSpace,
}

/// Highest `CRASH_ALIGN`-aligned base in `[min, max)` at which `size` bytes
/// fit inside one usable range.
///
/// Top-down because the bottom of usable memory is where the running kernel,
/// its early bookkeeping and the firmware tables already sit; a bottom-up
/// search finds a window whose pages are already spoken for and the
/// reservation then silently covers something else's memory.
/// # C: O(N_ranges)
pub fn search(ram: &[RamRange], size: u64, min: u64, max: u64) -> Option<u64> {
    if size == 0 { return None; }
    let mut best: Option<u64> = None;
    for r in ram {
        let lo = r.start.max(min);
        let hi = r.end.min(max);
        if hi < lo || hi - lo < size { continue; }
        let base = (hi - size) & !(CRASH_ALIGN - 1);
        if base < lo { continue; }
        if best.is_none_or(|b| base > b) { best = Some(base); }
    }
    best
}

/// Is `size` bytes at exactly `base` inside one usable range?
/// # C: O(N_ranges)
fn fits_exactly(ram: &[RamRange], base: u64, size: u64) -> bool {
    let Some(end) = base.checked_add(size) else { return false };
    ram.iter().any(|r| base >= r.start && end <= r.end)
}

/// Resolve a parsed command line into physical regions.
/// # C: O(N_ranges)
pub fn place(spec: &CrashKernelSpec, ram: &[RamRange]) -> Result<Placement, PlaceError> {
    let req = spec.main.ok_or(PlaceError::NotRequested)?;
    let size = (req.size + CRASH_ALIGN - 1) & !(CRASH_ALIGN - 1);
    let base = match req.base {
        // A fixed base is a statement about the machine, not a hint: the
        // operator picked an address that firmware and devices leave alone.
        // Searching elsewhere when it does not fit would reserve memory the
        // operator has reason to believe is unusable.
        Some(b) => {
            if b % CRASH_ALIGN != 0 || !fits_exactly(ram, b, size) { return Err(PlaceError::NoSpace); }
            b
        }
        None => {
            let (first, second) = match req.pref {
                Pref::High => ((CRASH_ADDR_LOW_MAX, CRASH_ADDR_HIGH_MAX), (0, CRASH_ADDR_LOW_MAX)),
                Pref::Auto => ((0, CRASH_ADDR_LOW_MAX), (CRASH_ADDR_LOW_MAX, CRASH_ADDR_HIGH_MAX)),
            };
            match search(ram, size, first.0, first.1).or_else(|| search(ram, size, second.0, second.1)) {
                Some(b) => b,
                None => return Err(PlaceError::NoSpace),
            }
        }
    };
    let mut out = Placement { base, size, low_base: 0, low_size: 0 };
    // The companion is only meaningful when the main region is out of a
    // 32-bit device's reach; asked for while the main region is already low,
    // it would reserve a second region for a problem that does not exist.
    if let Some(low) = spec.low {
        if base >= CRASH_ADDR_LOW_MAX {
            let low_size = (low + CRASH_ALIGN - 1) & !(CRASH_ALIGN - 1);
            // No overlap check is needed and none is written: the companion is
            // only sought when the main region sits at or above the boundary,
            // and the search for it stops below the boundary. The two windows
            // are disjoint by construction, and a redundant check here would
            // be a second place that could disagree about which is which.
            let lb = search(ram, low_size, 0, CRASH_ADDR_LOW_MAX)
                .ok_or(PlaceError::NoLowSpace)?;
            out.low_base = lb;
            out.low_size = low_size;
        }
    }
    Ok(out)
}

