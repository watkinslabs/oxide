// The reserved crash-kernel region: the `crashkernel=` command line, the
// physical range it claims at boot, and the queries the file surfaces answer.
//
// Module manifest:
// - `parse`: ungated — the `crashkernel=` grammar and the placement rules.
// - this file: the one live reservation, published once at boot and read by
//   every later consumer (a crash load's destination bound, the size the
//   `/sys/kernel` attribute reports, and the shrink that attribute performs).
//
// ONE reservation, published once. A crash image's destinations are checked
// against this range and its control pages are drawn from inside it, so a
// second place recording "where the crash kernel lives" is a way for those two
// answers to disagree at the moment a machine is panicking.

pub mod parse;

use core::sync::atomic::{AtomicU64, Ordering};

use crate::validate::CrashRange;

/// Alignment every reserved crash region is placed and sized to.
///
/// Large because the region is handed to a whole second kernel, which will
/// map it with the biggest leaves it can; a region that is not aligned to a
/// hugepage forces that kernel to fragment its own direct map.
pub const CRASH_ALIGN: u64 = 16 * 1024 * 1024;

/// Granularity the reserved size may be shrunk to.
pub const CRASH_SHRINK_ALIGN: u64 = 1024 * 1024;

/// First byte of the reserved region; `0` when nothing is reserved.
static CRASH_BASE: AtomicU64 = AtomicU64::new(0);
/// Bytes reserved; `0` when nothing is reserved.
static CRASH_SIZE: AtomicU64 = AtomicU64::new(0);

/// Publish the region reserved at boot.
///
/// Called once, from the boot path, after the physical range has actually been
/// taken out of the page allocator. Publishing a range that was not reserved
/// would let a crash load stage an image on top of live kernel memory.
/// # C: O(1)
pub fn publish(base: u64, size: u64) {
    CRASH_BASE.store(base, Ordering::Release);
    CRASH_SIZE.store(size, Ordering::Release);
}

/// Bytes currently reserved for a crash kernel. Zero when none is.
/// # C: O(1)
pub fn crash_size() -> u64 { CRASH_SIZE.load(Ordering::Acquire) }

/// Base of the reserved region, or zero.
/// # C: O(1)
pub fn crash_base() -> u64 { CRASH_BASE.load(Ordering::Acquire) }

/// The reserved region as the inclusive range a crash load is bounded by, or
/// `None` when no region is reserved.
///
/// `None` is what makes every `KEXEC_ON_CRASH` load fail with EADDRNOTAVAIL on
/// a machine booted without `crashkernel=`: there is nowhere the image could
/// legally land, and the entry-point test refuses before anything is staged.
/// # C: O(1)
pub fn crash_range() -> Option<CrashRange> {
    let (base, size) = (crash_base(), crash_size());
    if size == 0 { return None; }
    Some(CrashRange { start: base, end: base + size - 1 })
}

/// Reset the published reservation. Test-only: the value is boot-once.
/// # C: O(1)
#[cfg(test)]
pub fn clear_for_tests() { publish(0, 0); }
