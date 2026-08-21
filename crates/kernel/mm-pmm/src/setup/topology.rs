//! Canonical retained, page-normalized boot memory topology.

use super::*;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering};

/// Maximum normalized boot topology entries retained for the machine.
pub const MAX_MEMORY_REGIONS: usize = 256;

/// One non-empty page-aligned physical range from the boot topology.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MemoryRegion {
    /// First PFN in the range.
    pub start: Pfn,
    /// Exclusive ending PFN.
    pub end: Pfn,
    /// Firmware classification retained without reinterpretation.
    pub kind: BootMemKind,
}

const EMPTY: MemoryRegion = MemoryRegion {
    start: Pfn(0), end: Pfn(0), kind: BootMemKind::Reserved,
};

struct Topology(UnsafeCell<[MemoryRegion; MAX_MEMORY_REGIONS]>);
// SAFETY: one early-boot writer publishes the immutable slice with Release.
unsafe impl Sync for Topology {}
static TOPOLOGY: Topology = Topology(UnsafeCell::new([EMPTY; MAX_MEMORY_REGIONS]));
static COUNT: AtomicUsize = AtomicUsize::new(0);

/// Retained normalized memory topology. Empty before PMM setup.
/// # C: O(1)
pub fn memory_topology() -> &'static [MemoryRegion] {
    let count = COUNT.load(Ordering::Acquire);
    // SAFETY: entries precede the release publication and are never changed.
    unsafe { core::slice::from_raw_parts(TOPOLOGY.0.get().cast::<MemoryRegion>(), count) }
}

/// Normalize and retain the boot topology once.
/// # C: O(map.len * MAX_MEMORY_REGIONS)
/// # Ctx: single-CPU, pre-PMM initialization
pub(super) fn publish(map: &[BootMemRegion]) -> Result<(), SetupError> {
    // SAFETY: setup is single-shot and no reader exists until COUNT publishes
    // the completed normalized prefix. Failed normalization leaves COUNT zero.
    let out = unsafe { &mut *TOPOLOGY.0.get() };
    out.fill(EMPTY);
    let count = normalize(map, out)?;
    COUNT.store(count, Ordering::Release);
    Ok(())
}

fn normalize(map: &[BootMemRegion], out: &mut [MemoryRegion]) -> Result<usize, SetupError> {
    let mut count = 0usize;
    for raw in map {
        if raw.len == 0 { continue; }
        let byte_end = raw.base_pa.checked_add(raw.len).ok_or(SetupError::OverlappingTopology)?;
        let (start, end) = if raw.kind == BootMemKind::Usable {
            (raw.base_pa.saturating_add(PAGE_SIZE_BYTES - 1) >> PAGE_SHIFT,
             byte_end >> PAGE_SHIFT)
        } else {
            (raw.base_pa >> PAGE_SHIFT,
             byte_end.saturating_add(PAGE_SIZE_BYTES - 1) >> PAGE_SHIFT)
        };
        if end <= start { continue; }
        if count == out.len() { return Err(SetupError::TooManyTopologyRegions); }
        let mut at = count;
        while at > 0 && out[at - 1].start.0 > start {
            out[at] = out[at - 1];
            at -= 1;
        }
        out[at] = MemoryRegion { start: Pfn(start), end: Pfn(end), kind: raw.kind };
        count += 1;
    }
    let mut write = 0usize;
    for read in 0..count {
        let region = out[read];
        if write > 0 {
            let prev = &mut out[write - 1];
            if region.start.0 < prev.end.0 { return Err(SetupError::OverlappingTopology); }
            if region.start == prev.end && region.kind == prev.kind {
                prev.end = region.end;
                continue;
            }
        }
        out[write] = region;
        write += 1;
    }
    Ok(write)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_sorts_aligns_and_coalesces_one_truth() {
        let map = [
            BootMemRegion { base_pa: 0x4000, len: 0x2000, kind: BootMemKind::Usable },
            BootMemRegion { base_pa: 0x1001, len: 0x1fff, kind: BootMemKind::Reserved },
            BootMemRegion { base_pa: 0x3000, len: 0x1000, kind: BootMemKind::Usable },
        ];
        let mut out = [EMPTY; 8];
        let count = normalize(&map, &mut out).unwrap();
        assert_eq!(count, 2);
        assert_eq!(out[0], MemoryRegion { start: Pfn(1), end: Pfn(3), kind: BootMemKind::Reserved });
        assert_eq!(out[1], MemoryRegion { start: Pfn(3), end: Pfn(6), kind: BootMemKind::Usable });
    }

    #[test]
    fn overlap_is_rejected_instead_of_creating_split_truth() {
        let map = [
            BootMemRegion { base_pa: 0x1000, len: 0x3000, kind: BootMemKind::Usable },
            BootMemRegion { base_pa: 0x2000, len: 0x1000, kind: BootMemKind::Reserved },
        ];
        assert_eq!(normalize(&map, &mut [EMPTY; 4]), Err(SetupError::OverlappingTopology));
    }
}
