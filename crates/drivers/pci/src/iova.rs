use alloc::vec::Vec;

/// IOMMU page-table granule used by the initial x86 DMA-domain profile.
pub const IOVA_PAGE_SIZE: u64 = 4096;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct IovaRange { pub start: u64, pub len: u64 }

impl IovaRange {
    /// Exclusive end of this owned IOVA interval. # C: O(1)
    pub const fn end(self) -> u64 { self.start + self.len }
}

/// Per-domain IOVA allocator. Ranges are page aligned and unavailable until
/// their hardware invalidation has completed and the caller returns them.
pub struct IovaSpace { free: Vec<IovaRange> }

impl IovaSpace {
    /// Make an empty page-granular IOVA domain over one inclusive-safe range. # C: O(1)
    pub fn new(start: u64, len: u64) -> Option<Self> {
        if start & (IOVA_PAGE_SIZE - 1) != 0 || len == 0 || len & (IOVA_PAGE_SIZE - 1) != 0 { return None; }
        start.checked_add(len)?;
        Some(Self { free: alloc::vec![IovaRange { start, len }] })
    }

    /// Reserve a page-aligned IOVA interval. # C: O(number of free ranges)
    pub fn alloc(&mut self, len: u64, align: u64) -> Option<IovaRange> {
        self.alloc_below(len, align, u64::MAX)
    }

    /// Reserve a page-aligned interval whose inclusive final byte fits `mask`.
    /// # C: O(number of free ranges)
    pub fn alloc_below(&mut self, len: u64, align: u64, mask: u64) -> Option<IovaRange> {
        if len == 0 || len & (IOVA_PAGE_SIZE - 1) != 0 || align == 0
            || align & (IOVA_PAGE_SIZE - 1) != 0 || !align.is_power_of_two() { return None; }
        for i in 0..self.free.len() {
            let r = self.free[i];
            let start = r.start.checked_add(align - 1)? & !(align - 1);
            let end = start.checked_add(len)?;
            if start < r.start || end > r.end() || end.checked_sub(1)? > mask { continue; }
            let before = start - r.start;
            let after = r.end() - end;
            if before != 0 && after != 0 {
                self.free[i] = IovaRange { start: r.start, len: before };
                self.free.insert(i + 1, IovaRange { start: end, len: after });
            } else if before != 0 {
                self.free[i].len = before;
            } else if after != 0 {
                self.free[i] = IovaRange { start: end, len: after };
            } else {
                self.free.remove(i);
            }
            return Some(IovaRange { start, len });
        }
        None
    }

    /// Reserve one caller-selected page-aligned IOVA interval. # C: O(number of free ranges)
    pub fn reserve_at(&mut self, start: u64, len: u64) -> Option<IovaRange> {
        if start & (IOVA_PAGE_SIZE - 1) != 0 || len == 0 || len & (IOVA_PAGE_SIZE - 1) != 0 { return None; }
        let end = start.checked_add(len)?;
        for i in 0..self.free.len() {
            let r = self.free[i];
            if start < r.start || end > r.end() { continue; }
            let before = start - r.start;
            let after = r.end() - end;
            if before != 0 && after != 0 {
                self.free[i] = IovaRange { start: r.start, len: before };
                self.free.insert(i + 1, IovaRange { start: end, len: after });
            } else if before != 0 { self.free[i].len = before; }
            else if after != 0 { self.free[i] = IovaRange { start: end, len: after }; }
            else { self.free.remove(i); }
            return Some(IovaRange { start, len });
        }
        None
    }

    /// Return an invalidated IOVA range and merge adjacent free intervals. # C: O(number of free ranges)
    pub fn free(&mut self, range: IovaRange) -> bool {
        if range.len == 0 || range.start & (IOVA_PAGE_SIZE - 1) != 0
            || range.len & (IOVA_PAGE_SIZE - 1) != 0 || range.start.checked_add(range.len).is_none() { return false; }
        let pos = self.free.iter().position(|r| r.start > range.start).unwrap_or(self.free.len());
        if pos > 0 && self.free[pos - 1].end() > range.start { return false; }
        if pos < self.free.len() && range.end() > self.free[pos].start { return false; }
        self.free.insert(pos, range);
        if pos > 0 && self.free[pos - 1].end() == self.free[pos].start {
            let len = self.free[pos].len;
            self.free[pos - 1].len += len;
            self.free.remove(pos);
        }
        let pos = self.free.iter().position(|r| r.start == range.start).unwrap_or(pos.saturating_sub(1));
        if pos + 1 < self.free.len() && self.free[pos].end() == self.free[pos + 1].start {
            let len = self.free[pos + 1].len;
            self.free[pos].len += len;
            self.free.remove(pos + 1);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn allocation_alignment_and_invalidation_return_contract() {
        let mut s = IovaSpace::new(0x1000, 0x8000).unwrap();
        let a = s.alloc(0x2000, 0x4000).unwrap();
        assert_eq!(a.start, 0x4000);
        assert!(s.free(a));
        assert!(!s.free(a));
        assert_eq!(s.alloc(0x8000, IOVA_PAGE_SIZE), Some(IovaRange { start: 0x1000, len: 0x8000 }));
    }

    #[test]
    fn explicit_reservation_preserves_the_requested_iova() {
        let mut s = IovaSpace::new(0, 0x10_000).unwrap();
        assert_eq!(s.reserve_at(0x4000, 0x2000), Some(IovaRange { start: 0x4000, len: 0x2000 }));
        assert_eq!(s.reserve_at(0x4000, 0x1000), None);
    }

    #[test]
    fn masked_allocation_uses_the_lowest_device_addressable_interval() {
        let mut s = IovaSpace::new(0, 0x20_000).unwrap();
        assert_eq!(s.alloc_below(0x1000, IOVA_PAGE_SIZE, 0x0fff), Some(IovaRange { start: 0, len: 0x1000 }));
        assert_eq!(s.alloc_below(0x1000, IOVA_PAGE_SIZE, 0x0fff), None);
    }
}
