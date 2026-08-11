const PAGE_BYTES: u64 = 4096;
const PTE_PRESENT: u64 = 1 << 0;
const PTE_NEXT_LEVEL_SHIFT: u64 = 9;
const PTE_NEXT_LEVEL_MASK: u64 = 0x7 << PTE_NEXT_LEVEL_SHIFT;
const PTE_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const PTE_FORCE_COHERENCE: u64 = 1 << 60;
const PTE_READ: u64 = 1 << 61;
const PTE_WRITE: u64 = 1 << 62;
const IOVA_INDEX_MASK: u64 = 0x1ff;
const LEVEL_SHIFTS: [u8; 4] = [39, 30, 21, 12];

/// Hardware-format AMD-Vi v1 page-table entry.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AmdViPte(u64);
impl AmdViPte {
    /// Construct a non-leaf entry pointing to the next IOVA page-table level. # C: O(1)
    pub const fn table(next_pa: u64, next_level: u8) -> Option<Self> {
        if next_pa & (PAGE_BYTES - 1) != 0 || next_pa & !PTE_ADDRESS_MASK != 0 || next_level == 0 || next_level > 7 { return None; }
        Some(Self(PTE_PRESENT | ((next_level as u64) << PTE_NEXT_LEVEL_SHIFT & PTE_NEXT_LEVEL_MASK)
            | (next_pa & PTE_ADDRESS_MASK) | PTE_READ | PTE_WRITE))
    }
    /// Construct a coherent 4K leaf entry with read/write DMA permission. # C: O(1)
    pub const fn leaf(pa: u64) -> Option<Self> {
        if pa & (PAGE_BYTES - 1) != 0 || pa & !PTE_ADDRESS_MASK != 0 { return None; }
        Some(Self(PTE_PRESENT | (pa & PTE_ADDRESS_MASK) | PTE_FORCE_COHERENCE | PTE_READ | PTE_WRITE))
    }
    /// Return the hardware entry word. # C: O(1)
    pub const fn word(self) -> u64 { self.0 }
}

/// Return four 9-bit indices for a 48-bit IOVA walk. # C: O(1)
pub const fn iova_indices(iova: u64) -> [usize; 4] {
    [((iova >> LEVEL_SHIFTS[0]) & IOVA_INDEX_MASK) as usize,
        ((iova >> LEVEL_SHIFTS[1]) & IOVA_INDEX_MASK) as usize,
        ((iova >> LEVEL_SHIFTS[2]) & IOVA_INDEX_MASK) as usize,
        ((iova >> LEVEL_SHIFTS[3]) & IOVA_INDEX_MASK) as usize]
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn pte_layout_matches_a_four_level_iova_walk() {
        assert_eq!(iova_indices(0x1234_5678_9000), [36, 209, 179, 393]);
        assert_eq!(AmdViPte::leaf(0x1234_5000).unwrap().word() & PTE_ADDRESS_MASK, 0x1234_5000);
        assert_eq!((AmdViPte::table(0x4567_8000, 3).unwrap().word() & PTE_NEXT_LEVEL_MASK) >> PTE_NEXT_LEVEL_SHIFT, 3);
        assert!(AmdViPte::leaf(0x1234_5001).is_none());
    }
}
