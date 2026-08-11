const PAGE_BYTES: u64 = 4096;
const PTE_ADDRESS_MASK: u64 = 0x000f_ffff_ffff_f000;
const PTE_READ: u64 = 1 << 0;
const PTE_WRITE: u64 = 1 << 1;
const PTE_LARGE_PAGE: u64 = 1 << 7;

/// Hardware-format VT-d second-level page-table entry.
#[repr(transparent)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VtdPte(u64);
impl VtdPte {
    /// Construct a read/write non-leaf entry for a page-aligned child table. # C: O(1)
    pub const fn table(next_pa: u64) -> Option<Self> {
        if next_pa & (PAGE_BYTES - 1) != 0 || next_pa & !PTE_ADDRESS_MASK != 0 { return None; }
        Some(Self(PTE_READ | PTE_WRITE | next_pa))
    }
    /// Construct a read/write second-level DMA leaf at the requested size. # C: O(1)
    pub const fn leaf(pa: u64, large: bool) -> Option<Self> {
        if pa & (PAGE_BYTES - 1) != 0 || pa & !PTE_ADDRESS_MASK != 0 { return None; }
        Some(Self(PTE_READ | PTE_WRITE | if large { PTE_LARGE_PAGE } else { 0 } | pa))
    }
    /// Return the little-endian hardware word. # C: O(1)
    pub const fn word(self) -> u64 { self.0 }
    /// Return whether this entry allows DMA translation. # C: O(1)
    pub const fn present(self) -> bool { self.0 & (PTE_READ | PTE_WRITE) != 0 }
    /// Return whether this entry is a large-page leaf. # C: O(1)
    pub const fn large(self) -> bool { self.0 & PTE_LARGE_PAGE != 0 }
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn vtd_pte_preserves_second_level_permissions_and_leaf_shape() {
        let table = VtdPte::table(0x1234_5000).unwrap();
        let leaf = VtdPte::leaf(0x4567_8000, true).unwrap();
        assert_eq!(table.word(), 0x1234_5003);
        assert_eq!(leaf.word(), 0x4567_8083);
        assert!(table.present());
        assert!(leaf.large());
        assert!(VtdPte::leaf(0x4567_8001, false).is_none());
    }
}
