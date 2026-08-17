//! Zone identities. Index order is address order: a lower index names a
//! strictly lower physical address range, which is what makes the fallback
//! walk (high index down to low) also a "widest bound first" walk.

/// Number of zone slots the allocator carries.
pub const NR_ZONES: usize = 4;

/// One allocator zone. `Dma`/`Dma32` exist because some bus masters cannot
/// address all of RAM; `Normal` is everything the kernel can reach directly;
/// `Movable` holds only migratable pages so offlining and contiguity have
/// somewhere to work.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
#[repr(u8)]
pub enum ZoneType { Dma = 0, Dma32 = 1, Normal = 2, Movable = 3 }

impl ZoneType {
    /// Zone index, the position of this zone in address order. # C: O(1)
    pub const fn index(self) -> usize { self as usize }

    /// Zone whose index is `idx`, or `None` when out of range. # C: O(1)
    pub const fn from_index(idx: usize) -> Option<Self> {
        match idx {
            0 => Some(Self::Dma),
            1 => Some(Self::Dma32),
            2 => Some(Self::Normal),
            3 => Some(Self::Movable),
            _ => None,
        }
    }

    /// Name as reported to userspace by the per-zone statistics files. # C: O(1)
    pub const fn name(self) -> &'static str {
        match self { Self::Dma => "DMA", Self::Dma32 => "DMA32", Self::Normal => "Normal", Self::Movable => "Movable" }
    }

    /// Every zone in address order. # C: O(1)
    pub const fn all() -> [Self; NR_ZONES] { [Self::Dma, Self::Dma32, Self::Normal, Self::Movable] }
}
