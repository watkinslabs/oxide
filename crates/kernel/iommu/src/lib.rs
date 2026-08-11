#![no_std]
extern crate alloc;
mod amd_vi;
pub use amd_vi::{AmdViRegisters, AmdViState, AmdViUnit, COMMAND_BUFFER, COMMAND_HEAD, COMMAND_TAIL,
    CONTROL, CONTROL_COMMAND_ENABLE, CONTROL_IOMMU_ENABLE, DEVICE_TABLE, EVENT_LOG};
use alloc::vec::Vec;
use pci::{Bdf, IovaRange, IovaSpace};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Mapping { pub iova: IovaRange, pub pa: u64 }

pub struct Domain { requester: Bdf, space: IovaSpace, maps: Vec<Mapping> }
impl Domain {
    /// Create one requester-bound DMA domain. # C: O(1)
    pub fn new(requester: Bdf, start: u64, len: u64) -> Option<Self> {
        Some(Self { requester, space: IovaSpace::new(start, len)?, maps: Vec::new() })
    }
    /// Requester this domain alone may attach. # C: O(1)
    pub const fn requester(&self) -> Bdf { self.requester }
    /// Reserve mapping state before backend PTE programming. # C: O(N)
    pub fn reserve(&mut self, pa: u64, len: u64, align: u64) -> Option<Mapping> {
        if pa & (pci::IOVA_PAGE_SIZE - 1) != 0 { return None; }
        let map = Mapping { iova: self.space.alloc(len, align)?, pa };
        self.maps.push(map);
        Some(map)
    }
    /// Retire a mapping only after hardware invalidation completed. # C: O(N)
    pub fn release_after_invalidate(&mut self, map: Mapping) -> bool {
        let Some(i) = self.maps.iter().position(|m| *m == map) else { return false; };
        if !self.space.free(map.iova) { return false; }
        self.maps.swap_remove(i); true
    }
    /// Return installed mapping state for a backend PTE walk. # C: O(N)
    pub fn mapping(&self, iova: u64) -> Option<Mapping> { self.maps.iter().copied().find(|m| m.iova.start == iova) }
}

#[cfg(test)] extern crate std;
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn mapping_lifecycle_waits_for_invalidation() {
        let b = Bdf { segment: 2, bus: 3, device: 4, function: 0 };
        let mut d = Domain::new(b, 0x1000, 0x4000).unwrap();
        let m = d.reserve(0x2000, 0x1000, 0x1000).unwrap();
        assert_eq!(d.requester(), b); assert_eq!(d.mapping(m.iova.start), Some(m));
        assert!(d.release_after_invalidate(m)); assert!(!d.release_after_invalidate(m));
    }
}
