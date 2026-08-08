// A mapping whose backing is made of huge pages must be PLACED on a huge
// boundary: a block leaf only exists on its own boundary, so an address off it
// is not a worse placement but an unusable one.

use alloc::sync::Arc;

use hal::UserVirtAddr;

use crate::address_space::AddressSpace;
use crate::vma::{FileBacking, FileBackingError, VmaBacking, VmaFlags, VmaProt};

const M2: u64 = 2 * 1024 * 1024;

struct HugeBacking { huge: u64 }
impl FileBacking for HugeBacking {
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, FileBackingError> { Ok(0) }
    fn size_hint(&self) -> u64 { u64::MAX }
    fn huge_page_size(&self) -> u64 { self.huge }
}

fn huge_backing(huge: u64) -> VmaBacking {
    VmaBacking::File { backing: Arc::new(HugeBacking { huge }) as Arc<dyn FileBacking>, off: 0 }
}

fn base_backing() -> VmaBacking {
    VmaBacking::File { backing: Arc::new(HugeBacking { huge: 0 }) as Arc<dyn FileBacking>, off: 0 }
}

fn rw() -> VmaProt { VmaProt::READ | VmaProt::WRITE }

#[test]
fn a_huge_backed_mapping_is_placed_on_a_huge_boundary() {
    let as_ = AddressSpace::new(0).unwrap();
    for i in 0..8 {
        // Skew the arena by an odd number of base pages first, so an
        // unconstrained search would land off the huge boundary rather than on
        // it by accident.
        as_.mmap(None, (4096 * (2 * i + 1)) as usize, rw(), VmaFlags::PRIVATE,
                 base_backing(), false).expect("skew mapping");
        let at = as_.mmap(None, M2 as usize, rw(), VmaFlags::SHARED, huge_backing(M2), false)
            .expect("huge mapping must be placeable");
        assert_eq!(at.as_u64() % M2, 0, "placed at {:#x}", at.as_u64());
    }
}

#[test]
fn a_base_page_mapping_keeps_its_unconstrained_placement() {
    let as_ = AddressSpace::new(0).unwrap();
    let at = as_.mmap(None, 4096, rw(), VmaFlags::SHARED, base_backing(), false).expect("mmap");
    assert_eq!(at.as_u64() % hal::PAGE_SIZE_BYTES, 0);
}

#[test]
fn a_fixed_huge_mapping_at_a_misaligned_address_is_refused() {
    let as_ = AddressSpace::new(0).unwrap();
    let bad = UserVirtAddr::new(0x4000_0000 + 4096).unwrap();
    assert!(as_.mmap(Some(bad), M2 as usize, rw(), VmaFlags::SHARED, huge_backing(M2), true).is_err());
}

#[test]
fn a_fixed_huge_mapping_at_an_aligned_address_is_accepted() {
    let as_ = AddressSpace::new(0).unwrap();
    let good = UserVirtAddr::new(0x4000_0000).unwrap();
    let at = as_.mmap(Some(good), M2 as usize, rw(), VmaFlags::SHARED, huge_backing(M2), true)
        .expect("aligned fixed huge mapping");
    assert_eq!(at, good);
}

#[test]
fn a_misaligned_hint_does_not_place_a_huge_mapping_off_boundary() {
    let as_ = AddressSpace::new(0).unwrap();
    as_.mmap(None, 4096, rw(), VmaFlags::PRIVATE, base_backing(), false).expect("skew");
    let hint = UserVirtAddr::new(0x4000_0000 + 4096).unwrap();
    let at = as_.mmap(Some(hint), M2 as usize, rw(), VmaFlags::SHARED, huge_backing(M2), false)
        .expect("advisory placement falls back to the search");
    assert_eq!(at.as_u64() % M2, 0);
    assert_ne!(at, hint);
}

#[test]
fn a_gigantic_mapping_is_placed_on_a_gigantic_boundary() {
    const G1: u64 = 1024 * 1024 * 1024;
    let as_ = AddressSpace::new(0).unwrap();
    let at = as_.mmap(None, G1 as usize, rw(), VmaFlags::SHARED, huge_backing(G1), false)
        .expect("gigantic mapping must be placeable");
    assert_eq!(at.as_u64() % G1, 0, "placed at {:#x}", at.as_u64());
}
