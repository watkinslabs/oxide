use core::cell::Cell;

use hal::{MmuOps, Pa, PageFlags, PageSize, UserVirtAddr, Va};

use crate::{AddressSpace, FaultAccess, FaultKind, PhysCacheMode, VmaBacking, VmaFlags, VmaProt};

const VA: u64 = 0x4400_0000;
const PA: u64 = 0xfd00_0000;

std::thread_local! {
    static LAST: Cell<Option<(u64, u64, PageFlags)>> = const { Cell::new(None) };
}

struct CaptureMmu;

impl MmuOps for CaptureMmu {
    unsafe fn map(va: Va, pa: Pa, flags: PageFlags, _size: PageSize) -> Option<Pa> {
        LAST.with(|last| last.set(Some((va.0, pa.0, flags))));
        None
    }

    unsafe fn unmap(_va: Va, _size: PageSize) {}

    fn translate(_va: Va) -> Option<(Pa, PageFlags)> {
        None
    }

    unsafe fn flush_va(_va: Va) {}

    fn flush_all_local() {}

    unsafe fn map_at(
        _root_pa: u64,
        _va: Va,
        _pa: Pa,
        _flags: PageFlags,
        _size: PageSize,
    ) -> Option<Pa> {
        None
    }

    unsafe fn activate(_root_pa: u64) {}
}

fn fault_flags(cache: PhysCacheMode) -> PageFlags {
    LAST.with(|last| last.set(None));
    let mm = AddressSpace::new(0).unwrap();
    mm.mmap(
        Some(UserVirtAddr::new(VA).unwrap()),
        hal::PAGE_SIZE_BYTES as usize,
        VmaProt::READ | VmaProt::WRITE,
        VmaFlags::SHARED,
        VmaBacking::PhysRange { base_pa: PA, cache },
        true,
    ).unwrap();
    // SAFETY: CaptureMmu records rather than touching page tables; PhysRange
    // needs no allocator or HHDM access.
    unsafe {
        mm.handle_page_fault::<CaptureMmu, _>(
            UserVirtAddr::new(VA).unwrap(),
            FaultKind::NotPresent { access: FaultAccess::Write },
            0,
            || None,
        ).unwrap();
    }
    let (va, pa, flags) = LAST.with(Cell::get).expect("fault installed a leaf");
    assert_eq!(va, VA);
    assert_eq!(pa, PA);
    flags
}

#[test]
fn framebuffer_phys_range_reaches_the_leaf_as_write_combining() {
    let flags = fault_flags(PhysCacheMode::WriteCombine);
    assert!(flags.contains(PageFlags::WRITE_COMBINE));
    assert!(!flags.contains(PageFlags::NO_CACHE));
}

#[test]
fn ordinary_ram_phys_range_stays_write_back() {
    let flags = fault_flags(PhysCacheMode::WriteBack);
    assert!(!flags.intersects(
        PageFlags::NO_CACHE | PageFlags::WRITE_THROUGH | PageFlags::WRITE_COMBINE,
    ));
}

#[test]
fn ordinary_device_phys_range_stays_strongly_uncached() {
    let flags = fault_flags(PhysCacheMode::Device);
    assert!(flags.contains(PageFlags::NO_CACHE));
    assert!(flags.contains(PageFlags::WRITE_THROUGH));
    assert!(!flags.contains(PageFlags::WRITE_COMBINE));
}
