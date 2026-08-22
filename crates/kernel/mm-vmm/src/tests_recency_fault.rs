// File-fault recency wiring regression.

#![cfg(test)]

use alloc::sync::Arc;
use core::cell::Cell;
use std::thread_local;

use hal::{MmuOps, Pa, PageFlags, PageSize, UserVirtAddr, Va};

use crate::address_space::AddressSpace;
use crate::vma::{FaultAccess, FaultKind, FileBacking, FileBackingError,
    VmaBacking, VmaFlags, VmaProt};

const PAGE: u64 = 4096;
const VA: u64 = 0x40_0000;

thread_local! {
    static LEAF: Cell<Option<(u64, u64)>> = const { Cell::new(None) };
}

struct TestMmu;
impl MmuOps for TestMmu {
    unsafe fn map(_va: Va, pa: Pa, flags: PageFlags, _size: PageSize) -> Option<Pa> {
        LEAF.with(|leaf| leaf.replace(Some((pa.0, flags.bits()))).map(|old| Pa(old.0)))
    }
    unsafe fn unmap(_va: Va, _size: PageSize) { LEAF.with(|leaf| leaf.set(None)); }
    fn translate(_va: Va) -> Option<(Pa, PageFlags)> {
        LEAF.with(|leaf| leaf.get().map(|(pa, flags)| (Pa(pa), PageFlags::from_bits_truncate(flags))))
    }
    unsafe fn flush_va(_va: Va) {}
    fn flush_all_local() {}
    unsafe fn map_at(_root: u64, va: Va, pa: Pa, flags: PageFlags, size: PageSize) -> Option<Pa> {
        // SAFETY: the hosted model has one active leaf and forwards the same valid tuple.
        unsafe { Self::map(va, pa, flags, size) }
    }
    unsafe fn activate(_root_pa: u64) {}
}

struct ResidentFile { pa: u64, noreuse: bool }
impl FileBacking for ResidentFile {
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, FileBackingError> {
        Err(FileBackingError::Io)
    }
    fn size_hint(&self) -> u64 { PAGE }
    fn direct_frame(&self, _off: u64) -> Option<u64> { Some(self.pa) }
    fn noreuse(&self) -> bool { self.noreuse }
}

fn fault_references_resident_page(noreuse: bool) -> usize {
    LEAF.with(|leaf| leaf.set(None));
    let frame = aligned_frame();
    let backing: Arc<dyn FileBacking> = Arc::new(ResidentFile { pa: frame, noreuse });
    let mm = AddressSpace::new(0x1000).expect("address space");
    mm.mmap(Some(UserVirtAddr::new(VA).unwrap()), PAGE as usize,
        VmaProt::READ, VmaFlags::PRIVATE, VmaBacking::File { backing, off: 0 }, true)
        .expect("file mapping");
    let referenced = Cell::new(0usize);
    // SAFETY: TestMmu owns the hosted leaf; frame is a live aligned allocation;
    // the callbacks model refcounts without releasing the frame during this fault.
    unsafe {
        mm.handle_page_fault_cow_rmap::<TestMmu, _, _, _, _, _, _, _, _, _>(
            UserVirtAddr::new(VA).unwrap(),
            FaultKind::NotPresent { access: FaultAccess::Read }, 0, false,
            || None, |_| 1, |_| {}, |_, _, _| {}, |_| {}, |_| false,
            || Ok(()), || {}, |_| referenced.set(referenced.get() + 1),
        ).expect("resident file fault");
    }
    referenced.get()
}

fn aligned_frame() -> u64 {
    use std::alloc::{alloc_zeroed, Layout};
    let layout = Layout::from_size_align(PAGE as usize, PAGE as usize).unwrap();
    // SAFETY: non-zero page-sized layout; the allocation remains live for the test process.
    unsafe { alloc_zeroed(layout) as u64 }
}

#[test]
fn noreuse_file_fault_does_not_promote_the_resident_page() {
    assert_eq!(fault_references_resident_page(false), 1,
        "ordinary resident file fault marks the page referenced");
    assert_eq!(fault_references_resident_page(true), 0,
        "FMODE_NOREUSE suppresses the fault-path recency promotion");
}
