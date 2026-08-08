use alloc::vec::Vec;

// A PRIVATE mapping of a huge-page file must not let its writes reach the file.
//
// These drive the real fault arms through a recording MMU, so a change that
// re-shares a private page — the exact defect this closes — turns them red.

use core::cell::RefCell;

use hal::{MmuOps, Pa, PageFlags, PageSize, UserVirtAddr, Va};

use crate::vma::{FileBacking, FileBackingError, SharedFrame};
use crate::{AddressSpace, FaultAccess, FaultKind, VmaBacking, VmaFlags, VmaProt};

const M2: u64 = 2 * 1024 * 1024;
const VA: u64 = 0x4000_0000;
const FILE_PA: u64 = 0x2000_0000;
const COW_PA: u64 = 0x6000_0000;

std::thread_local! {
    static MAPS: RefCell<Vec<(u64, u64, PageFlags, PageSize)>> = const { RefCell::new(Vec::new()) };
    static PRESENT: RefCell<Option<(u64, PageFlags)>> = const { RefCell::new(None) };
}

struct RecMmu;
impl MmuOps for RecMmu {
    unsafe fn map(va: Va, pa: Pa, flags: PageFlags, size: PageSize) -> Option<Pa> {
        MAPS.with(|m| m.borrow_mut().push((va.0, pa.0, flags, size)));
        let old = PRESENT.with(|p| p.borrow().map(|(pa, _)| pa));
        PRESENT.with(|p| *p.borrow_mut() = Some((pa.0, flags)));
        match old { Some(o) if o != pa.0 => Some(Pa(o)), _ => None }
    }
    unsafe fn unmap(_va: Va, _size: PageSize) {}
    fn translate(_va: Va) -> Option<(Pa, PageFlags)> {
        PRESENT.with(|p| p.borrow().map(|(pa, f)| (Pa(pa), f)))
    }
    unsafe fn flush_va(_va: Va) {}
    fn flush_all_local() {}
    unsafe fn map_at(_r: u64, _va: Va, _pa: Pa, _f: PageFlags, _s: PageSize) -> Option<Pa> { None }
    unsafe fn activate(_root_pa: u64) {}
}

/// Records which frame source each fault asked for, and every page handed back.
struct HugeFile {
    asked: RefCell<Vec<&'static str>>,
    put:   RefCell<Vec<u64>>,
}
// SAFETY: every test drives one instance from one thread; the interior
// mutability only records call order and is never shared across threads.
unsafe impl Sync for HugeFile {}
unsafe impl Send for HugeFile {}

impl FileBacking for HugeFile {
    fn read_at(&self, _o: u64, _d: &mut [u8]) -> Result<usize, FileBackingError> { Ok(0) }
    fn size_hint(&self) -> u64 { u64::MAX }
    fn huge_page_size(&self) -> u64 { M2 }
    fn shared_frame(&self, _o: u64) -> Result<Option<SharedFrame>, FileBackingError> {
        self.asked.borrow_mut().push("shared");
        Ok(Some(SharedFrame { pa: FILE_PA, map_ref_held: false }))
    }
    fn huge_cow_frame(&self, _o: u64) -> Result<Option<SharedFrame>, FileBackingError> {
        self.asked.borrow_mut().push("cow");
        Ok(Some(SharedFrame { pa: COW_PA, map_ref_held: true }))
    }
    fn huge_put_frame(&self, pa: u64) { self.put.borrow_mut().push(pa); }
}

fn setup(flags: VmaFlags) -> (alloc::sync::Arc<AddressSpace>, alloc::sync::Arc<HugeFile>) {
    MAPS.with(|m| m.borrow_mut().clear());
    PRESENT.with(|p| *p.borrow_mut() = None);
    let f = alloc::sync::Arc::new(HugeFile {
        asked: RefCell::new(Vec::new()), put: RefCell::new(Vec::new()) });
    let mm = AddressSpace::new(0).unwrap();
    mm.mmap(
        Some(UserVirtAddr::new(VA).unwrap()), M2 as usize,
        VmaProt::READ | VmaProt::WRITE, flags,
        VmaBacking::File { backing: f.clone() as alloc::sync::Arc<dyn FileBacking>, off: 0 },
        true,
    ).unwrap();
    (mm, f)
}

fn fault(mm: &AddressSpace, kind: FaultKind) -> Result<(), crate::Error> {
    // SAFETY: RecMmu records rather than touching page tables, and the frames
    // are synthetic addresses no allocator owns.
    unsafe {
        mm.handle_page_fault_cow::<RecMmu, _, _, _>(
            UserVirtAddr::new(VA + 4096).unwrap(), kind, 0,
            || None, |_| 2, |_| {},
        )
    }
}

fn last_map() -> (u64, u64, PageFlags, PageSize) { MAPS.with(|m| *m.borrow().last().unwrap()) }

#[test]
fn a_private_read_maps_the_files_page_without_the_write_bit() {
    let (mm, f) = setup(VmaFlags::PRIVATE);
    fault(&mm, FaultKind::NotPresent { access: FaultAccess::Read }).unwrap();
    let (va, pa, flags, size) = last_map();
    assert_eq!(f.asked.borrow().as_slice(), &["shared"]);
    assert_eq!((va, pa, size), (VA, FILE_PA, PageSize::P2M));
    assert!(!flags.contains(PageFlags::WRITE),
            "a writable private mapping must still fault on its first write");
}

#[test]
fn a_private_write_maps_a_copy_and_never_the_files_page() {
    let (mm, f) = setup(VmaFlags::PRIVATE);
    fault(&mm, FaultKind::NotPresent { access: FaultAccess::Write }).unwrap();
    let (va, pa, flags, size) = last_map();
    assert_eq!(f.asked.borrow().as_slice(), &["cow"]);
    assert_eq!((va, pa, size), (VA, COW_PA, PageSize::P2M));
    assert!(flags.contains(PageFlags::WRITE));
}

#[test]
fn a_private_write_after_a_read_copies_and_hands_the_files_page_back() {
    let (mm, f) = setup(VmaFlags::PRIVATE);
    fault(&mm, FaultKind::NotPresent { access: FaultAccess::Read }).unwrap();
    assert_eq!(last_map().1, FILE_PA);
    fault(&mm, FaultKind::Protection { access: FaultAccess::Write }).unwrap();
    let (_, pa, flags, size) = last_map();
    assert_eq!(pa, COW_PA, "the write must land on the copy");
    assert_eq!(size, PageSize::P2M);
    assert!(flags.contains(PageFlags::WRITE));
    assert_eq!(f.asked.borrow().as_slice(), &["shared", "cow"]);
    assert_eq!(f.put.borrow().as_slice(), &[FILE_PA],
               "the displaced file page's reference must go back to the backing");
}

#[test]
fn a_shared_mapping_writes_through_to_the_files_own_page() {
    let (mm, f) = setup(VmaFlags::SHARED);
    fault(&mm, FaultKind::NotPresent { access: FaultAccess::Write }).unwrap();
    let (va, pa, flags, size) = last_map();
    assert_eq!(f.asked.borrow().as_slice(), &["shared"]);
    assert_eq!((va, pa, size), (VA, FILE_PA, PageSize::P2M));
    assert!(flags.contains(PageFlags::WRITE));
    assert!(f.put.borrow().is_empty(), "nothing is displaced");
}

#[test]
fn a_shared_write_protection_fault_reinstalls_the_same_page_at_the_same_granule() {
    let (mm, f) = setup(VmaFlags::SHARED);
    fault(&mm, FaultKind::NotPresent { access: FaultAccess::Read }).unwrap();
    fault(&mm, FaultKind::Protection { access: FaultAccess::Write }).unwrap();
    let (_, pa, flags, size) = last_map();
    assert_eq!(pa, FILE_PA);
    assert_eq!(size, PageSize::P2M, "never a base leaf over a huge page");
    assert!(flags.contains(PageFlags::WRITE));
    assert!(f.put.borrow().is_empty());
}
