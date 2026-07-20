use crate::{page_table_frame_allocated, page_table_frame_released, AddressSpace, VmaBacking, VmaFlags, VmaProt};
use hal::{UserVirtAddr, PAGE_SIZE_BYTES};

const PAGE: usize = PAGE_SIZE_BYTES as usize;

fn uva(x: u64) -> UserVirtAddr { UserVirtAddr::new(x).expect("test user address") }

#[test]
fn vma_accounting_tracks_commit_fixed_replace_unmap_and_mlock() {
    let mm = AddressSpace::new(PAGE_SIZE_BYTES).unwrap();
    let va = uva(0x4000_0000);
    let flags = VmaFlags::PRIVATE | VmaFlags::ANONYMOUS;
    mm.mmap(Some(va), PAGE * 2, VmaProt::READ | VmaProt::WRITE,
        flags, VmaBacking::Anonymous, true).unwrap();
    let s = mm.accounting_snapshot();
    assert_eq!(s.committed_virtual_bytes, (PAGE * 2) as u64);
    assert_eq!(s.locked_virtual_bytes, 0);
    assert_eq!(s.root_page_table_frames, 1);

    mm.update_flags_range(va, PAGE * 2, VmaFlags::LOCKED, VmaFlags::empty());
    let s = mm.accounting_snapshot();
    assert_eq!(s.locked_virtual_bytes, (PAGE * 2) as u64);
    assert_eq!(s.mlock_transitions, 1);

    mm.mmap(Some(va), PAGE, VmaProt::READ, flags | VmaFlags::LOCKED, VmaBacking::Anonymous, true).unwrap();
    let s = mm.accounting_snapshot();
    assert_eq!(s.committed_virtual_bytes, (PAGE * 2) as u64);
    assert_eq!(s.locked_virtual_bytes, (PAGE * 2) as u64);

    mm.munmap(va, PAGE).unwrap();
    let s = mm.accounting_snapshot();
    assert_eq!(s.committed_virtual_bytes, PAGE_SIZE_BYTES);
    assert_eq!(s.locked_virtual_bytes, PAGE_SIZE_BYTES);
}

#[test]
fn page_table_snapshot_tracks_root_and_intermediate_lifecycle() {
    let root = PAGE_SIZE_BYTES * 2;
    let mm = AddressSpace::new(root).unwrap();
    assert_eq!(mm.accounting_snapshot().page_table_frames, 1);
    page_table_frame_allocated(root);
    page_table_frame_allocated(root);
    assert_eq!(mm.accounting_snapshot().page_table_frames, 3);
    page_table_frame_released(root);
    page_table_frame_released(root);
    assert_eq!(mm.accounting_snapshot().page_table_frames, 1);
}
