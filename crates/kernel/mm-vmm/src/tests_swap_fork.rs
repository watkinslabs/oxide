//! Fork ownership tests for non-present swap PTEs.

#![cfg(test)]

use alloc::sync::Arc;
use core::cell::RefCell;
use std::collections::HashMap;
use std::thread_local;

use hal::{MmuOps, Pa, PageFlags, PageSize, Va};
use hal::pt_walker::{SwapEntry, WalkErr};

use crate::address_space::AddressSpace;
use crate::vma::{VmaBacking, VmaFlags, VmaProt};
use crate::Error;

const PAGE_BYTES: u64 = hal::PAGE_SIZE_BYTES;
const PARENT_ROOT: u64 = 1;
const CHILD_ROOT: u64 = 2;
const TEST_VA: u64 = 0x0000_0000_4100_0000;
const TEST_SWAP_KIND: u8 = 1;
const TEST_SWAP_OFFSET: u64 = 42;

#[derive(Copy, Clone)]
enum Leaf { Present(u64, u64), Swap(SwapEntry) }

thread_local! {
    static ROOTS: RefCell<HashMap<u64, HashMap<u64, Leaf>>> = RefCell::new(HashMap::new());
    static ACTIVE: RefCell<u64> = RefCell::new(PARENT_ROOT);
}

fn with_roots<R>(f: impl FnOnce(&mut HashMap<u64, HashMap<u64, Leaf>>) -> R) -> R {
    ROOTS.with(|roots| f(&mut roots.borrow_mut()))
}

struct SwapForkMmu;
impl MmuOps for SwapForkMmu {
    unsafe fn map(va: Va, pa: Pa, flags: PageFlags, _size: PageSize) -> Option<Pa> {
        let root = ACTIVE.with(|active| *active.borrow());
        with_roots(|roots| match roots.entry(root).or_default().insert(va.0, Leaf::Present(pa.0, flags.bits())) {
            Some(Leaf::Present(old, _)) if old != pa.0 => Some(Pa(old)),
            _ => None,
        })
    }
    unsafe fn unmap(va: Va, _size: PageSize) {
        let root = ACTIVE.with(|active| *active.borrow());
        with_roots(|roots| { let _ = roots.entry(root).or_default().remove(&va.0); });
    }
    fn translate(va: Va) -> Option<(Pa, PageFlags)> {
        let root = ACTIVE.with(|active| *active.borrow());
        with_roots(|roots| match roots.get(&root).and_then(|leaves| leaves.get(&va.0)) {
            Some(Leaf::Present(pa, flags)) => Some((Pa(*pa), PageFlags::from_bits_retain(*flags))),
            _ => None,
        })
    }
    unsafe fn flush_va(_va: Va) {}
    fn flush_all_local() {}
    unsafe fn map_at(root: u64, va: Va, pa: Pa, flags: PageFlags, _size: PageSize) -> Option<Pa> {
        with_roots(|roots| match roots.entry(root).or_default().insert(va.0, Leaf::Present(pa.0, flags.bits())) {
            Some(Leaf::Present(old, _)) if old != pa.0 => Some(Pa(old)),
            _ => None,
        })
    }
    fn swap_entry_at(root: u64, va: Va) -> Option<SwapEntry> {
        with_roots(|roots| match roots.get(&root).and_then(|leaves| leaves.get(&va.0)) {
            Some(Leaf::Swap(entry)) => Some(*entry), _ => None,
        })
    }
    unsafe fn map_swap_at(root: u64, va: Va, entry: SwapEntry) -> Result<(), WalkErr> {
        with_roots(|roots| {
            let leaves = roots.entry(root).or_default();
            if leaves.contains_key(&va.0) { return Err(WalkErr::AlreadyMapped); }
            leaves.insert(va.0, Leaf::Swap(entry));
            Ok(())
        })
    }
    unsafe fn clear_swap_at(root: u64, va: Va, entry: SwapEntry) -> bool {
        with_roots(|roots| {
            let leaves = roots.entry(root).or_default();
            if matches!(leaves.get(&va.0), Some(Leaf::Swap(current)) if *current == entry) {
                leaves.remove(&va.0);
                true
            } else { false }
        })
    }
    unsafe fn activate(root: u64) { ACTIVE.with(|active| *active.borrow_mut() = root); }
}

fn parent_with_swap(flags: VmaFlags) -> Arc<AddressSpace> {
    with_roots(|roots| roots.clear());
    ACTIVE.with(|active| *active.borrow_mut() = PARENT_ROOT);
    let parent = AddressSpace::new(PARENT_ROOT).unwrap();
    let uva = hal::UserVirtAddr::new(TEST_VA).unwrap();
    parent.mmap(Some(uva), PAGE_BYTES as usize, VmaProt::READ | VmaProt::WRITE,
                flags | VmaFlags::ANONYMOUS, VmaBacking::Anonymous, true).unwrap();
    let entry = SwapEntry::new(TEST_SWAP_KIND, TEST_SWAP_OFFSET).unwrap();
    with_roots(|roots| { roots.entry(PARENT_ROOT).or_default().insert(TEST_VA, Leaf::Swap(entry)); });
    parent
}

#[test]
fn fork_clones_swap_leaf_and_acquires_exact_slot_reference() {
    let parent = parent_with_swap(VmaFlags::PRIVATE);
    let retained = core::cell::Cell::new(0usize);
    let released = core::cell::Cell::new(0usize);
    let child = parent.fork_cow_pages_with_swap::<SwapForkMmu, _, _, _, _>(
        CHILD_ROOT, 0, |_| {},
        |_, _| { retained.set(retained.get() + 1); Ok(()) },
        |_| released.set(released.get() + 1),
        |_| {},
    ).unwrap();
    assert_eq!(child.root_pa(), CHILD_ROOT);
    assert_eq!(SwapForkMmu::swap_entry_at(CHILD_ROOT, Va(TEST_VA)),
               SwapEntry::new(TEST_SWAP_KIND, TEST_SWAP_OFFSET));
    assert_eq!(retained.get(), 1);
    assert_eq!(released.get(), 0);
}

#[test]
fn fork_swap_install_failure_releases_provisional_reference() {
    let parent = parent_with_swap(VmaFlags::PRIVATE);
    let occupied = SwapEntry::new(TEST_SWAP_KIND, TEST_SWAP_OFFSET + 1).unwrap();
    with_roots(|roots| { roots.entry(CHILD_ROOT).or_default().insert(TEST_VA, Leaf::Swap(occupied)); });
    let retained = core::cell::Cell::new(0usize);
    let released = core::cell::Cell::new(0usize);
    let result = parent.fork_cow_pages_with_swap::<SwapForkMmu, _, _, _, _>(
        CHILD_ROOT, 0, |_| {},
        |_, _| { retained.set(retained.get() + 1); Ok(()) },
        |_| released.set(released.get() + 1),
        |_| {},
    );
    assert!(matches!(result, Err(Error::NoMem)));
    assert_eq!(retained.get(), 1);
    assert_eq!(released.get(), 1);
    assert_eq!(SwapForkMmu::swap_entry_at(CHILD_ROOT, Va(TEST_VA)), Some(occupied));
}

#[test]
fn fork_dontfork_and_wipeonfork_do_not_copy_swap_leaf() {
    for flags in [VmaFlags::PRIVATE | VmaFlags::DONTFORK, VmaFlags::PRIVATE | VmaFlags::WIPEONFORK] {
        let parent = parent_with_swap(flags);
        let retained = core::cell::Cell::new(0usize);
        let child = parent.fork_cow_pages_with_swap::<SwapForkMmu, _, _, _, _>(
            CHILD_ROOT, 0, |_| {},
            |_, _| { retained.set(retained.get() + 1); Ok(()) }, |_| {}, |_| {},
        ).unwrap();
        assert_eq!(child.root_pa(), CHILD_ROOT);
        assert_eq!(SwapForkMmu::swap_entry_at(CHILD_ROOT, Va(TEST_VA)), None);
        assert_eq!(retained.get(), 0);
    }
}
