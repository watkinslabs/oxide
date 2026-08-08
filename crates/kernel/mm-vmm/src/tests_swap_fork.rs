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
enum Leaf { Present(u64, u64), Swap(SwapEntry, bool) }

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
            Some(Leaf::Swap(entry, _)) => Some(*entry), _ => None,
        })
    }
    fn nonpresent_uffd_wp_at(root: u64, va: Va) -> bool {
        with_roots(|roots| matches!(roots.get(&root).and_then(|l| l.get(&va.0)), Some(Leaf::Swap(_, true))))
    }
    unsafe fn map_swap_at(root: u64, va: Va, entry: SwapEntry, uffd_wp: bool) -> Result<(), WalkErr> {
        with_roots(|roots| {
            let leaves = roots.entry(root).or_default();
            if leaves.contains_key(&va.0) { return Err(WalkErr::AlreadyMapped); }
            leaves.insert(va.0, Leaf::Swap(entry, uffd_wp));
            Ok(())
        })
    }
    unsafe fn clear_swap_at(root: u64, va: Va, entry: SwapEntry) -> bool {
        with_roots(|roots| {
            let leaves = roots.entry(root).or_default();
            if matches!(leaves.get(&va.0), Some(Leaf::Swap(current, _)) if *current == entry) {
                leaves.remove(&va.0);
                true
            } else { false }
        })
    }
    unsafe fn activate(root: u64) { ACTIVE.with(|active| *active.borrow_mut() = root); }
}

fn parent_with_swap_wp(flags: VmaFlags, wp: bool) -> Arc<AddressSpace> {
    with_roots(|roots| roots.clear());
    ACTIVE.with(|active| *active.borrow_mut() = PARENT_ROOT);
    let parent = AddressSpace::new(PARENT_ROOT).unwrap();
    let uva = hal::UserVirtAddr::new(TEST_VA).unwrap();
    parent.mmap(Some(uva), PAGE_BYTES as usize, VmaProt::READ | VmaProt::WRITE,
                flags | VmaFlags::ANONYMOUS, VmaBacking::Anonymous, true).unwrap();
    let entry = SwapEntry::new(TEST_SWAP_KIND, TEST_SWAP_OFFSET).unwrap();
    with_roots(|roots| { roots.entry(PARENT_ROOT).or_default().insert(TEST_VA, Leaf::Swap(entry, wp)); });
    parent
}

fn parent_with_swap(flags: VmaFlags) -> Arc<AddressSpace> { parent_with_swap_wp(flags, false) }

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
    with_roots(|roots| { roots.entry(CHILD_ROOT).or_default().insert(TEST_VA, Leaf::Swap(occupied, false)); });
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

/// A monitor whose fork-tracking answer is fixed at construction.
struct ForkMonitor { tracks_fork: bool }

impl crate::uffd::UffdContext for ForkMonitor {
    fn fault(&self, _addr: u64, _kind: crate::uffd::UffdFaultKind, _write: bool, _user: bool) -> bool { true }
    fn wants_event(&self, kind: crate::uffd::UffdEventKind) -> bool {
        self.tracks_fork && matches!(kind, crate::uffd::UffdEventKind::Fork)
    }
    fn fork_dup(&self, _child: alloc::sync::Weak<AddressSpace>)
        -> Option<Arc<dyn crate::uffd::UffdContext>> {
        if self.tracks_fork { Some(Arc::new(ForkMonitor { tracks_fork: true })) } else { None }
    }
}

/// A child that inherits the MONITOR must inherit the barrier riding on its
/// parent's swap leaf, and a child that does not must inherit neither.
///
/// The barrier belongs to a monitor. Copying it into a child the monitor was
/// never told about would block that child's first write on a context with no
/// record of it; dropping it for a child the monitor DID ask about hands back an
/// address space whose first write goes unreported.
#[test]
fn a_child_inherits_the_swap_barrier_exactly_when_it_inherits_the_monitor() {
    for tracks_fork in [true, false] {
        let parent = parent_with_swap_wp(VmaFlags::PRIVATE, true);
        parent.set_uffd(TEST_VA, TEST_VA + PAGE_BYTES,
                        Arc::new(ForkMonitor { tracks_fork }), VmaFlags::UFFD_WP);
        let child = parent.fork_cow_pages_with_swap::<SwapForkMmu, _, _, _, _>(
            CHILD_ROOT, 0, |_| {}, |_, _| Ok(()), |_| {}, |_| {},
        ).unwrap();
        assert_eq!(child.root_pa(), CHILD_ROOT);
        assert_eq!(SwapForkMmu::swap_entry_at(CHILD_ROOT, Va(TEST_VA)),
                   SwapEntry::new(TEST_SWAP_KIND, TEST_SWAP_OFFSET),
                   "the child owns its own reference to the same slot either way");
        assert_eq!(SwapForkMmu::nonpresent_uffd_wp_at(CHILD_ROOT, Va(TEST_VA)), tracks_fork,
                   "the barrier follows the monitor, not the page");
        // The parent keeps its own barrier regardless.
        assert!(SwapForkMmu::nonpresent_uffd_wp_at(PARENT_ROOT, Va(TEST_VA)));
    }
}

/// With no registration at all there is no monitor to inherit, so no child ever
/// gets a barrier — even from a parent leaf that carries one left behind by an
/// unregistration.
#[test]
fn an_unregistered_parent_hands_its_child_no_barrier() {
    let parent = parent_with_swap_wp(VmaFlags::PRIVATE, true);
    let child = parent.fork_cow_pages_with_swap::<SwapForkMmu, _, _, _, _>(
        CHILD_ROOT, 0, |_| {}, |_, _| Ok(()), |_| {}, |_| {},
    ).unwrap();
    assert_eq!(child.root_pa(), CHILD_ROOT);
    assert!(!SwapForkMmu::nonpresent_uffd_wp_at(CHILD_ROOT, Va(TEST_VA)));
}
