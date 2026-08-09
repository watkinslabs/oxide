//! Linux `vm_operations_struct` — the mapped OBJECT's own open/close/may_split
//! hooks, over the VMA tree and the address space.
//!
//! What these pin is lifetime symmetry. A subsystem that charges a resource
//! while its object is mapped (perf's per-user `locked_vm` pages) is only
//! correct if every VMA birth is matched by exactly one death: a charge that
//! outlives its mapping is not a fast failure, it is a mapping loop that
//! refuses everything once the allowance is walked to zero.
//!
//! Counters live on the backing object, not in a static, so these run in
//! parallel with everything else.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI64, Ordering};
use hal::UserVirtAddr;

use crate::address_space::AddressSpace;
use crate::tree::VmaTree;
use crate::vma::{FileBacking, FileBackingError, Vma, VmaBacking, VmaFlags, VmaProt};

const PAGE: u64 = 4096;
const BASE: u64 = 0x4000_0000;

fn uva(a: u64) -> UserVirtAddr { UserVirtAddr::new(a).expect("test VA") }

/// A mapped object that counts its live VMAs, and optionally refuses to be
/// cut — the perf ring's shape.
struct Obj { live: AtomicI64, splittable: bool }

impl Obj {
    fn new(splittable: bool) -> Arc<Obj> { Arc::new(Obj { live: AtomicI64::new(0), splittable }) }
    fn live(&self) -> i64 { self.live.load(Ordering::Acquire) }
}

impl FileBacking for Obj {
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, FileBackingError> { Ok(0) }
    fn size_hint(&self) -> u64 { PAGE * 4 }
    fn vma_open(&self) { self.live.fetch_add(1, Ordering::AcqRel); }
    fn vma_close(&self) { self.live.fetch_sub(1, Ordering::AcqRel); }
    fn may_split(&self) -> bool { self.splittable }
}

fn vma(o: &Arc<Obj>, start: u64, end: u64) -> Vma {
    Vma::new(uva(start), uva(end), VmaProt::READ | VmaProt::WRITE,
             VmaFlags::SHARED,
             VmaBacking::File { backing: o.clone(), off: start - BASE })
}

/// Every path that creates or destroys a VMA runs the object's hooks exactly
/// once, so the live count is back at zero when nothing maps it any more.
#[test]
fn object_hooks_bracket_every_vma_birth_and_death() {
    let o = Obj::new(true);
    let mut t = VmaTree::new();
    t.insert(vma(&o, BASE, BASE + 4 * PAGE)).expect("insert");
    assert_eq!(o.live(), 1, "the establishing mmap is one mapping");

    // A partial mprotect splits: fragments open, the original closes.
    t.mprotect_range(uva(BASE), uva(BASE + PAGE), VmaProt::READ).expect("mprotect");
    assert_eq!(t.len(), 2);
    assert_eq!(o.live(), 2);

    // Merging them back frees one VMA.
    t.mprotect_range(uva(BASE), uva(BASE + PAGE), VmaProt::READ | VmaProt::WRITE)
        .expect("mprotect back");
    assert_eq!(t.len(), 1);
    assert_eq!(o.live(), 1);

    // munmap of the MIDDLE: two fragments survive one original.
    t.remove_range(uva(BASE + PAGE), uva(BASE + 2 * PAGE));
    assert_eq!(t.len(), 2);
    assert_eq!(o.live(), 2, "a split unmap leaves both fragments mapped");

    t.remove_range(uva(BASE), uva(BASE + PAGE));
    assert_eq!(o.live(), 1);

    // Address-space teardown closes whatever is still mapped — the case a
    // process that exits without unmapping hits.
    drop(t);
    assert_eq!(o.live(), 0, "dropping the tree closes every surviving VMA");
}

/// The count a charge is released on is the count of MAPPINGS, so a fork copy
/// of the VMA holds the object mapped until the copy goes too.
#[test]
fn a_second_mapping_of_the_same_object_holds_it_open() {
    let o = Obj::new(true);
    let mut t = VmaTree::new();
    t.insert(vma(&o, BASE, BASE + PAGE)).expect("insert");
    t.insert(vma(&o, BASE + 8 * PAGE, BASE + 9 * PAGE)).expect("insert 2");
    assert_eq!(o.live(), 2);
    t.remove_range(uva(BASE), uva(BASE + PAGE));
    assert_eq!(o.live(), 1, "the other mapping still holds the object");
    t.remove_range(uva(BASE + 8 * PAGE), uva(BASE + 9 * PAGE));
    assert_eq!(o.live(), 0);
}

/// `vm_ops->may_split`: only an INTERIOR cut is refused. A range that covers
/// the VMA whole, or misses it, splits nothing and is admitted.
#[test]
fn only_an_interior_cut_is_refused() {
    let o = Obj::new(false);
    let mut t = VmaTree::new();
    t.insert(vma(&o, BASE, BASE + 4 * PAGE)).expect("insert");
    assert!(t.refuses_split(uva(BASE), uva(BASE + PAGE)), "cut at the tail");
    assert!(t.refuses_split(uva(BASE + PAGE), uva(BASE + 2 * PAGE)), "cut in the middle");
    assert!(t.refuses_split(uva(BASE + 3 * PAGE), uva(BASE + 4 * PAGE)), "cut at the head");
    assert!(!t.refuses_split(uva(BASE), uva(BASE + 4 * PAGE)), "whole VMA is not a split");
    assert!(!t.refuses_split(uva(BASE + 8 * PAGE), uva(BASE + 9 * PAGE)), "disjoint range");

    // A splittable object is never refused.
    let s = Obj::new(true);
    let mut t2 = VmaTree::new();
    t2.insert(vma(&s, BASE, BASE + 4 * PAGE)).expect("insert");
    assert!(!t2.refuses_split(uva(BASE + PAGE), uva(BASE + 2 * PAGE)));
}

fn mapped_as(o: &Arc<Obj>, len: u64) -> Arc<AddressSpace> {
    let a = AddressSpace::new(0).expect("address space");
    a.mmap(Some(uva(BASE)), len as usize, VmaProt::READ | VmaProt::WRITE,
           VmaFlags::SHARED,
           VmaBacking::File { backing: o.clone(), off: 0 }, true)
        .expect("mmap");
    a
}

/// A partial `munmap` of a mapping whose object refuses splitting is EINVAL,
/// and the mapping is left exactly as it was.
#[test]
fn a_partial_unmap_of_an_unsplittable_mapping_is_refused() {
    let o = Obj::new(false);
    let a = mapped_as(&o, 4 * PAGE);
    assert_eq!(o.live(), 1);
    assert_eq!(a.munmap(uva(BASE + PAGE), PAGE as usize), Err(crate::Error::Inval));
    assert_eq!(o.live(), 1, "a refused unmap changes nothing");
    assert!(a.range_refuses_split(uva(BASE + PAGE), PAGE as usize));
    assert!(!a.range_refuses_split(uva(BASE), 4 * PAGE as usize));
    // The whole mapping still unmaps.
    a.munmap(uva(BASE), 4 * PAGE as usize).expect("whole-range unmap");
    assert_eq!(o.live(), 0);
}

/// The same rule on the `mprotect` path: a partial protection change would
/// split, so it is refused before any fragment exists.
#[test]
fn a_partial_mprotect_of_an_unsplittable_mapping_is_refused() {
    let o = Obj::new(false);
    let a = mapped_as(&o, 4 * PAGE);
    assert!(a.mprotect(uva(BASE + PAGE), PAGE as usize, VmaProt::READ).is_err());
    assert_eq!(o.live(), 1);
    // Covering the whole mapping is not a split, so it goes through.
    a.mprotect(uva(BASE), 4 * PAGE as usize, VmaProt::READ).expect("whole mprotect");
    assert_eq!(o.live(), 1);
}
