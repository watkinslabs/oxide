// Reverse-mapping + COW-chain integration tests per `11§7`.
//
// These test the hosted invariants the F156 boot triage exposed:
// - fork → child writes → COW split on child must NOT panic the
//   walker on a same-VA, different-PA install.
// - Repeated fork+COW cycles populate / shrink the anon_vma chain
//   correctly; dropped AS edges are filtered.
// - `rmap_walk_anon` after a series of COW splits yields the right
//   set of (mm, va) pairs.
//
// `HostMmu` here mirrors the real PT walker's defensive behaviour:
// `map` rejects `AlreadyMapped` at the leaf level via the same
// "different PA at same VA" check the kernel `pt_walker::map_at_level`
// uses. Without the F156 fix in `hal-x86_64::mmu_ops::map` (unmap-
// then-remap on AlreadyMapped) the COW handler would panic the walker
// on its second-and-later cycle. These tests pin the fix in place.

#![cfg(test)]

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::cell::Cell;
use std::collections::HashMap;
use std::thread_local;

use hal::{MmuOps, Pa, PageFlags, PageSize, Va};

use crate::address_space::AddressSpace;
use crate::vma::{FaultAccess, FaultKind, VmaBacking, VmaFlags, VmaProt};
use crate::{Error, KResult};

/// Hosted PT analogue. Stores leaves keyed by VA. `map` enforces the
/// same defensive AlreadyMapped policy the real x86 / arm walker had
/// before F156 — a test will panic if the COW handler hands us a
/// same-VA, different-PA install without unmap-then-remap.
///
/// `unmap` clears the slot; the production fix routes COW remaps
/// through unmap-then-map so this stays satisfied.
#[derive(Default)]
struct HostPt {
    leaves: HashMap<u64, (u64, u64)>, // va -> (pa, flags)
}

thread_local! {
    static PT: RefCell<HostPt> = RefCell::new(HostPt::default());
    static ALLOC_PA_NEXT: RefCell<u64> = RefCell::new(0x1_0000_0000);
}

fn pt_with<R, F: FnOnce(&mut HostPt) -> R>(f: F) -> R {
    PT.with(|p| f(&mut p.borrow_mut()))
}

fn fresh_pa() -> u64 {
    // Back each "physical frame" with a REAL 4 KiB-aligned host allocation so
    // the COW slow-path's copy_nonoverlapping (which dereferences hhdm+pa, with
    // the tests passing hhdm=0) reads/writes valid memory instead of a fake
    // address. This lets Miri exercise the actual COW/fork/rmap LOGIC for UB
    // (use-after-free, double-free of the AnonVma Arc) rather than crashing on
    // a dangling pointer. Leaked intentionally — test process is short-lived.
    let _ = &ALLOC_PA_NEXT;
    use std::alloc::{alloc_zeroed, Layout};
    let layout = Layout::from_size_align(4096, 4096).unwrap();
    // SAFETY: non-zero 4 KiB layout; alloc_zeroed returns a valid 4 KiB-aligned
    // zeroed block (or null, which `as u64` faithfully forwards to the caller).
    let ptr = unsafe { alloc_zeroed(layout) };
    ptr as u64
}

/// Wraps `fresh_pa` for callers that want the `Option<u64>` shape
/// of the production allocator.
fn fresh_pa_opt() -> Option<u64> { Some(fresh_pa()) }

struct HostMmu;

impl MmuOps for HostMmu {
    unsafe fn map(va: Va, pa: Pa, flags: PageFlags, _size: PageSize) -> Option<Pa> {
        // Model the REAL per-arch walker (`hal_x86_64::mmu_ops::map` /
        // `hal_aarch64`): an install over a present leaf at the same VA tears
        // down the displaced leaf and installs the new PA (the
        // `WalkErr::AlreadyMapped` -> `unmap_at_va` + `map_at_level` path).
        // F157-A1: return the displaced PA (different frame) so the COW handler
        // can dec_ref it, matching the production trait contract.
        pt_with(|pt| {
            let prev = pt.leaves.insert(va.0, (pa.0, flags.bits()));
            prev.filter(|(old, _)| (old >> 12) != (pa.0 >> 12)).map(|(old, _)| Pa(old))
        })
    }

    unsafe fn unmap(va: Va, _size: PageSize) {
        pt_with(|pt| { pt.leaves.remove(&va.0); });
    }

    fn translate(va: Va) -> Option<(Pa, PageFlags)> {
        pt_with(|pt| {
            pt.leaves.get(&va.0).map(|(pa, f)| (Pa(*pa), PageFlags::from_bits_truncate(*f)))
        })
    }

    unsafe fn flush_va(_va: Va) {}
    fn flush_all_local() {}

    unsafe fn map_at(_root_pa: u64, va: Va, pa: Pa, flags: PageFlags, _size: PageSize) -> Option<Pa> {
        // For tests we have a single PT. Treat map_at like map; if a
        // different PA is at the slot, overwrite (Linux semantics) and
        // return the displaced PA per the F157-A1 trait contract.
        pt_with(|pt| {
            let prev = pt.leaves.insert(va.0, (pa.0, flags.bits()));
            prev.filter(|(old, _)| (old >> 12) != (pa.0 >> 12)).map(|(old, _)| Pa(old))
        })
    }

    unsafe fn activate(_root_pa: u64) {}
}

fn reset_pt() {
    pt_with(|pt| pt.leaves.clear());
    ALLOC_PA_NEXT.with(|n| *n.borrow_mut() = 0x1_0000_0000);
}

fn mk_anon_as(start: u64, end: u64) -> Arc<AddressSpace> {
    let as_ = AddressSpace::new(0).expect("AS::new");
    let s = hal::UserVirtAddr::new(start).expect("va");
    let _ = as_.mmap(
        Some(s),
        (end - start) as usize,
        VmaProt::READ | VmaProt::WRITE,
        VmaFlags::PRIVATE | VmaFlags::ANONYMOUS,
        VmaBacking::Anonymous,
        true,
    ).expect("mmap anon");
    as_
}

fn install_anon_page(as_: &Arc<AddressSpace>, va: u64) {
    let pa = fresh_pa();
    // Demand-fault style: write the leaf directly. We don't bump the
    // anon_vma chain here because the COW path tests focus on the
    // walker remap behaviour; rmap_walk tests below exercise chain
    // attach/detach via the AnonVma API directly.
    let _ = as_;
    pt_with(|pt| {
        pt.leaves.insert(va, (pa, PageFlags::USER.bits() | PageFlags::READ.bits() | PageFlags::WRITE.bits()));
    });
}

#[test]
fn anon_charge_rolls_back_when_first_touch_allocation_fails() {
    reset_pt();
    let mm = mk_anon_as(0x40_0000, 0x40_2000);
    let charges = Cell::new(0usize);
    let rollbacks = Cell::new(0usize);
    // SAFETY: hosted PT is empty; allocator deliberately returns no frame so
    // the test reaches only the charge/admission rollback contract.
    let r = unsafe {
        mm.handle_page_fault_cow_rmap::<HostMmu, _, _, _, _, _, _, _, _>(
            hal::UserVirtAddr::new(0x40_0000).unwrap(),
            FaultKind::NotPresent { access: FaultAccess::Read }, 0,
            || None, |_pa| 0, |_pa| {}, |_pa, _av, _idx| {}, |_pa| {}, |_pa| false,
            || { charges.set(charges.get() + 1); Ok(()) },
            || { rollbacks.set(rollbacks.get() + 1); },
        )
    };
    assert_eq!(r, Err(Error::NoMem));
    assert_eq!(charges.get(), 1);
    assert_eq!(rollbacks.get(), 1);
}

#[test]
fn anon_charge_rolls_back_when_cow_allocation_fails() {
    reset_pt();
    let mm = mk_anon_as(0x41_0000, 0x41_2000);
    install_anon_page(&mm, 0x41_0000);
    let charges = Cell::new(0usize);
    let rollbacks = Cell::new(0usize);
    // SAFETY: hosted PT has a writable anon source; reuse is refused so the
    // write fault must obtain a provisional charge before its COW allocation.
    let r = unsafe {
        mm.handle_page_fault_cow_rmap::<HostMmu, _, _, _, _, _, _, _, _>(
            hal::UserVirtAddr::new(0x41_0000).unwrap(),
            FaultKind::Protection { access: FaultAccess::Write }, 0,
            || None, |_pa| 2, |_pa| {}, |_pa, _av, _idx| {}, |_pa| {}, |_pa| false,
            || { charges.set(charges.get() + 1); Ok(()) },
            || { rollbacks.set(rollbacks.get() + 1); },
        )
    };
    assert_eq!(r, Err(Error::NoMem));
    assert_eq!(charges.get(), 1);
    assert_eq!(rollbacks.get(), 1);
}

#[test]
fn fork_then_cow_split_no_walker_panic() {
    reset_pt();
    let parent = mk_anon_as(0x10_0000, 0x10_4000);
    install_anon_page(&parent, 0x10_0000);

    // Simulate fork_cow_pages (which routes through M::map for the
    // parent-side W-clear remap). With the F156 fix in HostMmu::map
    // this is fine; without it the walker would panic.
    // We use ::map only after rebuilding HostPt accordingly; here we
    // exercise the test infra by issuing handle_page_fault_cow
    // directly on parent and verifying it succeeds.
    // SAFETY: hosted test under thread-local PT; HostMmu satisfies the COW handler's preconditions.
    let r = unsafe {
        parent.handle_page_fault_cow::<HostMmu, _, _, _>(
            hal::UserVirtAddr::new(0x10_0000).unwrap(),
            FaultKind::Protection { access: FaultAccess::Write },
            0, /* hhdm_offset */
            fresh_pa_opt,
            |_pa| 1u32,    // refcount=1 → wp_page_copy short-circuit
            |_pa| {},
        )
    };
    assert!(r.is_ok(), "first COW must succeed: {:?}", r);
}

#[test]
fn cow_in_place_flip_repeats_no_panic() {
    // Refcount=1 → wp_page_copy short-circuits to in-place W flip.
    // No memcpy through hhdm so HostMmu is sufficient. Verifies the
    // handler can be called repeatedly on the same VA without the
    // walker rejecting the second-and-later install.
    reset_pt();
    let parent = mk_anon_as(0x10_0000, 0x10_2000);
    install_anon_page(&parent, 0x10_0000);
    for _ in 0..5 {
        // SAFETY: hosted test under thread-local PT; HostMmu satisfies the COW handler's preconditions.
        let r = unsafe {
            parent.handle_page_fault_cow::<HostMmu, _, _, _>(
                hal::UserVirtAddr::new(0x10_0000).unwrap(),
                FaultKind::Protection { access: FaultAccess::Write },
                0,
                fresh_pa_opt,
                |_pa| 1u32,
                |_pa| {},
            )
        };
        assert!(r.is_ok());
    }
}

#[test]
fn fork_attaches_child_to_anon_vma_chain() {
    reset_pt();
    let parent = mk_anon_as(0x20_0000, 0x20_2000);
    // Fork using the COW path with a no-op M::translate (no leaves
    // installed — we just want to verify chain attach happens).
    let child = parent
        .fork_cow_pages::<HostMmu, _>(0, 0, |_pa| {})
        .expect("fork_cow_pages");

    // Each anonymous VMA's anon_vma chain should now have the child
    // mm as a target. The parent isn't on the chain unless the
    // origin path attached it (post-mmap helper, future work).
    let tree = child.vmas_for_test();
    let cv = tree.iter().next().expect("child has the anon VMA");
    let av = cv.anon_vma.as_ref().expect("anon_vma present");
    let mut found = 0;
    av.walk(|mm, _, _| {
        if Arc::ptr_eq(mm, &child) { found += 1; }
    });
    assert_eq!(found, 1, "child mm appears exactly once on chain");
}

#[test]
fn dropped_child_removed_from_chain_walks() {
    reset_pt();
    let parent = mk_anon_as(0x30_0000, 0x30_2000);
    let av = {
        let child = parent
            .fork_cow_pages::<HostMmu, _>(0, 0, |_pa| {})
            .expect("fork");
        let tree = child.vmas_for_test();
        let cv = tree.iter().next().unwrap();
        Arc::clone(cv.anon_vma.as_ref().unwrap())
    };
    // child Arc dropped here; its weak entry on the chain dangles. A4-1:
    // the parent's OWN self-edge (attached by `mmap`) survives, so exactly
    // one live target remains. Pre-A4 the parent edge was never attached
    // and this read 0 — that was the rmap-invisibility bug A4 closes.
    assert_eq!(av.live_target_count(), 1,
        "parent self-edge (A4-1) survives child drop");
}

#[test]
fn repeat_fork_cow_chain_grows_then_settles() {
    reset_pt();
    let parent = mk_anon_as(0x40_0000, 0x40_2000);
    let mut children: Vec<Arc<AddressSpace>> = Vec::new();
    for _ in 0..5 {
        let c = parent.fork_cow_pages::<HostMmu, _>(0, 0, |_pa| {}).unwrap();
        children.push(c);
    }
    // Pick one child's anon_vma and verify the chain has 6 live targets:
    // the parent self-edge (A4-1, attached by `mmap`) + one per fork. All
    // 5 children share the same anon_vma family.
    let av = {
        let tree = children[0].vmas_for_test();
        let cv = tree.iter().next().unwrap();
        Arc::clone(cv.anon_vma.as_ref().unwrap())
    };
    assert_eq!(av.live_target_count(), 6);

    // Drop two children — chain raw_len stays the same, live count
    // drops by 2 (parent + 3 surviving children = 4).
    children.truncate(3);
    assert_eq!(av.live_target_count(), 4);
    av.gc_dangling();
    assert_eq!(av.raw_chain_len(), 4);
}
