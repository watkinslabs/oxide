// `queue_pages_range` (`mm/mempolicy.c:979`): mbind's hole (EFAULT) and
// MPOL_MF_STRICT (EIO) decisions.

use hal::UserVirtAddr;

use crate::mempolicy::nodemask::NodeMask;
use crate::mempolicy::scan::*;
use crate::mempolicy::uapi::*;
use crate::vma::{Vma, VmaBacking, VmaFlags, VmaProt};
use crate::Error;
use alloc::vec::Vec;

const PAGE: u64 = 0x1000;
const BASE: u64 = 0x4000_0000;
const NODE0: NodeMask = NodeMask(1);

fn uva(a: u64) -> UserVirtAddr { UserVirtAddr::new(a).unwrap() }

fn anon(start: u64, end: u64) -> Vma {
    Vma::new(uva(start), uva(end), VmaProt::READ | VmaProt::WRITE,
             VmaFlags::PRIVATE | VmaFlags::ANONYMOUS, VmaBacking::Anonymous)
}

fn device(start: u64, end: u64) -> Vma {
    Vma::new(uva(start), uva(end), VmaProt::READ | VmaProt::WRITE,
             VmaFlags::SHARED, VmaBacking::PhysRange { base_pa: 0 })
}

/// Every page resident — the state that makes STRICT observable.
fn all_present(_: u64) -> bool { true }
fn none_present(_: u64) -> bool { false }

#[test]
fn a_fully_mapped_range_with_a_conforming_mask_reports_nothing() {
    let vmas: Vec<Vma> = alloc::vec![anon(BASE, BASE + 4 * PAGE)];
    let r = queue_pages_range(&vmas, BASE, BASE + 4 * PAGE, NODE0,
                              MPOL_MF_STRICT | MPOL_MF_INVERT, all_present);
    assert_eq!(r, Ok(0), "every page is on node 0 and node 0 is in the mask");
}

#[test]
fn a_hole_at_the_head_middle_or_tail_is_efault() {
    let flags = MPOL_MF_STRICT | MPOL_MF_INVERT;
    // Head: the range starts before the first VMA.
    let vmas: Vec<Vma> = alloc::vec![anon(BASE + PAGE, BASE + 2 * PAGE)];
    assert_eq!(queue_pages_range(&vmas, BASE, BASE + 2 * PAGE, NODE0, flags, all_present),
               Err(Error::Fault));
    // Middle: two VMAs with a gap between them.
    let vmas: Vec<Vma> = alloc::vec![anon(BASE, BASE + PAGE), anon(BASE + 2 * PAGE, BASE + 3 * PAGE)];
    assert_eq!(queue_pages_range(&vmas, BASE, BASE + 3 * PAGE, NODE0, flags, all_present),
               Err(Error::Fault));
    // Tail: the range extends past the last VMA.
    let vmas: Vec<Vma> = alloc::vec![anon(BASE, BASE + PAGE)];
    assert_eq!(queue_pages_range(&vmas, BASE, BASE + 2 * PAGE, NODE0, flags, all_present),
               Err(Error::Fault));
    // Whole range unmapped.
    let vmas: Vec<Vma> = Vec::new();
    assert_eq!(queue_pages_range(&vmas, BASE, BASE + PAGE, NODE0, flags, all_present),
               Err(Error::Fault));
}

#[test]
fn mpol_default_sets_discontig_ok_so_holes_are_legal() {
    let flags = MPOL_MF_INVERT | MPOL_MF_DISCONTIG_OK;
    let vmas: Vec<Vma> = alloc::vec![anon(BASE, BASE + PAGE), anon(BASE + 2 * PAGE, BASE + 3 * PAGE)];
    assert_eq!(queue_pages_range(&vmas, BASE, BASE + 3 * PAGE, NodeMask::EMPTY, flags, all_present),
               Ok(0), "MPOL_DEFAULT clears STRICT and permits discontiguous ranges");
}

#[test]
fn strict_with_a_mask_that_excludes_node_zero_reports_every_resident_page() {
    // This is the reachable single-node STRICT failure: mbind(MPOL_LOCAL) and
    // mbind(MPOL_PREFERRED, NULL) both pass an EMPTY nodemask down here, so
    // every resident page is "misplaced" and do_mbind answers -EIO.
    let vmas: Vec<Vma> = alloc::vec![anon(BASE, BASE + 4 * PAGE)];
    let flags = MPOL_MF_STRICT | MPOL_MF_INVERT;
    // strictly_unmovable ⇒ the walk stops at the first misplaced page.
    assert_eq!(queue_pages_range(&vmas, BASE, BASE + 4 * PAGE, NodeMask::EMPTY, flags, all_present),
               Ok(1));
    // No resident pages ⇒ nothing to report, so no EIO.
    assert_eq!(queue_pages_range(&vmas, BASE, BASE + 4 * PAGE, NodeMask::EMPTY, flags, none_present),
               Ok(0));
}

#[test]
fn strict_plus_move_never_fails_when_the_target_node_is_where_the_page_already_is() {
    let vmas: Vec<Vma> = alloc::vec![anon(BASE, BASE + 4 * PAGE)];
    let flags = MPOL_MF_STRICT | MPOL_MF_MOVE | MPOL_MF_INVERT;
    assert!(!strictly_unmovable(flags));
    assert_eq!(queue_pages_range(&vmas, BASE, BASE + 4 * PAGE, NodeMask::EMPTY, flags, all_present),
               Ok(0), "migration to the node the page occupies cannot fail");
}

#[test]
fn a_non_migratable_vma_is_skipped_without_strict_and_counted_with_it() {
    let vmas: Vec<Vma> = alloc::vec![device(BASE, BASE + 2 * PAGE)];
    assert!(!vma_migratable(&vmas[0]), "PhysRange is Linux VM_PFNMAP");
    // Without STRICT the VMA is skipped entirely (test_walk returns 1).
    assert_eq!(queue_pages_range(&vmas, BASE, BASE + 2 * PAGE, NodeMask::EMPTY,
                                 MPOL_MF_MOVE | MPOL_MF_INVERT, all_present), Ok(0));
    // With STRICT it is scanned, and a MOVE bit cannot rescue it.
    assert_eq!(queue_pages_range(&vmas, BASE, BASE + 2 * PAGE, NodeMask::EMPTY,
                                 MPOL_MF_STRICT | MPOL_MF_MOVE | MPOL_MF_INVERT, all_present),
               Ok(2));
}

#[test]
fn without_strict_or_move_the_walk_is_pure_range_checking() {
    let vmas: Vec<Vma> = alloc::vec![anon(BASE, BASE + 4 * PAGE)];
    // No STRICT, no MOVE: the page scan is skipped, only the hole test runs.
    assert_eq!(queue_pages_range(&vmas, BASE, BASE + 4 * PAGE, NodeMask::EMPTY,
                                 MPOL_MF_INVERT, |_| panic!("must not scan pages")),
               Ok(0));
}

#[test]
fn strictly_unmovable_is_strict_without_either_move_bit() {
    assert!(strictly_unmovable(MPOL_MF_STRICT));
    assert!(!strictly_unmovable(MPOL_MF_STRICT | MPOL_MF_MOVE));
    assert!(!strictly_unmovable(MPOL_MF_STRICT | MPOL_MF_MOVE_ALL));
    assert!(!strictly_unmovable(MPOL_MF_MOVE));
    assert!(!strictly_unmovable(0));
}

#[test]
fn migratable_backings_match_linux_vma_migratable() {
    assert!(vma_migratable(&anon(BASE, BASE + PAGE)));
    assert!(!vma_migratable(&device(BASE, BASE + PAGE)));
    let special = Vma::new(uva(BASE), uva(BASE + PAGE), VmaProt::READ,
                           VmaFlags::PRIVATE, VmaBacking::Special);
    assert!(!vma_migratable(&special));
    let kframe = Vma::new(uva(BASE), uva(BASE + PAGE), VmaProt::READ,
                          VmaFlags::SHARED, VmaBacking::KernelFrame { pa: 0 });
    assert!(!vma_migratable(&kframe));
}
