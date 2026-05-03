// VMA tree tests: invariant 1 (non-overlap, `11§2`) + split/merge
// behavior (`11§4`, `11§6`). Per `11§11` this is the hosted-unit
// portion of the test contract; QEMU integration + soak land in
// `40§3`-controlled CI.

use super::*;
use crate::vma::{Vma, VmaBacking, VmaFlags, VmaProt};

use hal::{UserVirtAddr, PAGE_SIZE_BYTES};
use std::sync::Arc;
use std::thread;
use std::vec::Vec;

fn uva(x: u64) -> UserVirtAddr {
    UserVirtAddr::new(x).expect("test address fits user range")
}

fn anon(start: u64, end: u64, prot: VmaProt) -> Vma {
    Vma::new(uva(start), uva(end), prot, VmaFlags::PRIVATE | VmaFlags::ANONYMOUS, VmaBacking::Anonymous)
}

fn file(start: u64, end: u64, off: u64, prot: VmaProt) -> Vma {
    Vma::new(uva(start), uva(end), prot, VmaFlags::PRIVATE, VmaBacking::File { off })
}

#[test]
fn empty_tree() {
    let t = VmaTree::new();
    assert_eq!(t.len(), 0);
    assert!(t.is_empty());
    assert!(t.find_containing(uva(0x1000)).is_none());
    t.audit_no_overlap().unwrap();
}

#[test]
fn insert_find_basic() {
    let mut t = VmaTree::new();
    t.insert(anon(0x1000, 0x4000, VmaProt::READ | VmaProt::WRITE)).unwrap();
    assert_eq!(t.len(), 1);
    assert!(t.find_containing(uva(0x1000)).is_some());
    assert!(t.find_containing(uva(0x3fff)).is_some());
    assert!(t.find_containing(uva(0x4000)).is_none()); // end exclusive
    assert!(t.find_containing(uva(0x0fff)).is_none()); // hole below
}

#[test]
fn insert_rejects_degenerate_range() {
    let mut t = VmaTree::new();
    let bad = Vma::new(uva(0x2000), uva(0x2000), VmaProt::READ,
                       VmaFlags::PRIVATE, VmaBacking::Anonymous);
    assert_eq!(t.insert(bad), Err(Error::Inval));
    let bad2 = Vma::new(uva(0x3000), uva(0x2000), VmaProt::READ,
                        VmaFlags::PRIVATE, VmaBacking::Anonymous);
    assert_eq!(t.insert(bad2), Err(Error::Inval));
}

#[test]
fn insert_rejects_overlap() {
    let mut t = VmaTree::new();
    t.insert(anon(0x1000, 0x4000, VmaProt::READ)).unwrap();

    // Exact same range.
    assert_eq!(t.insert(anon(0x1000, 0x4000, VmaProt::WRITE)), Err(Error::Inval));
    // Strict subset (different prot to defeat merge).
    assert_eq!(t.insert(anon(0x2000, 0x3000, VmaProt::WRITE)), Err(Error::Inval));
    // Left overlap.
    assert_eq!(t.insert(anon(0x0800, 0x2000, VmaProt::WRITE)), Err(Error::Inval));
    // Right overlap.
    assert_eq!(t.insert(anon(0x3000, 0x5000, VmaProt::WRITE)), Err(Error::Inval));

    t.audit_no_overlap().unwrap();
    assert_eq!(t.len(), 1);
}

#[test]
fn insert_abutting_non_compatible_no_merge() {
    let mut t = VmaTree::new();
    t.insert(anon(0x1000, 0x2000, VmaProt::READ)).unwrap();
    // Abuts but different prot ⇒ stays separate.
    t.insert(anon(0x2000, 0x3000, VmaProt::WRITE)).unwrap();
    assert_eq!(t.len(), 2);
    t.audit_no_overlap().unwrap();
}

#[test]
fn insert_merges_compatible_left_neighbor() {
    let mut t = VmaTree::new();
    t.insert(anon(0x1000, 0x2000, VmaProt::READ)).unwrap();
    t.insert(anon(0x2000, 0x3000, VmaProt::READ)).unwrap();
    assert_eq!(t.len(), 1);
    let v = t.iter().next().unwrap();
    assert_eq!(v.start, uva(0x1000));
    assert_eq!(v.end,   uva(0x3000));
}

#[test]
fn insert_merges_compatible_right_neighbor() {
    let mut t = VmaTree::new();
    t.insert(anon(0x2000, 0x3000, VmaProt::READ)).unwrap();
    t.insert(anon(0x1000, 0x2000, VmaProt::READ)).unwrap();
    assert_eq!(t.len(), 1);
    let v = t.iter().next().unwrap();
    assert_eq!(v.start, uva(0x1000));
    assert_eq!(v.end,   uva(0x3000));
}

#[test]
fn insert_merges_both_neighbors() {
    let mut t = VmaTree::new();
    t.insert(anon(0x1000, 0x2000, VmaProt::READ)).unwrap();
    t.insert(anon(0x3000, 0x4000, VmaProt::READ)).unwrap();
    // Hole [0x2000, 0x3000); fill it with compatible VMA.
    t.insert(anon(0x2000, 0x3000, VmaProt::READ)).unwrap();
    assert_eq!(t.len(), 1);
    let v = t.iter().next().unwrap();
    assert_eq!(v.start, uva(0x1000));
    assert_eq!(v.end,   uva(0x4000));
}

#[test]
fn file_backed_merge_requires_contig_offset() {
    let mut t = VmaTree::new();
    t.insert(file(0x1000, 0x2000, 0, VmaProt::READ)).unwrap();
    // Contiguous offset → merges.
    t.insert(file(0x2000, 0x3000, 0x1000, VmaProt::READ)).unwrap();
    assert_eq!(t.len(), 1);

    // Non-contiguous offset → separate VMA.
    t.insert(file(0x3000, 0x4000, 0xdead, VmaProt::READ)).unwrap();
    assert_eq!(t.len(), 2);
}

#[test]
fn special_backing_never_merges() {
    let mut t = VmaTree::new();
    let prot = VmaProt::READ;
    t.insert(Vma::new(uva(0x1000), uva(0x2000), prot, VmaFlags::PRIVATE, VmaBacking::Special)).unwrap();
    t.insert(Vma::new(uva(0x2000), uva(0x3000), prot, VmaFlags::PRIVATE, VmaBacking::Special)).unwrap();
    assert_eq!(t.len(), 2, "special VMAs must not merge per `11§4`");
}

#[test]
fn remove_range_full_unmap() {
    let mut t = VmaTree::new();
    t.insert(anon(0x1000, 0x4000, VmaProt::READ)).unwrap();
    let removed = t.remove_range(uva(0x1000), uva(0x4000));
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].start, uva(0x1000));
    assert_eq!(removed[0].end,   uva(0x4000));
    assert!(t.is_empty());
}

#[test]
fn remove_range_punches_hole_in_middle() {
    let mut t = VmaTree::new();
    t.insert(anon(0x1000, 0x5000, VmaProt::READ)).unwrap();
    let removed = t.remove_range(uva(0x2000), uva(0x4000));
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].start, uva(0x2000));
    assert_eq!(removed[0].end,   uva(0x4000));
    // Two surviving fragments.
    assert_eq!(t.len(), 2);
    let mut it = t.iter();
    let l = it.next().unwrap();
    assert_eq!((l.start, l.end), (uva(0x1000), uva(0x2000)));
    let r = it.next().unwrap();
    assert_eq!((r.start, r.end), (uva(0x4000), uva(0x5000)));
    t.audit_no_overlap().unwrap();
}

#[test]
fn remove_range_spans_multiple_vmas_with_partial_endpoints() {
    let mut t = VmaTree::new();
    t.insert(anon(0x1000, 0x3000, VmaProt::READ)).unwrap();
    t.insert(anon(0x3000, 0x5000, VmaProt::WRITE)).unwrap(); // diff prot ⇒ no merge
    t.insert(anon(0x6000, 0x8000, VmaProt::READ)).unwrap();
    // Range cuts through middle VMA's right half + all of third VMA's left half.
    let removed = t.remove_range(uva(0x2000), uva(0x7000));
    // Expected: kept fragments [0x1000..0x2000) and [0x7000..0x8000); the
    // hole [0x5000..0x6000) yields no removed VMA (no coverage there).
    assert_eq!(t.len(), 2);
    t.audit_no_overlap().unwrap();
    // Removed pieces correspond to the three intersecting VMAs' overlapping
    // portions.
    assert_eq!(removed.len(), 3);
}

#[test]
fn remove_range_no_intersection() {
    let mut t = VmaTree::new();
    t.insert(anon(0x1000, 0x2000, VmaProt::READ)).unwrap();
    t.insert(anon(0x4000, 0x5000, VmaProt::READ)).unwrap();
    let removed = t.remove_range(uva(0x2000), uva(0x4000));
    assert!(removed.is_empty());
    assert_eq!(t.len(), 2);
}

#[test]
fn file_backing_offset_adjusts_on_split() {
    let mut t = VmaTree::new();
    t.insert(file(0x1000, 0x5000, 0, VmaProt::READ)).unwrap();
    let removed = t.remove_range(uva(0x2000), uva(0x4000));
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].backing, VmaBacking::File { off: 0x1000 });

    // Right-kept fragment offset shifted by full prefix length (0x3000).
    let mut it = t.iter();
    let _left = it.next().unwrap();
    let right = it.next().unwrap();
    assert_eq!(right.backing, VmaBacking::File { off: 0x3000 });
}

#[test]
fn mprotect_full_vma() {
    let mut t = VmaTree::new();
    t.insert(anon(0x1000, 0x4000, VmaProt::READ)).unwrap();
    t.mprotect_range(uva(0x1000), uva(0x4000), VmaProt::READ | VmaProt::WRITE).unwrap();
    let v = t.iter().next().unwrap();
    assert_eq!(v.prot, VmaProt::READ | VmaProt::WRITE);
    assert_eq!(t.len(), 1);
}

#[test]
fn mprotect_splits_at_boundaries() {
    let mut t = VmaTree::new();
    t.insert(anon(0x1000, 0x5000, VmaProt::READ)).unwrap();
    t.mprotect_range(uva(0x2000), uva(0x4000), VmaProt::READ | VmaProt::WRITE).unwrap();
    assert_eq!(t.len(), 3);
    let mut it = t.iter();
    let a = it.next().unwrap();
    let b = it.next().unwrap();
    let c = it.next().unwrap();
    assert_eq!((a.start, a.end, a.prot), (uva(0x1000), uva(0x2000), VmaProt::READ));
    assert_eq!((b.start, b.end, b.prot),
               (uva(0x2000), uva(0x4000), VmaProt::READ | VmaProt::WRITE));
    assert_eq!((c.start, c.end, c.prot), (uva(0x4000), uva(0x5000), VmaProt::READ));
    t.audit_no_overlap().unwrap();
}

#[test]
fn mprotect_rejects_hole() {
    let mut t = VmaTree::new();
    t.insert(anon(0x1000, 0x2000, VmaProt::READ)).unwrap();
    t.insert(anon(0x3000, 0x4000, VmaProt::READ)).unwrap();
    // Range straddles a hole.
    assert_eq!(
        t.mprotect_range(uva(0x1800), uva(0x3800), VmaProt::WRITE),
        Err(Error::Inval),
    );
    // Tree unchanged.
    assert_eq!(t.len(), 2);
}

#[test]
fn mprotect_then_back_remerges() {
    let mut t = VmaTree::new();
    t.insert(anon(0x1000, 0x4000, VmaProt::READ)).unwrap();
    // Demote middle.
    t.mprotect_range(uva(0x2000), uva(0x3000), VmaProt::WRITE).unwrap();
    assert_eq!(t.len(), 3);
    // Restore middle to original.
    t.mprotect_range(uva(0x2000), uva(0x3000), VmaProt::READ).unwrap();
    // All three fragments now have identical prot/flags/backing ⇒ merge.
    assert_eq!(t.len(), 1);
    let v = t.iter().next().unwrap();
    assert_eq!((v.start, v.end), (uva(0x1000), uva(0x4000)));
}

#[test]
fn dense_random_pattern_preserves_invariant_1() {
    // Deterministic pseudo-random pattern: alternating insert / remove
    // across the user space; assert non-overlap holds throughout.
    let mut t = VmaTree::new();
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    for i in 0..200u64 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let base = ((state >> 12) & 0x0fff) << 12; // page-aligned, < 2^40
        let len  = (((state >> 28) & 0xf) + 1) << 12; // 1..16 pages
        let start = base;
        let end   = base + len;
        if end >= 0x4000_0000_0000 { continue; }
        let prot = if i & 1 == 0 { VmaProt::READ } else { VmaProt::READ | VmaProt::WRITE };
        // Clear the destination first; then insert.
        t.remove_range(uva(start), uva(end));
        t.insert(anon(start, end, prot)).unwrap();
        t.audit_no_overlap().unwrap();
    }
    // After the loop, audit still holds.
    t.audit_no_overlap().unwrap();
}

// ---------------------------------------------------------------------------
// AddressSpace tests (`11§3`).
// ---------------------------------------------------------------------------

const PAGE: usize = PAGE_SIZE_BYTES as usize;

fn r_w() -> VmaProt { VmaProt::READ | VmaProt::WRITE }
fn priv_anon() -> VmaFlags { VmaFlags::PRIVATE | VmaFlags::ANONYMOUS }

#[test]
fn address_space_new_is_empty() {
    let a = AddressSpace::new(0).unwrap();
    assert_eq!(a.vma_count(), 0);
    a.audit().unwrap();
}

#[test]
fn mmap_no_hint_returns_min_user_va() {
    let a = AddressSpace::new(0).unwrap();
    let va = a.mmap(None, PAGE, r_w(), priv_anon(), VmaBacking::Anonymous, false).unwrap();
    assert_eq!(va.as_u64(), MIN_USER_VA);
    assert_eq!(a.vma_count(), 1);
    a.audit().unwrap();
}

#[test]
fn mmap_hint_honored_when_clear() {
    let a = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(0x4000_0000).unwrap();
    let va = a.mmap(Some(h), PAGE, r_w(), priv_anon(), VmaBacking::Anonymous, false).unwrap();
    assert_eq!(va, h);
}

#[test]
fn mmap_hint_falls_back_when_overlap() {
    let a = AddressSpace::new(0).unwrap();
    // First map at hint H.
    let h = UserVirtAddr::new(0x4000_0000).unwrap();
    let _ = a.mmap(Some(h), 4 * PAGE, r_w(), priv_anon(), VmaBacking::Anonymous, false).unwrap();
    // Second mmap with same hint: hint occupied, must succeed elsewhere.
    let va = a.mmap(Some(h), PAGE, r_w(), priv_anon(), VmaBacking::Anonymous, false).unwrap();
    assert_ne!(va, h);
    assert_eq!(a.vma_count(), 2);
    a.audit().unwrap();
}

#[test]
fn mmap_fixed_clears_overlap_first() {
    let a = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(0x4000_0000).unwrap();
    a.mmap(Some(h), 4 * PAGE, VmaProt::READ, priv_anon(), VmaBacking::Anonymous, false).unwrap();
    // Overlapping FIXED replaces the conflicting region.
    let va = a.mmap(Some(h), 2 * PAGE, r_w(), priv_anon(), VmaBacking::Anonymous, true).unwrap();
    assert_eq!(va, h);
    a.audit().unwrap();
    // The covered range must report the new prot.
    let v = a.find_vma(h).unwrap();
    assert_eq!(v.prot, r_w());
}

#[test]
fn mmap_rejects_zero_length_and_misalignment() {
    let a = AddressSpace::new(0).unwrap();
    assert_eq!(
        a.mmap(None, 0, r_w(), priv_anon(), VmaBacking::Anonymous, false),
        Err(Error::Inval)
    );
    assert_eq!(
        a.mmap(None, 0x123, r_w(), priv_anon(), VmaBacking::Anonymous, false),
        Err(Error::Inval)
    );
    let unaligned = UserVirtAddr::new(0x4000_0001).unwrap();
    assert_eq!(
        a.mmap(Some(unaligned), PAGE, r_w(), priv_anon(), VmaBacking::Anonymous, true),
        Err(Error::Inval)
    );
}

#[test]
fn mmap_fixed_without_hint_is_inval() {
    let a = AddressSpace::new(0).unwrap();
    assert_eq!(
        a.mmap(None, PAGE, r_w(), priv_anon(), VmaBacking::Anonymous, true),
        Err(Error::Inval)
    );
}

#[test]
fn munmap_round_trip() {
    let a = AddressSpace::new(0).unwrap();
    let va = a.mmap(None, 4 * PAGE, r_w(), priv_anon(), VmaBacking::Anonymous, false).unwrap();
    a.munmap(va, 4 * PAGE).unwrap();
    assert_eq!(a.vma_count(), 0);
    assert!(a.find_vma(va).is_none());
}

#[test]
fn munmap_punches_hole() {
    let a = AddressSpace::new(0).unwrap();
    let va = a.mmap(None, 4 * PAGE, r_w(), priv_anon(), VmaBacking::Anonymous, false).unwrap();
    let mid = UserVirtAddr::new(va.as_u64() + PAGE as u64).unwrap();
    a.munmap(mid, PAGE).unwrap();
    assert_eq!(a.vma_count(), 2);
    a.audit().unwrap();
}

#[test]
fn mprotect_changes_prot() {
    let a = AddressSpace::new(0).unwrap();
    let va = a.mmap(None, 4 * PAGE, VmaProt::READ, priv_anon(), VmaBacking::Anonymous, false).unwrap();
    a.mprotect(va, 4 * PAGE, r_w()).unwrap();
    let v = a.find_vma(va).unwrap();
    assert_eq!(v.prot, r_w());
}

#[test]
fn mprotect_rejects_hole_inside_range() {
    let a = AddressSpace::new(0).unwrap();
    let h1 = UserVirtAddr::new(0x4000_0000).unwrap();
    let h2 = UserVirtAddr::new(0x4000_2000).unwrap();
    a.mmap(Some(h1), PAGE, VmaProt::READ, priv_anon(), VmaBacking::Anonymous, true).unwrap();
    a.mmap(Some(h2), PAGE, VmaProt::READ, priv_anon(), VmaBacking::Anonymous, true).unwrap();
    // Range straddles the hole between them.
    assert_eq!(
        a.mprotect(h1, 3 * PAGE, r_w()),
        Err(Error::Inval)
    );
}

#[test]
fn mmap_no_mem_when_user_range_full() {
    let a = AddressSpace::new(0).unwrap();
    // Two abutting VMAs that leave a 1-page tail hole. UserVirtAddr
    // forbids reaching USER_VA_END exactly (`01§1`), so the largest
    // mapping that ends at USER_VA_END - PAGE consumes everything but
    // the final reserved page.
    let h = UserVirtAddr::new(0x1000).unwrap();
    let span = (hal::USER_VA_END - 0x1000 - PAGE as u64) as usize;
    a.mmap(Some(h), span, r_w(), priv_anon(), VmaBacking::Anonymous, true).unwrap();
    // The remaining hole is exactly 1 page; a 2-page request can't fit.
    assert_eq!(
        a.mmap(None, 2 * PAGE, r_w(), priv_anon(), VmaBacking::Anonymous, false),
        Err(Error::NoMem)
    );
}

#[test]
fn concurrent_readers_via_find_vma() {
    let a = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(0x4000_0000).unwrap();
    a.mmap(Some(h), 4 * PAGE, r_w(), priv_anon(), VmaBacking::Anonymous, true).unwrap();
    let mut handles = Vec::new();
    for _ in 0..8 {
        let a = Arc::clone(&a);
        handles.push(thread::spawn(move || {
            for _ in 0..1_000 {
                let v = a.find_vma(h).expect("mapped");
                assert_eq!(v.start, h);
            }
        }));
    }
    for h in handles { h.join().unwrap(); }
}
