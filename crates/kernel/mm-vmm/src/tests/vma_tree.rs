use super::*;

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
    let prot = VmaProt::READ;
    let shared = fake_backing();
    let mk = |s: u64, e: u64, off: u64| {
        Vma::new(uva(s), uva(e), prot, VmaFlags::PRIVATE,
            VmaBacking::File { backing: alloc::sync::Arc::clone(&shared), off })
    };
    t.insert(mk(0x1000, 0x2000, 0)).unwrap();
    // Contiguous offset → merges.
    t.insert(mk(0x2000, 0x3000, 0x1000)).unwrap();
    assert_eq!(t.len(), 1);

    // Non-contiguous offset → separate VMA.
    t.insert(mk(0x3000, 0x4000, 0xdead)).unwrap();
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
    match &removed[0].backing {
        VmaBacking::File { off, .. } => assert_eq!(*off, 0x1000),
        _ => panic!("expected File backing"),
    }

    // Right-kept fragment offset shifted by full prefix length (0x3000).
    let mut it = t.iter();
    let _left = it.next().unwrap();
    let right = it.next().unwrap();
    match &right.backing {
        VmaBacking::File { off, .. } => assert_eq!(*off, 0x3000),
        _ => panic!("expected File backing"),
    }
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
fn anon_name_splits_exact_range_and_clear_remerges() {
    let mut t = VmaTree::new();
    t.insert(anon(0x1000, 0x4000, VmaProt::READ)).unwrap();
    let name: Arc<str> = Arc::from("mesa-buffer");
    t.set_anon_name_range(uva(0x2000), uva(0x3000), Some(name)).unwrap();
    let v: Vec<_> = t.iter().collect();
    assert_eq!(v.len(), 3);
    assert_eq!(v[1].anon_name.as_deref(), Some("mesa-buffer"));
    assert!(v[0].anon_name.is_none() && v[2].anon_name.is_none());
    t.set_anon_name_range(uva(0x2000), uva(0x3000), None).unwrap();
    assert_eq!(t.len(), 1, "clearing the name restores Linux mergeability");
}

#[test]
fn anon_name_rejects_holes_without_partial_change() {
    let mut t = VmaTree::new();
    t.insert(anon(0x1000, 0x2000, VmaProt::READ)).unwrap();
    t.insert(anon(0x3000, 0x4000, VmaProt::READ)).unwrap();
    assert_eq!(t.set_anon_name_range(uva(0x1000), uva(0x4000), Some(Arc::from("x"))), Err(Error::NoMem));
    assert!(t.iter().all(|v| v.anon_name.is_none()));
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
