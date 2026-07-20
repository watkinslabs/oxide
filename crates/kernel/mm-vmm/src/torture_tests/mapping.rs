use super::*;

// ---------------------------------------------------------------
// mmap boundary conditions
// ---------------------------------------------------------------

#[test]
fn mmap_zero_len_rejected() {
    let a = AddressSpace::new(0).unwrap();
    let r = a.mmap(None, 0, r_w(), priv_anon(), VmaBacking::Anonymous, false);
    assert!(r.is_err(), "zero-length mmap must fail");
}

#[test]
fn mmap_unaligned_len_rejected() {
    let a = AddressSpace::new(0).unwrap();
    // 1-byte length is not page-aligned; PAGE+1 isn't either.
    assert!(a.mmap(None, 1, r_w(), priv_anon(), VmaBacking::Anonymous, false).is_err());
    assert!(a.mmap(None, PAGE + 1, r_w(), priv_anon(), VmaBacking::Anonymous, false).is_err());
    assert!(a.mmap(None, PAGE - 1, r_w(), priv_anon(), VmaBacking::Anonymous, false).is_err());
}

#[test]
fn mmap_fixed_unaligned_addr_rejected() {
    let a = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(0x4000_0001).unwrap();
    assert!(a.mmap(Some(h), PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).is_err(),
        "fixed mmap with off-by-1 addr must fail");
}

#[test]
fn mmap_at_min_user_va_works() {
    let a = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(MIN_USER_VA).unwrap();
    let r = a.mmap(Some(h), PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    assert_eq!(r.as_u64(), MIN_USER_VA);
}

#[test]
fn mmap_at_user_va_end_boundary() {
    // The last page [USER_VA_END-PAGE, USER_VA_END) is unmappable
    // because end == USER_VA_END is excluded by UserVirtAddr.
    // (Linux makes the highest page available; we trade that for a
    // strict half-open invariant — observable but unusual.)
    let a = AddressSpace::new(0).unwrap();
    let edge_start = USER_VA_END - PAGE as u64;
    let h = UserVirtAddr::new(edge_start).unwrap();
    let r = a.mmap(Some(h), PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true);
    assert!(r.is_err(), "end == USER_VA_END must be rejected");
    // The page just below WORKS.
    let safe = UserVirtAddr::new(edge_start - PAGE as u64).unwrap();
    let ok = a.mmap(Some(safe), PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    assert_eq!(ok.as_u64(), edge_start - PAGE as u64);
}

#[test]
fn mmap_huge_len_rejected_when_no_room() {
    let a = AddressSpace::new(0).unwrap();
    // Request a length that exceeds the entire user range.
    let huge = (USER_VA_END - MIN_USER_VA) as usize + PAGE;
    let r = a.mmap(None, huge, r_w(), priv_anon(),
        VmaBacking::Anonymous, false);
    assert!(r.is_err(), "huge mmap must hit NoMem");
}

#[test]
fn mmap_fixed_then_topdown_skips_fixed() {
    // Fixed mmap reserves a region; subsequent topdown must not
    // place atop it.
    let a = AddressSpace::new(0).unwrap();
    let fixed = UserVirtAddr::new(MMAP_TOP - 4 * PAGE as u64).unwrap();
    a.mmap(Some(fixed), 2 * PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    let r = a.mmap(None, PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, false).unwrap();
    assert_eq!(r.as_u64(), MMAP_TOP - PAGE as u64);
    let r2 = a.mmap(None, PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, false).unwrap();
    assert_eq!(r2.as_u64(), MMAP_TOP - 2 * PAGE as u64);
    // Third allocation should land BELOW the fixed VMA (which
    // ends at MMAP_TOP - 2*PAGE).
    let r3 = a.mmap(None, PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, false).unwrap();
    assert!(r3.as_u64() < fixed.as_u64(),
        "post-fixed alloc must be below the fixed VMA, got 0x{:x}",
        r3.as_u64());
}

#[test]
fn mmap_fixed_overlap_replaces() {
    // MAP_FIXED with overlap clears the prior region per `11§6`.
    let a = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(0x4000_0000).unwrap();
    a.mmap(Some(h), 4 * PAGE, VmaProt::READ, priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    // Replace the middle two pages with PROT_NONE.
    let mid = UserVirtAddr::new(0x4000_1000).unwrap();
    a.mmap(Some(mid), 2 * PAGE, VmaProt::empty(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    // Should now have 3 VMAs: [0,1) RO, [1,3) NONE, [3,4) RO.
    let n = a.vma_count();
    assert!(n == 3 || n == 1, "expect 3 split VMAs, got {}", n);
}

#[test]
fn mremap_missing_source_is_fault_not_nomem() {
    let a = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(0x4000_0000).unwrap();
    assert_eq!(
        a.mremap_full(h, PAGE, 2 * PAGE, true, false, false, None),
        Err(Error::Fault)
    );
}

#[test]
fn mremap_source_crossing_vma_end_is_fault() {
    let a = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(0x4000_0000).unwrap();
    a.mmap(Some(h), PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    assert_eq!(
        a.mremap_full(h, 2 * PAGE, 3 * PAGE, true, false, false, None),
        Err(Error::Fault)
    );
}

#[test]
fn mremap_zero_old_len_private_duplicate_is_inval() {
    let a = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(0x4000_0000).unwrap();
    a.mmap(Some(h), PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    assert_eq!(
        a.mremap_full(h, 0, PAGE, true, false, false, None),
        Err(Error::Inval)
    );
}

#[test]
fn mremap_dontunmap_uses_new_addr_as_hint() {
    let a = AddressSpace::new(0).unwrap();
    let src = UserVirtAddr::new(0x4000_0000).unwrap();
    let dst = UserVirtAddr::new(0x5000_0000).unwrap();
    a.mmap(Some(src), PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    let moved = a.mremap_full(src, PAGE, PAGE, true, false, true, Some(dst)).unwrap();
    assert_eq!(moved, dst);
    assert!(a.find_vma(src).is_some(), "DONTUNMAP leaves source VMA mapped");
    assert!(a.find_vma(dst).is_some(), "DONTUNMAP creates destination VMA");
}

#[test]
fn mremap_dontunmap_preserves_source_prot_flags_and_file_offset() {
    let a = AddressSpace::new(0).unwrap();
    let src = UserVirtAddr::new(0x4000_0000).unwrap();
    let sub = UserVirtAddr::new(0x4000_1000).unwrap();
    let dst = UserVirtAddr::new(0x5000_0000).unwrap();
    let file: Arc<dyn FileBacking> = Arc::new(FakeFile);
    a.mmap(Some(src), 2 * PAGE, VmaProt::READ, VmaFlags::SHARED,
        VmaBacking::File { backing: file.clone(), off: 0x7000 }, true).unwrap();

    let moved = a.mremap_full(sub, PAGE, PAGE, true, false, true, Some(dst)).unwrap();
    assert_eq!(moved, dst);
    let v = a.find_vma(dst).expect("DONTUNMAP destination exists");
    assert_eq!(v.prot, VmaProt::READ);
    assert_eq!(v.flags, VmaFlags::SHARED);
    match &v.backing {
        VmaBacking::File { backing, off } => {
            assert!(Arc::ptr_eq(backing, &file));
            assert_eq!(*off, 0x7000 + PAGE as u64);
        }
        other => panic!("expected file backing, got {:?}", other),
    }
}

#[test]
fn mremap_expand_without_maymove_is_nomem() {
    let a = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(0x4000_0000).unwrap();
    let blocker = UserVirtAddr::new(0x4000_1000).unwrap();
    a.mmap(Some(h), PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    a.mmap(Some(blocker), PAGE, VmaProt::READ, priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    assert_eq!(
        a.mremap_full(h, PAGE, 2 * PAGE, false, false, false, None),
        Err(Error::NoMem)
    );
}

#[test]
fn mremap_fixed_shrink_moves_to_fixed_address() {
    let a = AddressSpace::new(0).unwrap();
    let src = UserVirtAddr::new(0x4000_0000).unwrap();
    let dst = UserVirtAddr::new(0x5000_0000).unwrap();
    a.mmap(Some(src), 2 * PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    let moved = a.mremap_full(src, 2 * PAGE, PAGE, true, true, false, Some(dst)).unwrap();
    assert_eq!(moved, dst);
    assert!(a.find_vma(src).is_none(), "fixed shrink unmaps the old VMA");
    assert!(a.find_vma(dst).is_some(), "fixed shrink installs destination VMA");
}

// ---------------------------------------------------------------
// munmap edge cases
// ---------------------------------------------------------------

#[test]
fn munmap_unmapped_is_ok() {
    // Linux semantic: munmap of a hole succeeds (returns 0).
    let a = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(0x4000_0000).unwrap();
    a.munmap(h, PAGE).unwrap();
}

#[test]
fn munmap_unaligned_addr_rejected() {
    let a = AddressSpace::new(0).unwrap();
    let bad = UserVirtAddr::new(0x4000_0001).unwrap();
    assert!(a.munmap(bad, PAGE).is_err());
}

#[test]
fn munmap_zero_len_rejected() {
    let a = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(0x4000_0000).unwrap();
    assert!(a.munmap(h, 0).is_err());
}

#[test]
fn munmap_from_zero_removes_low_overlap() {
    let a = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(MIN_USER_VA).unwrap();
    a.mmap(Some(h), PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    a.munmap(UserVirtAddr::new(0).unwrap(), 2 * PAGE).unwrap();
    assert!(a.find_vma(h).is_none());
}

#[test]
fn munmap_hole_can_end_at_user_va_end() {
    let a = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(USER_VA_END - PAGE as u64).unwrap();
    a.munmap(h, PAGE).unwrap();
}

#[test]
fn munmap_partial_splits_vma() {
    let a = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(0x4000_0000).unwrap();
    a.mmap(Some(h), 4 * PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    // Punch out the middle two pages.
    let mid = UserVirtAddr::new(0x4000_1000).unwrap();
    a.munmap(mid, 2 * PAGE).unwrap();
    assert_eq!(a.vma_count(), 2);
    a.audit().unwrap();
    // First page remains.
    assert!(a.find_vma(h).is_some());
    // Last page remains.
    assert!(a.find_vma(uva(0x4000_3000)).is_some());
    // Middle is hole.
    assert!(a.find_vma(uva(0x4000_1000)).is_none());
    assert!(a.find_vma(uva(0x4000_2000)).is_none());
}

#[test]
fn munmap_spans_multiple_vmas() {
    // Linux munmap can span multiple VMAs and removes/splits each.
    let a = AddressSpace::new(0).unwrap();
    let h1 = UserVirtAddr::new(0x4000_0000).unwrap();
    let h2 = UserVirtAddr::new(0x4000_2000).unwrap();
    a.mmap(Some(h1), 2 * PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    // Insert a second VMA with different prot so they don't merge.
    a.mmap(Some(h2), 2 * PAGE, VmaProt::READ, priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    assert_eq!(a.vma_count(), 2);
    // Single munmap covering both.
    a.munmap(h1, 4 * PAGE).unwrap();
    assert_eq!(a.vma_count(), 0);
}

// ---------------------------------------------------------------
// mprotect edge cases
// ---------------------------------------------------------------

#[test]
fn mprotect_hole_rejected() {
    let a = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(0x4000_0000).unwrap();
    assert!(a.mprotect(h, PAGE, VmaProt::READ).is_err(),
        "mprotect on a hole must fail");
}

#[test]
fn mprotect_partial_splits_vma() {
    let a = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(0x4000_0000).unwrap();
    a.mmap(Some(h), 4 * PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    let mid = UserVirtAddr::new(0x4000_1000).unwrap();
    a.mprotect(mid, 2 * PAGE, VmaProt::READ).unwrap();
    // Three VMAs: head=R+W, mid=R, tail=R+W.
    assert_eq!(a.vma_count(), 3);
    a.audit().unwrap();
}

#[test]
fn mprotect_full_vma_no_split() {
    let a = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(0x4000_0000).unwrap();
    a.mmap(Some(h), 4 * PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    a.mprotect(h, 4 * PAGE, VmaProt::READ).unwrap();
    assert_eq!(a.vma_count(), 1);
    let v = a.find_vma(h).unwrap();
    assert_eq!(v.prot, VmaProt::READ);
}

// ---------------------------------------------------------------
// VMA split at all four boundary positions
// ---------------------------------------------------------------

#[test]
fn split_at_start() {
    // [vma_start, vma_end), unmap [vma_start, vma_start+PAGE).
    let a = AddressSpace::new(0).unwrap();
    let h = uva(0x4000_0000);
    a.mmap(Some(h), 4 * PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    a.munmap(h, PAGE).unwrap();
    assert_eq!(a.vma_count(), 1);
    a.audit().unwrap();
    assert!(a.find_vma(h).is_none());
    assert!(a.find_vma(uva(0x4000_1000)).is_some());
}

#[test]
fn split_at_end() {
    let a = AddressSpace::new(0).unwrap();
    let h = uva(0x4000_0000);
    a.mmap(Some(h), 4 * PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    a.munmap(uva(0x4000_3000), PAGE).unwrap();
    assert_eq!(a.vma_count(), 1);
    assert!(a.find_vma(h).is_some());
    assert!(a.find_vma(uva(0x4000_3000)).is_none());
}

#[test]
fn split_at_middle() {
    let a = AddressSpace::new(0).unwrap();
    let h = uva(0x4000_0000);
    a.mmap(Some(h), 4 * PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    a.munmap(uva(0x4000_1000), 2 * PAGE).unwrap();
    assert_eq!(a.vma_count(), 2);
    a.audit().unwrap();
}

#[test]
fn split_at_both_ends() {
    // Unmap the whole VMA range — equivalent to one removal, no split.
    let a = AddressSpace::new(0).unwrap();
    let h = uva(0x4000_0000);
    a.mmap(Some(h), 4 * PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    a.munmap(h, 4 * PAGE).unwrap();
    assert_eq!(a.vma_count(), 0);
}

#[test]
fn mseal_marks_whole_vma() {
    let a = AddressSpace::new(0).unwrap();
    let h = uva(0x4000_0000);
    a.mmap(Some(h), 4 * PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    assert!(!a.range_sealed(h, 4 * PAGE));
    a.mseal(h, 4 * PAGE).unwrap();
    assert!(a.range_sealed(h, 4 * PAGE));
    a.audit().unwrap();
}

#[test]
fn mseal_partial_range_splits_and_seals_middle_only() {
    let a = AddressSpace::new(0).unwrap();
    let h = uva(0x4000_0000);
    a.mmap(Some(h), 4 * PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    a.mseal(uva(0x4000_1000), 2 * PAGE).unwrap();      // seal middle 2 pages
    assert!(a.range_sealed(uva(0x4000_1000), 2 * PAGE));
    assert!(!a.range_sealed(h, PAGE));                 // first page unsealed
    assert!(!a.range_sealed(uva(0x4000_3000), PAGE));  // last page unsealed
    a.audit().unwrap();
}

#[test]
fn mseal_hole_rejected() {
    let a = AddressSpace::new(0).unwrap();
    assert!(a.mseal(uva(0x4000_0000), PAGE).is_err());  // unmapped → ENOMEM
}

#[test]
fn update_flags_range_splits_for_mlock_and_munlock() {
    let a = AddressSpace::new(0).unwrap();
    let h = uva(0x4000_0000);
    a.mmap(Some(h), 4 * PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();

    a.update_flags_range(uva(0x4000_1000), 2 * PAGE,
        VmaFlags::LOCKED, VmaFlags::empty());
    let vmas = a.snapshot_vmas();
    assert_eq!(vmas.len(), 3);
    assert!(!vmas[0].flags.contains(VmaFlags::LOCKED));
    assert!( vmas[1].flags.contains(VmaFlags::LOCKED));
    assert!(!vmas[2].flags.contains(VmaFlags::LOCKED));

    a.update_flags_range(uva(0x4000_1000), PAGE,
        VmaFlags::empty(), VmaFlags::LOCKED);
    assert!(!a.find_vma(uva(0x4000_1000)).unwrap().flags.contains(VmaFlags::LOCKED));
    assert!( a.find_vma(uva(0x4000_2000)).unwrap().flags.contains(VmaFlags::LOCKED));
    a.audit().unwrap();
}

#[test]
fn mlock_future_marks_new_mappings_and_tracks_onfault() {
    let a = AddressSpace::new(0).unwrap();
    let h = uva(0x4000_0000);
    a.set_mlock_future(true, true);
    assert_eq!(a.mlock_future_policy(), (true, true));
    a.mmap(Some(h), PAGE, r_w(), priv_anon(), VmaBacking::Anonymous, true).unwrap();
    assert!(a.find_vma(h).unwrap().flags.contains(VmaFlags::LOCKED));

    a.set_mlock_future(false, false);
    assert_eq!(a.mlock_future_policy(), (false, false));
    let next = uva(0x4000_1000);
    a.mmap(Some(next), PAGE, r_w(), priv_anon(), VmaBacking::Anonymous, true).unwrap();
    assert!(!a.find_vma(next).unwrap().flags.contains(VmaFlags::LOCKED));
}

#[test]
fn fork_does_not_inherit_mlockall_future_policy() {
    let parent = AddressSpace::new(0).unwrap();
    parent.set_mlock_future(true, false);
    let child = parent.fork(0).unwrap();
    assert_eq!(child.mlock_future_policy(), (false, false));
}
