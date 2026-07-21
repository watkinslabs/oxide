use super::*;

// ---------------------------------------------------------------------------
// VmaBacking::KernelBytes — ELF-loader bridge per docs/31 + `11§4`.
// ---------------------------------------------------------------------------

static ELF_BLOB: [u8; 8] = [b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h'];

// ---------------------------------------------------------------------------
// AddressSpace::fork — naive VMA-tree clone per docs/11§7 (P2-15a).
// ---------------------------------------------------------------------------

#[test]
fn fork_clones_empty_as() {
    let parent = AddressSpace::new(0).unwrap();
    let child  = parent.fork(0).unwrap();
    assert_eq!(child.vma_count(), 0);
    assert_eq!(child.root_pa(), 0);
    child.audit().unwrap();
}

#[test]
fn fork_inherits_vma_tree() {
    let parent = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(0x4000_0000).unwrap();
    parent.mmap(Some(h), PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, false).unwrap();
    let h2 = UserVirtAddr::new(0x4001_0000).unwrap();
    parent.mmap(Some(h2), PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, false).unwrap();
    assert_eq!(parent.vma_count(), 2);
    let child = parent.fork(0).unwrap();
    assert_eq!(child.vma_count(), 2);
    // Child sees the same VMAs at the same VAs.
    assert!(child.find_vma(h).is_some());
    assert!(child.find_vma(h2).is_some());
    child.audit().unwrap();
}

#[test]
fn fork_inherits_kernel_bytes_slice() {
    let parent = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(0x4000_0000).unwrap();
    let arc: alloc::sync::Arc<[u8]> =
        alloc::sync::Arc::from(ELF_BLOB.to_vec().into_boxed_slice());
    parent.mmap(Some(h), PAGE, VmaProt::READ | VmaProt::EXEC,
        VmaFlags::PRIVATE, VmaBacking::KernelBytes { data: alloc::sync::Arc::clone(&arc), off: 0 },
        false).unwrap();
    let child = parent.fork(0xdead_b000).unwrap();
    assert_eq!(child.root_pa(), 0xdead_b000);
    let v = child.find_vma(h).expect("inherited");
    match v.backing {
        VmaBacking::KernelBytes { data, off } => {
            assert_eq!(&data[..], &ELF_BLOB[..]);
            assert_eq!(off, 0);
        }
        _ => panic!("expected KernelBytes inherited from parent"),
    }
}

#[test]
fn fork_subsequent_changes_dont_alias() {
    // Insert a VMA in parent, fork, insert a different one in
    // parent — child should NOT see the post-fork insert.
    let parent = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(0x4000_0000).unwrap();
    parent.mmap(Some(h), PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, false).unwrap();
    let child = parent.fork(0).unwrap();
    let h2 = UserVirtAddr::new(0x4001_0000).unwrap();
    parent.mmap(Some(h2), PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, false).unwrap();
    assert_eq!(parent.vma_count(), 2);
    assert_eq!(child.vma_count(), 1, "child must have its own tree");
    assert!(child.find_vma(h2).is_none());
}

#[test]
fn kernel_bytes_never_merges() {
    // Two abutting KernelBytes VMAs with sub-slices of the same blob
    // must NOT merge — each PT_LOAD is treated as a distinct
    // segment per `11§4` mergeable rule.
    let a = kbytes(0x1000, 0x2000, &ELF_BLOB[0..4], VmaProt::READ);
    let b = kbytes(0x2000, 0x3000, &ELF_BLOB[4..8], VmaProt::READ);
    assert!(!a.mergeable_with_next(&b));
}

#[test]
fn kernel_bytes_clone_subrange_advances_slice() {
    // Sub-range starting `off_delta` bytes into the parent should
    // see the slice advanced by the same amount (BSS tail past
    // `data.len()` is preserved as an empty slice).
    let parent = kbytes(0x1000, 0x3000, &ELF_BLOB[0..4], VmaProt::READ);
    let sub = parent.clone_subrange(uva(0x1800), uva(0x2000));
    match &sub.backing {
        VmaBacking::KernelBytes { data, off } => {
            // off_delta = 0x800. Same Arc shared, off bumped.
            assert_eq!(data.len(), 4);
            assert_eq!(*off, 0x800);
        }
        _ => panic!("expected KernelBytes"),
    }
    let sub2 = parent.clone_subrange(uva(0x1002), uva(0x2000));
    match &sub2.backing {
        VmaBacking::KernelBytes { data, off } => {
            // Bytes available at the sub-range = data[off..] (clamped).
            let available = &data[(*off).min(data.len())..];
            assert_eq!(available, &ELF_BLOB[2..4]);
        }
        _ => panic!("expected KernelBytes"),
    }
}

// F156: KernelBytes Arc lifetime — child VMAs must remain valid
// even if parent AS drops first. Pre-Arc design dangled `&'static [u8]`
// when parent's `staged_bytes` Vec dropped.
#[test]
fn fork_kernel_bytes_outlives_parent() {
    let parent = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(0x4000_0000).unwrap();
    let bytes: alloc::vec::Vec<u8> = (0..16u8).collect();
    let arc: alloc::sync::Arc<[u8]> =
        alloc::sync::Arc::from(bytes.into_boxed_slice());
    parent.mmap(Some(h), PAGE, VmaProt::READ,
        VmaFlags::PRIVATE,
        VmaBacking::KernelBytes { data: alloc::sync::Arc::clone(&arc), off: 0 },
        false).unwrap();
    let child = parent.fork(0).unwrap();
    // Strong count: parent-VMA + child-VMA + outer arc handle = 3
    assert_eq!(alloc::sync::Arc::strong_count(&arc), 3);
    drop(parent);
    // After parent drop, child VMA + outer handle remain.
    assert_eq!(alloc::sync::Arc::strong_count(&arc), 2);
    // Child's KernelBytes is still readable (no UAF).
    let v = child.find_vma(h).expect("child still has VMA");
    if let VmaBacking::KernelBytes { data, .. } = &v.backing {
        assert_eq!(&data[..16], &(0..16u8).collect::<alloc::vec::Vec<u8>>()[..]);
    } else {
        panic!("expected KernelBytes");
    }
}

// F156: topdown mmap places anon mappings in high-address arena.
#[test]
fn anon_mmap_uses_high_address_topdown() {
    use crate::address_space::MMAP_TOP;
    let a = AddressSpace::new(0).unwrap();
    let r = a.mmap(None, PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, false).unwrap();
    // First mmap should land at the highest aligned slot below MMAP_TOP.
    assert_eq!(r.as_u64(), MMAP_TOP - PAGE as u64);
    let r2 = a.mmap(None, PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, false).unwrap();
    // Second goes immediately below the first.
    assert_eq!(r2.as_u64(), MMAP_TOP - 2 * PAGE as u64);
}

// F156: topdown allocator descends past mid-VA fixed mappings (e.g.
// PT_LOADs at 0x400000) without colliding.
#[test]
fn topdown_skips_low_fixed_mappings() {
    use crate::address_space::MMAP_TOP;
    let a = AddressSpace::new(0).unwrap();
    // Simulate ELF .text at 0x400000.
    let text = UserVirtAddr::new(0x400000).unwrap();
    a.mmap(Some(text), 0x10000, VmaProt::READ | VmaProt::EXEC,
        VmaFlags::PRIVATE, VmaBacking::Anonymous, true).unwrap();
    // Anon mmap with no hint goes to the high arena, NOT just above
    // .text.
    let r = a.mmap(None, PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, false).unwrap();
    assert!(r.as_u64() >= MMAP_TOP - PAGE as u64);
    assert!(r.as_u64() > 0x500000, "should not land near .text");
}

#[test]
fn address_space_new_is_empty() {
    let a = AddressSpace::new(0).unwrap();
    assert_eq!(a.vma_count(), 0);
    a.audit().unwrap();
}

#[test]
fn fork_preserves_vdso_signal_restorer() {
    let parent = AddressSpace::new(0).unwrap();
    parent.set_vdso_rt_sigreturn(0x7fff_f000_0368);
    let child = parent.fork(0).unwrap();
    assert_eq!(child.vdso_rt_sigreturn(), 0x7fff_f000_0368);
}

#[test]
fn mmap_no_hint_uses_topdown() {
    use crate::address_space::MMAP_TOP;
    let a = AddressSpace::new(0).unwrap();
    let va = a.mmap(None, PAGE, r_w(), priv_anon(), VmaBacking::Anonymous, false).unwrap();
    assert_eq!(va.as_u64(), MMAP_TOP - PAGE as u64);
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
fn mprotect_rejects_access_beyond_may_prot() {
    let a = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(0x4000_0000).unwrap();
    a.mmap_with_may(Some(h), 2 * PAGE, VmaProt::READ, VmaProt::READ,
        priv_anon(), VmaBacking::Anonymous, true).unwrap();
    assert_eq!(a.mprotect(h, PAGE, VmaProt::READ | VmaProt::WRITE), Err(Error::Access));
    let v = a.find_vma(h).unwrap();
    assert_eq!(v.prot, VmaProt::READ);
}

#[test]
fn mprotect_split_preserves_may_prot() {
    let a = AddressSpace::new(0).unwrap();
    let h = UserVirtAddr::new(0x4000_0000).unwrap();
    a.mmap_with_may(Some(h), 3 * PAGE, VmaProt::READ, r_w(),
        priv_anon(), VmaBacking::Anonymous, true).unwrap();
    let mid = UserVirtAddr::new(h.as_u64() + PAGE as u64).unwrap();
    a.mprotect(mid, PAGE, r_w()).unwrap();
    let v = a.find_vma(mid).unwrap();
    assert_eq!(v.prot, r_w());
    assert_eq!(v.may_prot, r_w());
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
