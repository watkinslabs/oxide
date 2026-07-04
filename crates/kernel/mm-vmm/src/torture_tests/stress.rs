use super::*;

// ---------------------------------------------------------------
// Fragmentation + topdown stress
// ---------------------------------------------------------------

#[test]
fn fragmented_topdown_uses_largest_high_gap() {
    // Lay down a checkerboard of fixed VMAs in the high arena;
    // topdown must find the highest fitting hole.
    let a = AddressSpace::new(0).unwrap();
    let base = MMAP_TOP - 16 * PAGE as u64;
    for i in 0..8 {
        // Skip every other slot to leave gaps.
        if i % 2 == 0 { continue; }
        let va = uva(base + (i as u64) * 2 * PAGE as u64);
        a.mmap(Some(va), PAGE, r_w(), priv_anon(),
            VmaBacking::Anonymous, true).unwrap();
    }
    // Topdown asks for 1 page — should fit at MMAP_TOP - PAGE.
    let r = a.mmap(None, PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, false).unwrap();
    assert_eq!(r.as_u64(), MMAP_TOP - PAGE as u64);
}

#[test]
fn topdown_falls_back_to_low_when_high_full() {
    // Fill the high mmap arena with a single giant VMA, force
    // topdown to find space below.
    let a = AddressSpace::new(0).unwrap();
    let high_start = uva(MMAP_TOP - 0x10000);
    a.mmap(Some(high_start), 0x10000, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    // Now any hintless mmap must land BELOW the giant VMA.
    let r = a.mmap(None, PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, false).unwrap();
    assert!(r.as_u64() < MMAP_TOP - 0x10000);
}

#[test]
fn alternating_insert_remove_keeps_invariant() {
    let a = AddressSpace::new(0).unwrap();
    let base = 0x4000_0000u64;
    for i in 0..32 {
        let va = uva(base + i * 0x2000);
        a.mmap(Some(va), PAGE, r_w(), priv_anon(),
            VmaBacking::Anonymous, true).unwrap();
    }
    a.audit().unwrap();
    for i in (0..32).step_by(2) {
        let va = uva(base + i * 0x2000);
        a.munmap(va, PAGE).unwrap();
    }
    a.audit().unwrap();
}

// ---------------------------------------------------------------
// brk window
// ---------------------------------------------------------------

#[test]
fn brk_uninit_returns_zero() {
    let a = AddressSpace::new(0).unwrap();
    assert_eq!(a.brk(), 0);
    // try_set_brk on uninit window is a no-op (returns current=0).
    assert_eq!(a.try_set_brk(0x40000), 0);
}

#[test]
fn brk_set_within_window_succeeds() {
    let a = AddressSpace::new(0).unwrap();
    a.set_brk_window(0x40000, 0x80000);
    assert_eq!(a.brk(), 0x40000);
    assert_eq!(a.try_set_brk(0x60000), 0x60000);
    assert_eq!(a.brk(), 0x60000);
}

#[test]
fn brk_set_above_max_rejected() {
    let a = AddressSpace::new(0).unwrap();
    a.set_brk_window(0x40000, 0x80000);
    // Request past brk_max — should fail (return cur).
    assert_eq!(a.try_set_brk(0x90000), 0x40000);
    assert_eq!(a.brk(), 0x40000);
}

#[test]
fn brk_set_below_initial_rejected() {
    let a = AddressSpace::new(0).unwrap();
    a.set_brk_window(0x40000, 0x80000);
    a.try_set_brk(0x60000);
    // Try shrinking below initial brk start.
    assert_eq!(a.try_set_brk(0x30000), 0x60000);
}

#[test]
fn brk_page_rounds_up() {
    let a = AddressSpace::new(0).unwrap();
    a.set_brk_window(0x40000, 0x80000);
    // Request a non-page-aligned brk; should round up.
    let r = a.try_set_brk(0x40001);
    assert_eq!(r, 0x41000);
}

// ---------------------------------------------------------------
// VMA backing equivalence + merge gates
// ---------------------------------------------------------------

#[test]
fn anon_anon_merge() {
    // Two abutting anonymous VMAs with identical prot/flags merge.
    let a = AddressSpace::new(0).unwrap();
    a.mmap(Some(uva(0x4000_0000)), PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    a.mmap(Some(uva(0x4000_1000)), PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    assert_eq!(a.vma_count(), 1, "abutting anon VMAs must merge");
}

#[test]
fn different_prot_no_merge() {
    let a = AddressSpace::new(0).unwrap();
    a.mmap(Some(uva(0x4000_0000)), PAGE, r_w(), priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    a.mmap(Some(uva(0x4000_1000)), PAGE, VmaProt::READ, priv_anon(),
        VmaBacking::Anonymous, true).unwrap();
    assert_eq!(a.vma_count(), 2);
}

#[test]
fn file_offset_merge_requires_contig() {
    use crate::vma::Vma;
    let mut t = VmaTree::new();
    // a+b share the same backing Arc and have contig offsets ⇒ merge.
    // c is built from the same Arc but a non-contig offset ⇒ stays
    // separate.
    let shared: alloc::sync::Arc<dyn FileBacking> = alloc::sync::Arc::new(FakeFile);
    let a = Vma::new(uva(0x4000_0000), uva(0x4000_1000),
        r_w(), priv_anon(),
        VmaBacking::File { backing: alloc::sync::Arc::clone(&shared), off: 0 });
    let b = Vma::new(uva(0x4000_1000), uva(0x4000_2000),
        r_w(), priv_anon(),
        VmaBacking::File { backing: alloc::sync::Arc::clone(&shared), off: 0x1000 });
    let c = Vma::new(uva(0x4000_2000), uva(0x4000_3000),
        r_w(), priv_anon(),
        VmaBacking::File { backing: shared, off: 0x5000 });
    t.insert(a).unwrap();
    t.insert(b).unwrap();
    t.insert(c).unwrap();
    // After insert+merge, a+b should fold (contig offsets); c stays
    // separate (non-contig). Final count: 2.
    assert_eq!(t.len(), 2);
}

// ---------------------------------------------------------------
// fork chain — Arc lifetime under repeated forks
// ---------------------------------------------------------------

#[test]
fn fork_chain_preserves_kernel_bytes() {
    let bytes: alloc::vec::Vec<u8> = (0..64u8).collect();
    let arc: Arc<[u8]> = Arc::from(bytes.into_boxed_slice());
    let parent = AddressSpace::new(0).unwrap();
    let h = uva(0x4000_0000);
    parent.mmap(Some(h), PAGE, VmaProt::READ, VmaFlags::PRIVATE,
        VmaBacking::KernelBytes { data: Arc::clone(&arc), off: 0 },
        true).unwrap();
    // Fork 8 generations.
    let mut chain: alloc::vec::Vec<Arc<AddressSpace>> = alloc::vec::Vec::new();
    chain.push(parent);
    for _ in 0..8 {
        let n = chain.last().unwrap().fork(0).unwrap();
        chain.push(n);
    }
    // Outer arc + 9 AS = 10 strong refs.
    assert_eq!(Arc::strong_count(&arc), 10);
    // Drop in reverse order: each drop decrements by 1.
    while let Some(_) = chain.pop() { /* drop on fall-out */ }
    assert_eq!(Arc::strong_count(&arc), 1, "only outer handle remains");
}

// ---------------------------------------------------------------
// Stress: 1024 mmap/munmap pairs
// ---------------------------------------------------------------

#[test]
fn churn_1024_iterations_keeps_invariants() {
    let a = AddressSpace::new(0).unwrap();
    let mut allocated: alloc::vec::Vec<UserVirtAddr> = alloc::vec::Vec::new();
    for i in 0..1024 {
        if i % 3 == 2 && !allocated.is_empty() {
            let v = allocated.swap_remove(i % allocated.len());
            a.munmap(v, PAGE).unwrap();
        } else {
            let v = a.mmap(None, PAGE, r_w(), priv_anon(),
                VmaBacking::Anonymous, false).unwrap();
            allocated.push(v);
        }
        if i % 64 == 0 { a.audit().unwrap(); }
    }
    a.audit().unwrap();
}

// ---------------------------------------------------------------
// Allocator exhaustion — request more than fits
// ---------------------------------------------------------------

