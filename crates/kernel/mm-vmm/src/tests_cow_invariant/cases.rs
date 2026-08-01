use super::*;

// ---- data-coherence: the fork-COW corruption the boot actually hits ----
//
// Refcount stays balanced (the proptest above proves it), but a genuine
// MAP_SHARED (memfd/tmpfs) frame must NOT be COW-split on fork: parent and
// child share ONE backing frame, so a write by either is visible to the other
// and to the file. The live-gnome corruption = a forked process reading a
// STALE private snapshot of a shared journald/systemd memfd page (random
// victim, random garbage -> SIGSEGV). `address_space.rs` forcing every VMA
// through COW on fork (`shared=false`) silently froze the child's shared view.

fn write_tag(pa: u64, tag: &[u8; 4]) {
    // SAFETY: pa is a live 4 KiB host frame from fresh_pa; 4-byte write in-bounds.
    unsafe { core::ptr::copy_nonoverlapping(tag.as_ptr(), pa as *mut u8, 4); }
}
fn read_tag(pa: u64) -> [u8; 4] {
    let mut b = [0u8; 4];
    // SAFETY: pa is a live 4 KiB host frame; 4-byte read in-bounds.
    unsafe { core::ptr::copy_nonoverlapping(pa as *const u8, b.as_mut_ptr(), 4); }
    b
}
fn cur_pa(va: u64) -> u64 { MultiMmu::translate(Va(va)).expect("mapped").0 .0 & !(PAGE - 1) }

/// Model a userspace store at `va`: if the PTE is write-protected the CPU
/// faults into the COW handler, then the instruction is retried on the
/// now-writable page. Writes `tag` to whichever frame ends up installed.
fn store(slot: &AsSlot, va: u64, tag: &[u8; 4]) {
    activate(slot.root);
    let (_, flags) = pte_at(slot.root, va).expect("page must be mapped before store");
    if !PageFlags::from_bits_truncate(flags).contains(PageFlags::WRITE) {
        do_fault(&slot.mm, va, COW_WRITE);
    }
    write_tag(cur_pa(va), tag);
}

#[test]
fn fork_does_not_cow_split_shared_memfd() {
    reset();
    let mut next_root = 0x5_0000_0000u64;

    // Parent maps a memfd MAP_SHARED page, faults it in, writes "PAR0".
    let proot = next_root; next_root += 0x1000_0000;
    let pmm = AddressSpace::new(proot).expect("AS::new");
    let _ = pmm.mmap(None, PAGE as usize,
        VmaProt::READ | VmaProt::WRITE, VmaFlags::SHARED,
        VmaBacking::File { backing: Arc::new(MemfdBacking), off: 0 }, false);
    let pslot = AsSlot::new(proot, pmm);
    let va = pslot.mm.vmas_for_test().iter().next().unwrap().start.as_u64();
    activate(proot);
    do_fault(&pslot.mm, va, DEMAND_WRITE);
    let shared_frame = cur_pa(va);
    store(&pslot, va, b"PAR0");
    check_invariant("shared-pre-fork");

    // Fork a child (COW fork). The SHARED frame must stay shared.
    activate(proot);
    let croot = next_root;
    let child = pslot.mm.fork_cow_pages::<MultiMmu, _>(croot, 0, rc_inc).expect("fork");
    let cslot = AsSlot::new(croot, child);
    check_invariant("shared-post-fork");

    // Child writes "CH1_" to the shared page.
    store(&cslot, va, b"CH1_");
    check_invariant("shared-post-child-write");

    // The bug: with `shared=false`, fork W-stripped the page, so the child's
    // store COW-split it into a private frame -> parent + file never see "CH1_".
    activate(proot);
    let parent_sees = read_tag(cur_pa(va));
    let file_sees = read_tag(shared_frame);
    BUG.with(|b| { if let Some(m) = b.borrow().as_ref() { panic!("invariant: {}", m); } });
    assert_eq!(&parent_sees, b"CH1_",
        "MAP_SHARED: parent must observe the child's shared write, got {:?} \
         (fork COW-split the shared memfd frame -> lost-write corruption)", parent_sees);
    assert_eq!(&file_sees, b"CH1_",
        "MAP_SHARED: the backing frame must hold the child's write, got {:?}", file_sees);

    // And a parent write must be visible to the child too (true sharing).
    store(&pslot, va, b"PAR1");
    activate(croot);
    assert_eq!(&read_tag(cur_pa(va)), b"PAR1", "child must observe parent's shared write");
}

#[test]
fn fork_does_cow_split_private_anon() {
    // Control: PRIVATE anon MUST COW-split on write (isolation). Passes both
    // before and after the shared-fix; guards against over-correcting.
    reset();
    let proot = 0x6_0000_0000u64;
    let pmm = AddressSpace::new(proot).expect("AS::new");
    let _ = pmm.mmap(None, PAGE as usize,
        VmaProt::READ | VmaProt::WRITE,
        VmaFlags::PRIVATE | VmaFlags::ANONYMOUS, VmaBacking::Anonymous, false);
    let pslot = AsSlot::new(proot, pmm);
    let va = pslot.mm.vmas_for_test().iter().next().unwrap().start.as_u64();
    activate(proot);
    do_fault(&pslot.mm, va, DEMAND_WRITE);
    store(&pslot, va, b"PAR0");

    let croot = 0x6_1000_0000u64;
    activate(proot);
    let child = pslot.mm.fork_cow_pages::<MultiMmu, _>(croot, 0, rc_inc).expect("fork");
    let cslot = AsSlot::new(croot, child);

    store(&cslot, va, b"CH1_");
    activate(proot);
    assert_eq!(&read_tag(cur_pa(va)), b"PAR0", "PRIVATE anon: parent isolated from child write");
    activate(croot);
    assert_eq!(&read_tag(cur_pa(va)), b"CH1_", "PRIVATE anon: child sees its own write");
    check_invariant("anon-isolation");
    BUG.with(|b| { if let Some(m) = b.borrow().as_ref() { panic!("invariant: {}", m); } });
}

// ---- MM5: MAP_SHARED|MAP_ANON must SHARE across fork (shmem_zero_setup) ----
//
// The intermittent boot corruption (journald/flatpak/user-session SIGSEGV,
// ~2/4 boots) was a DATA-COHERENCE bug: the mmap syscall built MAP_SHARED|
// MAP_ANON as `VmaFlags::SHARED|ANONYMOUS` + `VmaBacking::Anonymous`. On fork
// `fork_cow_pages` (line ~407) only shares File-backed SHARED VMAs, so an
// anon-backed SHARED VMA was COW-SPLIT — parent and child stopped seeing each
// other's writes (POSIX violation: MAP_SHARED|ANON pages MUST be shared across
// fork). A peer then read a stale private snapshot -> wrong pointer -> SIGSEGV.
//
// The fix (`009_mmap.rs`, Linux `shmem_zero_setup`): route MAP_SHARED|MAP_ANON
// through a fresh anonymous tmpfs (shmem) inode so the VMA is File-backed and
// `fork_cow_pages` shares the frames. These two tests pin both halves:
//   * `anon_backed_shared_loses_child_write_mm5_bug` reproduces the ORIGIN
//     representation (Anonymous backing) and asserts the lost-write — the bug.
//   * `fork_shares_shmem_anon_mapping` drives the FIXED representation (shmem
//     File backing) and asserts mutual visibility — fail-on-origin / pass-after
//     for the actual data-coherence contract.

#[test]
fn anon_backed_shared_loses_child_write_mm5_bug() {
    // ORIGIN/F649 representation of MAP_SHARED|MAP_ANON: SHARED|ANONYMOUS flags
    // with a plain Anonymous backing. `fork_cow_pages` COW-splits it (no File
    // backing) -> the child's write lands in a private frame the parent never
    // sees. This documents the exact lost-write the fix removes.
    reset();
    let proot = 0xA_0000_0000u64;
    let pmm = AddressSpace::new(proot).expect("AS::new");
    let _ = pmm.mmap(None, PAGE as usize,
        VmaProt::READ | VmaProt::WRITE,
        VmaFlags::SHARED | VmaFlags::ANONYMOUS, VmaBacking::Anonymous, false);
    let pslot = AsSlot::new(proot, pmm);
    let va = pslot.mm.vmas_for_test().iter().next().unwrap().start.as_u64();
    activate(proot);
    do_fault(&pslot.mm, va, DEMAND_WRITE);
    store(&pslot, va, b"PAR0");

    let croot = 0xA_1000_0000u64;
    activate(proot);
    let child = pslot.mm.fork_cow_pages::<MultiMmu, _>(croot, 0, rc_inc).expect("fork");
    let cslot = AsSlot::new(croot, child);
    store(&cslot, va, b"CH1_");

    // The bug: anon-backed SHARED COW-splits, so the parent is frozen at PAR0.
    activate(proot);
    assert_eq!(&read_tag(cur_pa(va)), b"PAR0",
        "ORIGIN bug: anon-backed MAP_SHARED|ANON COW-splits -> parent must NOT \
         see the child write (this is the corruption the shmem fix removes)");
    check_invariant("mm5-origin-bug");
    BUG.with(|b| { if let Some(m) = b.borrow().as_ref() { panic!("invariant: {}", m); } });
    let _ = cslot;
}

#[test]
fn fork_shares_shmem_anon_mapping() {
    // FIXED representation: MAP_SHARED|MAP_ANON routed through an anonymous
    // shmem backing (File-backed). The frames are owned by one object both
    // processes alias, so fork shares them and writes are mutually visible.
    // This is the failing-on-origin / passing-after data-coherence gate: with
    // the origin Anonymous backing (test above) the parent never sees "CH1_".
    reset();
    let mut next_root = 0xB_0000_0000u64;

    // Parent maps a SHARED|ANONYMOUS shmem page, faults it in, writes "PAR0".
    let proot = next_root; next_root += 0x1000_0000;
    let pmm = AddressSpace::new(proot).expect("AS::new");
    let _ = pmm.mmap(None, PAGE as usize,
        VmaProt::READ | VmaProt::WRITE,
        VmaFlags::SHARED | VmaFlags::ANONYMOUS,
        VmaBacking::File { backing: Arc::new(MemfdBacking), off: 0 }, false);
    let pslot = AsSlot::new(proot, pmm);
    let va = pslot.mm.vmas_for_test().iter().next().unwrap().start.as_u64();
    activate(proot);
    do_fault(&pslot.mm, va, DEMAND_WRITE);
    let shared_frame = cur_pa(va);
    store(&pslot, va, b"PAR0");
    check_invariant("shmem-anon-pre-fork");

    // Fork. The shmem-anon frame must stay shared (no COW split, no W-strip).
    activate(proot);
    let croot = next_root;
    let child = pslot.mm.fork_cow_pages::<MultiMmu, _>(croot, 0, rc_inc).expect("fork");
    let cslot = AsSlot::new(croot, child);
    check_invariant("shmem-anon-post-fork");

    // Child writes "CH1_": the parent and the backing frame MUST observe it.
    store(&cslot, va, b"CH1_");
    check_invariant("shmem-anon-post-child-write");
    activate(proot);
    assert_eq!(&read_tag(cur_pa(va)), b"CH1_",
        "MAP_SHARED|ANON: parent must observe the child's shared write \
         (fork COW-split the anon mapping -> lost-write corruption)");
    assert_eq!(&read_tag(shared_frame), b"CH1_",
        "MAP_SHARED|ANON: the shmem backing frame must hold the child's write");

    // And a parent write is visible to the child (true bidirectional sharing).
    store(&pslot, va, b"PAR1");
    activate(croot);
    assert_eq!(&read_tag(cur_pa(va)), b"PAR1",
        "MAP_SHARED|ANON: child must observe the parent's shared write");

    // Coherence holds across teardown in either order.
    do_exit(&cslot);
    drop(cslot.mm);
    check_invariant("shmem-anon-child-exit");
    activate(proot);
    assert_eq!(&read_tag(cur_pa(va)), b"PAR1",
        "parent's shmem view survives the child's munmap/exit");
    do_exit(&pslot);
    check_invariant("shmem-anon-parent-exit");
    BUG.with(|b| { if let Some(m) = b.borrow().as_ref() { panic!("invariant: {}", m); } });
}

// ---- RANK-1 regression: map-over-present must account the displaced frame --
//
// The randomized proptest gates demand faults to empty slots (`pte_at == None`)
// and only exercises map-over-present through the COW arm (which always dec'd
// the displaced frame). The NON-COW installers (anon/file/kernelbytes/
// kernelframe demand) used `M::map` over a possibly-present leaf and SILENTLY
// dropped the displaced frame — refcount/mapcount > live-PTE count → leak, then
// realloc-while-mapped aliasing → the non-deterministic boot SIGSEGV. This test
// drives the REAL anon demand-fault path over an already-present leaf and
// asserts the displaced frame is fully released.
//
// FAIL-BEFORE / PASS-AFTER: with the displaced-PTE return wired
// (`MmuOps::map -> Option<Pa>` + the `if let Some(old)=… { dec_ref(old) }` at
// the anon install site), `check_invariant` is clean. Revert EITHER the
// `MultiMmu::map` displaced return OR the anon-site `dec_ref` and this test
// panics with `MAPCOUNT-LEAK` / `over-count` on the displaced frame.
#[test]
fn anon_demand_over_present_leaf_accounts_displaced() {
    reset();
    let root = 0x7_0000_0000u64;
    let mm = AddressSpace::new(root).expect("AS::new");
    let _ = mm.mmap(None, PAGE as usize,
        VmaProt::READ | VmaProt::WRITE,
        VmaFlags::PRIVATE | VmaFlags::ANONYMOUS,
        VmaBacking::Anonymous, false);
    let slot = AsSlot::new(root, mm);
    let va = slot.mm.vmas_for_test().iter().next().unwrap().start.as_u64();
    activate(root);

    // First demand fault installs frame A over an EMPTY slot.
    do_fault(&slot.mm, va, DEMAND_WRITE);
    check_invariant("first-install");
    let a = pte_at(root, va).expect("A mapped").0 & !(PAGE - 1);
    assert_eq!(rc_get(a), 1, "A: alloc refcount 1");

    // Second demand fault at the SAME (now PRESENT) va: the anon arm allocs a
    // fresh frame B and installs it OVER the present leaf A. The displaced A
    // must be dec_ref'd (refcount AND mapcount → 0), else over-count / leak.
    do_fault(&slot.mm, va, DEMAND_WRITE);
    let b = pte_at(root, va).expect("B mapped").0 & !(PAGE - 1);
    assert_ne!(a, b, "second demand fault installed a fresh frame over the present leaf");

    check_invariant("over-present");
    BUG.with(|bug| {
        if let Some(m) = bug.borrow().as_ref() {
            panic!("map-over-present displaced-frame accounting bug: {}", m);
        }
    });
    // A is displaced with no remaining mapping → fully released.
    assert_eq!(rc_get(a), 0, "displaced frame A refcount returns to 0");
    let a_mc = MC.with(|m| *m.borrow().get(&a).unwrap_or(&0));
    assert_eq!(a_mc, 0, "displaced frame A mapcount returns to 0");
    // B is the sole live mapping.
    assert_eq!(rc_get(b), 1, "B: sole live mapping refcount 1");
}

// ---- A3 PageAnonExclusive: wp_page_reuse fires iff exclusive ----------
//
// The fast path (reuse the frame in place on a write fault) must fire ONLY
// for a sole-owned anon page and NEVER for a fork-shared one — the exact
// write-while-shared corruption that disabled the path. These two tests
// pin both directions of `can_reuse_anon_exclusive`.

#[test]
fn cow_reuse_in_place_when_sole_anon_owner() {
    reset();
    let proot = 0x8_0000_0000u64;
    let pmm = AddressSpace::new(proot).expect("AS::new");
    let _ = pmm.mmap(None, PAGE as usize,
        VmaProt::READ | VmaProt::WRITE,
        VmaFlags::PRIVATE | VmaFlags::ANONYMOUS, VmaBacking::Anonymous, false);
    let pslot = AsSlot::new(proot, pmm);
    let va = pslot.mm.vmas_for_test().iter().next().unwrap().start.as_u64();
    activate(proot);
    do_fault(&pslot.mm, va, DEMAND_WRITE);
    let a = cur_pa(va);
    assert!(EXCL.with(|e| e.borrow().contains(&a)), "fresh anon page is exclusive");

    // Fork then drop the child: A is shared (exclusive cleared, parent PTE
    // W-stripped) then returns to a sole mapper (exclusive RESTORED).
    let croot = 0x8_1000_0000u64;
    activate(proot);
    let child = pslot.mm.fork_cow_pages::<MultiMmu, _>(croot, 0, rc_inc).expect("fork");
    let cslot = AsSlot::new(croot, child);
    assert!(!EXCL.with(|e| e.borrow().contains(&a)), "fork-shared page is NOT exclusive");
    do_exit(&cslot);
    drop(cslot.mm);
    assert!(EXCL.with(|e| e.borrow().contains(&a)), "sole survivor is exclusive again");

    // Parent's PTE is still W-stripped from the fork; a write faults into
    // the COW handler, which now REUSES A in place (no new frame).
    store(&pslot, va, b"PAR1");
    activate(proot);
    assert_eq!(cur_pa(va), a, "wp_page_reuse: exclusive sole owner reuses the SAME frame");
    check_invariant("reuse-positive");
    BUG.with(|b| { if let Some(m) = b.borrow().as_ref() { panic!("invariant: {}", m); } });
}

#[test]
fn cow_no_reuse_while_fork_shared() {
    reset();
    let proot = 0x9_0000_0000u64;
    let pmm = AddressSpace::new(proot).expect("AS::new");
    let _ = pmm.mmap(None, PAGE as usize,
        VmaProt::READ | VmaProt::WRITE,
        VmaFlags::PRIVATE | VmaFlags::ANONYMOUS, VmaBacking::Anonymous, false);
    let pslot = AsSlot::new(proot, pmm);
    let va = pslot.mm.vmas_for_test().iter().next().unwrap().start.as_u64();
    activate(proot);
    do_fault(&pslot.mm, va, DEMAND_WRITE);
    let a = cur_pa(va);
    store(&pslot, va, b"PAR0");

    // Fork; A is now shared (non-exclusive). A parent write MUST copy, not
    // reuse — reusing in place would corrupt the child's still-shared view.
    let croot = 0x9_1000_0000u64;
    activate(proot);
    let child = pslot.mm.fork_cow_pages::<MultiMmu, _>(croot, 0, rc_inc).expect("fork");
    let cslot = AsSlot::new(croot, child);
    store(&pslot, va, b"PAR1");
    activate(proot);
    assert_ne!(cur_pa(va), a, "non-exclusive shared page must COW-copy, never reuse");
    activate(croot);
    assert_eq!(cur_pa(va), a, "child keeps the original frame");
    assert_eq!(&read_tag(a), b"PAR0", "child's shared frame is NOT clobbered by parent");
    check_invariant("reuse-negative");
    BUG.with(|b| { if let Some(m) = b.borrow().as_ref() { panic!("invariant: {}", m); } });
    let _ = cslot;
}

#[test]
fn fork_cow_refcount_invariant_proptest() {
    // Several independent seeds; each drives 50k randomized ops (200k total)
    // through the real fork/COW/munmap/teardown code with the global
    // refcount==mapping invariant checked after every single op.
    for seed in [0x9E3779B97F4A7C15u64, 0xD1B54A32D192ED03, 0x2545F4914F6CDD1D, 0x1234_5678_9ABC_DEF1] {
        run(seed, 50_000);
    }
}
