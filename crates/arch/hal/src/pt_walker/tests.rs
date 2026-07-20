use super::*;

    use std::sync::Mutex;

    // Tests share the static fake-root tree; `cargo test` runs in
    // parallel by default. Serialize via this mutex.
    static SERIAL: Mutex<()> = Mutex::new(());
    /// Test encoding bit marking a valid page-table entry.
    const TEST_PTE_VALID: u64 = 1;
    /// Test encoding bit marking a huge/block entry or swap entry.
    const TEST_PTE_BLOCK_OR_SWAP: u64 = 1 << 1;
    /// Shift of the swap kind field in the hosted test PTE encoding.
    const TEST_SWAP_KIND_SHIFT: u8 = 2;
    /// Shift of the swap offset field in the hosted test PTE encoding.
    const TEST_SWAP_OFFSET_SHIFT: u8 = 12;
    /// A software-only non-present bit distinct from the hosted swap shape.
    const TEST_MIGRATION_MARKER: u64 = 1 << 11;
    /// HHDM offset in a hosted synthetic page-table tree.
    const TEST_HHDM_OFFSET: u64 = 0;
    /// Empty scalar stored in zero-initialized test page tables.
    const TEST_EMPTY_PTE: u64 = 0;

    /// Hosted PtWalker stub — verifies the walk-driver loop end-to-
    /// end on a synthetic in-memory tree without privileged regs.
    struct HostWalker;
    static mut FAKE_ROOT: [u64; ENTRIES_PER_TABLE] = [0; ENTRIES_PER_TABLE];
    static mut FAKE_FLUSH_COUNT: u32 = 0;

    /// HHDM offset = 0 for the host test (PA == VA on the in-process heap).
    impl PtWalker for HostWalker {
        const PHYS_MASK: u64 = 0xffff_ffff_ffff_f000;
        unsafe fn read_pt_base(_va: u64) -> u64 {
            // SAFETY: hosted test; FAKE_ROOT is `static mut` test state.
            unsafe { (&raw mut FAKE_ROOT).cast::<u8>() as u64 }
        }
        unsafe fn flush_va(_va: u64) {
            // SAFETY: hosted test; mutate the test-only counter.
            unsafe { FAKE_FLUSH_COUNT += 1; }
        }
        fn is_valid(e: u64) -> bool { (e & 1) != 0 }
        fn is_huge_or_block(e: u64) -> bool { (e & 2) != 0 }
        fn pack_table(child_pa: u64) -> u64 { (child_pa & Self::PHYS_MASK) | 1 }
        fn pack_device_leaf(pa: u64) -> u64 { (pa & Self::PHYS_MASK) | 1 | 4 }
        fn pack_4k_leaf(pa: u64, _flags: crate::PageFlags) -> u64 {
            // Test stub: same shape as pack_device_leaf so the
            // walk loop sees a valid leaf; per-arch impls translate
            // PageFlags to real bits.
            (pa & Self::PHYS_MASK) | 1 | 4
        }
        fn pack_block_leaf(pa: u64, _flags: crate::PageFlags) -> u64 {
            // Test stub: bit 0 = valid, bit 1 = huge-or-block (so
            // `is_huge_or_block` returns true for translate/unmap
            // walks), bit 5 marks "this is a block/huge leaf"
            // distinct from the 4 KiB page leaf (bit 4).
            (pa & Self::PHYS_MASK) | 1 | 2 | 0x20
        }
        fn pack_swap_entry(entry: SwapEntry) -> u64 {
            TEST_PTE_BLOCK_OR_SWAP
                | ((entry.kind() as u64) << TEST_SWAP_KIND_SHIFT)
                | (entry.offset() << TEST_SWAP_OFFSET_SHIFT)
        }
        fn unpack_swap_entry(raw: u64) -> Option<SwapEntry> {
            if raw & TEST_PTE_VALID != TEST_EMPTY_PTE
                || raw & TEST_PTE_BLOCK_OR_SWAP == TEST_EMPTY_PTE
                || raw & TEST_MIGRATION_MARKER != TEST_EMPTY_PTE
            { return None; }
            SwapEntry::new(
                ((raw >> TEST_SWAP_KIND_SHIFT) & SwapEntry::MAX_KIND as u64) as u8,
                raw >> TEST_SWAP_OFFSET_SHIFT,
            )
        }
        fn pack_migration_entry(entry: MigrationEntry) -> u64 {
            TEST_MIGRATION_MARKER | (entry.token() << TEST_SWAP_OFFSET_SHIFT)
        }
        fn unpack_migration_entry(raw: u64) -> Option<MigrationEntry> {
            if raw & TEST_PTE_VALID != TEST_EMPTY_PTE || raw & TEST_MIGRATION_MARKER == TEST_EMPTY_PTE {
                return None;
            }
            MigrationEntry::new(raw >> TEST_SWAP_OFFSET_SHIFT)
        }
    }

    /// 4 KiB-aligned wrapper so `Box::new(AlignedTable(_))` returns
    /// a heap allocation that satisfies `PHYS_MASK & addr == addr`.
    /// The default heap allocator doesn't guarantee 4 KiB alignment;
    /// without this wrapper the walker masks low bits off the pa
    /// stored in parent slots and reads garbage.
    #[repr(align(4096))]
    struct AlignedTable([u64; ENTRIES_PER_TABLE]);

    /// Reset shared test state. Caller holds `SERIAL`.
    fn reset() -> alloc::vec::Vec<alloc::boxed::Box<AlignedTable>> {
        // SAFETY: SERIAL held; no other test thread reads/writes these.
        unsafe { FAKE_ROOT = [0; ENTRIES_PER_TABLE]; FAKE_FLUSH_COUNT = 0; }
        alloc::vec::Vec::new()
    }

    #[test]
    fn map_device_4k_allocates_three_tables_and_installs_leaf() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let pages_cell = core::cell::RefCell::new(reset());
        let mut allocated = 0usize;
        let alloc = || -> Option<u64> {
            allocated += 1;
            let p = alloc::boxed::Box::new(AlignedTable([0u64; ENTRIES_PER_TABLE]));
            let pa = p.0.as_ptr() as u64;
            pages_cell.borrow_mut().push(p);
            Some(pa)
        };
        let va = 0x0000_1234_0005_6000_u64;
        let pa = 0x0000_0000_dead_b000_u64;
        // SAFETY: hosted test; synthetic root + boxed children owned by this scope.
        let r = unsafe { map_device_4k::<HostWalker, _>(va, pa, 0, alloc) };
        assert_eq!(r, Ok(()));
        assert_eq!(allocated, 3, "L1+L2+L3 tables allocated");
        // SAFETY: SERIAL mutex serializes test threads accessing FAKE_FLUSH_COUNT.
        assert_eq!(unsafe { FAKE_FLUSH_COUNT }, 1, "flush_va called exactly once");
    }

    #[test]
    fn map_device_4k_already_mapped_when_leaf_points_elsewhere() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let pages_cell = core::cell::RefCell::new(reset());
        let mut alloc = || -> Option<u64> {
            let p = alloc::boxed::Box::new(AlignedTable([0u64; ENTRIES_PER_TABLE]));
            let pa = p.0.as_ptr() as u64;
            pages_cell.borrow_mut().push(p);
            Some(pa)
        };
        let va = 0x0000_1234_0005_6000_u64;
        // SAFETY: hosted test; install a first leaf.
        let r1 = unsafe { map_device_4k::<HostWalker, _>(va, 0xaaaa_b000, 0, &mut alloc) };
        assert_eq!(r1, Ok(()));
        // SAFETY: hosted test; same VA, different PA → AlreadyMapped.
        let r2 = unsafe { map_device_4k::<HostWalker, _>(va, 0xbbbb_b000, 0, &mut alloc) };
        assert_eq!(r2, Err(WalkErr::AlreadyMapped));
    }

    #[test]
    fn swap_entry_replaces_present_leaf_and_roundtrips() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let pages_cell = core::cell::RefCell::new(reset());
        let mut alloc = || -> Option<u64> {
            let page = alloc::boxed::Box::new(AlignedTable([TEST_EMPTY_PTE; ENTRIES_PER_TABLE]));
            let pa = page.0.as_ptr() as u64;
            pages_cell.borrow_mut().push(page);
            Some(pa)
        };
        const TEST_VA: u64 = 0x0000_0000_1234_5000;
        const TEST_PRESENT_PA: u64 = 0x0000_0000_dead_b000;
        const TEST_RESTORED_PA: u64 = 0x0000_0000_beef_c000;
        const TEST_SWAP_KIND: u8 = 3;
        const TEST_SWAP_OFFSET: u64 = 0x12345;
        const TEST_OTHER_SWAP_OFFSET: u64 = TEST_SWAP_OFFSET + 1;
        const TEST_PAGE_FLAGS: crate::PageFlags = crate::PageFlags::USER;
        // SAFETY: hosted synthetic tree; alloc owns every table page.
        assert_eq!(unsafe { map_device_4k::<HostWalker, _>(TEST_VA, TEST_PRESENT_PA, TEST_HHDM_OFFSET, &mut alloc) }, Ok(()));
        // SAFETY: SERIAL protects the test root; its address is the synthetic root PA.
        let root = (&raw const FAKE_ROOT).cast::<u8>() as u64;
        let swap = SwapEntry::new(TEST_SWAP_KIND, TEST_SWAP_OFFSET).unwrap();
        // SAFETY: test owns this root and no concurrent walker exists.
        let old = unsafe { replace_present_4k_with_swap_at_root::<HostWalker>(root, TEST_VA, swap, TEST_HHDM_OFFSET) };
        assert_eq!(old.map(|raw| raw & HostWalker::PHYS_MASK), Some(TEST_PRESENT_PA));
        // SAFETY: same synthetic root; read-only decode.
        assert_eq!(unsafe { swap_entry_4k_at_root::<HostWalker>(root, TEST_VA, TEST_HHDM_OFFSET) }, Some(swap));
        assert_eq!(unsafe { translate_4k_at_root::<HostWalker>(root, TEST_VA, TEST_HHDM_OFFSET) }, None);
        // A stale zap must not clear a replacement entry; the exact entry does.
        let other = SwapEntry::new(TEST_SWAP_KIND, TEST_OTHER_SWAP_OFFSET).unwrap();
        // SAFETY: test owns this root and serializes all leaf mutation.
        assert!(!unsafe { clear_swap_4k_at_root::<HostWalker>(root, TEST_VA, other, TEST_HHDM_OFFSET) });
        // SAFETY: test owns this root and serializes all leaf mutation.
        assert!(unsafe { clear_swap_4k_at_root::<HostWalker>(root, TEST_VA, swap, TEST_HHDM_OFFSET) });
        assert_eq!(unsafe { swap_entry_4k_at_root::<HostWalker>(root, TEST_VA, TEST_HHDM_OFFSET) }, None);
        // SAFETY: test owns this root and serializes all leaf mutation.
        assert!(unsafe { replace_present_4k_with_swap_at_root::<HostWalker>(root, TEST_VA, swap, TEST_HHDM_OFFSET) }.is_none());
        // Reinstall the original present leaf then swap it for the remainder of this test.
        // SAFETY: test owns this root and serializes all leaf mutation.
        assert_eq!(unsafe { map_device_4k::<HostWalker, _>(TEST_VA, TEST_PRESENT_PA, TEST_HHDM_OFFSET, &mut alloc) }, Ok(()));
        // SAFETY: test owns this root and serializes all leaf mutation.
        assert!(unsafe { replace_present_4k_with_swap_at_root::<HostWalker>(root, TEST_VA, swap, TEST_HHDM_OFFSET) }.is_some());
        let mut swaps = alloc::vec::Vec::new();
        // SAFETY: test owns the synthetic root and serializes every walk.
        unsafe { walk_user_swap_entries_at_root::<HostWalker, _>(root, TEST_HHDM_OFFSET, |entry_va, entry| swaps.push((entry_va, entry))); }
        assert_eq!(swaps.as_slice(), &[(TEST_VA, swap)]);
        // A mismatched entry must not overwrite the slot.
        // SAFETY: test owns this root and no concurrent walker exists.
        assert!(!unsafe {
            replace_swap_4k_with_present_at_root::<HostWalker>(
                root, TEST_VA, other, TEST_RESTORED_PA, TEST_PAGE_FLAGS, TEST_HHDM_OFFSET,
            )
        });
        // SAFETY: test owns this root and no concurrent walker exists.
        assert!(unsafe {
            replace_swap_4k_with_present_at_root::<HostWalker>(
                root, TEST_VA, swap, TEST_RESTORED_PA, TEST_PAGE_FLAGS, TEST_HHDM_OFFSET,
            )
        });
        // SAFETY: same synthetic root; read-only translation.
        assert_eq!(
            unsafe { translate_4k_at_root::<HostWalker>(root, TEST_VA, TEST_HHDM_OFFSET) }
                .map(|(resolved, _)| resolved & HostWalker::PHYS_MASK),
            Some(TEST_RESTORED_PA),
        );
    }

    #[test]
    fn migration_marker_roundtrips_and_never_decodes_as_swap() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let pages_cell = core::cell::RefCell::new(reset());
        let mut alloc = || -> Option<u64> {
            let page = alloc::boxed::Box::new(AlignedTable([TEST_EMPTY_PTE; ENTRIES_PER_TABLE]));
            let pa = page.0.as_ptr() as u64;
            pages_cell.borrow_mut().push(page);
            Some(pa)
        };
        const VA: u64 = 0x0000_0000_2233_4000;
        const OLD_PA: u64 = 0x0000_0000_dead_f000;
        const RESTORED_PA: u64 = 0x0000_0000_beef_d000;
        let marker = MigrationEntry::new(0x77123).unwrap();
        let swap = SwapEntry::new(3, 0x77123).unwrap();
        // SAFETY: hosted synthetic tree; alloc owns every table page.
        assert_eq!(unsafe { map_device_4k::<HostWalker, _>(VA, OLD_PA, TEST_HHDM_OFFSET, &mut alloc) }, Ok(()));
        let root = (&raw const FAKE_ROOT).cast::<u8>() as u64;
        // SAFETY: test owns this root and serializes all leaf mutation.
        assert!(unsafe {
            replace_present_4k_with_migration_if_pa_at_root::<HostWalker>(
                root, VA, OLD_PA, marker, TEST_HHDM_OFFSET,
            )
        });
        // SAFETY: same owned root; marker and swap decoders are read-only.
        assert_eq!(unsafe { migration_entry_4k_at_root::<HostWalker>(root, VA, TEST_HHDM_OFFSET) }, Some(marker));
        // SAFETY: same owned root; a migration marker must not acquire swap semantics.
        assert_eq!(unsafe { swap_entry_4k_at_root::<HostWalker>(root, VA, TEST_HHDM_OFFSET) }, None);
        // SAFETY: same owned root; a stale token cannot restore the PTE.
        assert!(!unsafe {
            replace_migration_4k_with_present_at_root::<HostWalker>(
                root, VA, MigrationEntry::new(marker.token() + 1).unwrap(), RESTORED_PA,
                crate::PageFlags::USER, TEST_HHDM_OFFSET,
            )
        });
        // SAFETY: same owned root; matching marker restores a present PTE.
        assert!(unsafe {
            replace_migration_4k_with_present_at_root::<HostWalker>(
                root, VA, marker, RESTORED_PA, crate::PageFlags::USER, TEST_HHDM_OFFSET,
            )
        });
        // SAFETY: same owned root; read-only translation.
        assert_eq!(
            unsafe { translate_4k_at_root::<HostWalker>(root, VA, TEST_HHDM_OFFSET) }
                .map(|(pa, _)| pa & HostWalker::PHYS_MASK),
            Some(RESTORED_PA),
        );
        // SAFETY: replace the restored mapping and commit the exact marker to swap.
        assert!(unsafe {
            replace_present_4k_with_migration_if_pa_at_root::<HostWalker>(
                root, VA, RESTORED_PA, marker, TEST_HHDM_OFFSET,
            )
        });
        // SAFETY: test owns this root and serializes all leaf mutation.
        assert!(unsafe {
            replace_migration_4k_with_swap_at_root::<HostWalker>(
                root, VA, marker, swap, TEST_HHDM_OFFSET,
            )
        });
        // SAFETY: same owned root; the committed entry has only swap semantics.
        assert_eq!(unsafe { migration_entry_4k_at_root::<HostWalker>(root, VA, TEST_HHDM_OFFSET) }, None);
        assert_eq!(unsafe { swap_entry_4k_at_root::<HostWalker>(root, VA, TEST_HHDM_OFFSET) }, Some(swap));
    }

    #[test]
    fn install_swap_leaf_is_empty_only_and_roundtrips() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let pages_cell = core::cell::RefCell::new(reset());
        let child_root = alloc::boxed::Box::new(AlignedTable([TEST_EMPTY_PTE; ENTRIES_PER_TABLE]));
        let root = child_root.0.as_ptr() as u64;
        let mut alloc = || -> Option<u64> {
            let page = alloc::boxed::Box::new(AlignedTable([TEST_EMPTY_PTE; ENTRIES_PER_TABLE]));
            let pa = page.0.as_ptr() as u64;
            pages_cell.borrow_mut().push(page);
            Some(pa)
        };
        const TEST_CHILD_SWAP_VA: u64 = 0x0000_0000_3141_5000;
        const TEST_CHILD_SWAP_KIND: u8 = 2;
        const TEST_CHILD_SWAP_OFFSET: u64 = 0x31415;
        let entry = SwapEntry::new(TEST_CHILD_SWAP_KIND, TEST_CHILD_SWAP_OFFSET).unwrap();
        // SAFETY: this test owns the child root and every allocated table.
        assert_eq!(unsafe { install_swap_4k_at_root::<HostWalker, _>(root, TEST_CHILD_SWAP_VA, entry, TEST_HHDM_OFFSET, &mut alloc) }, Ok(()));
        // SAFETY: same owned root; the non-present leaf must decode exactly.
        assert_eq!(unsafe { swap_entry_4k_at_root::<HostWalker>(root, TEST_CHILD_SWAP_VA, TEST_HHDM_OFFSET) }, Some(entry));
        // A child construction path must never overwrite an existing leaf.
        // SAFETY: same owned root; no concurrent walker exists.
        assert_eq!(unsafe { install_swap_4k_at_root::<HostWalker, _>(root, TEST_CHILD_SWAP_VA, entry, TEST_HHDM_OFFSET, &mut alloc) }, Err(WalkErr::AlreadyMapped));
    }

    #[test]
    fn checked_swap_replacement_rejects_remapped_leaf() {
        const TEST_VA: u64 = 0x0000_0000_4321_0000;
        const TEST_PRESENT_PA: u64 = 0x0000_0000_dead_c000;
        const TEST_STALE_PA: u64 = 0x0000_0000_dead_d000;
        const TEST_SWAP_KIND: u8 = 3;
        const TEST_SWAP_OFFSET: u64 = 0x12346;
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let pages_cell = core::cell::RefCell::new(reset());
        let mut alloc = || -> Option<u64> {
            let page = alloc::boxed::Box::new(AlignedTable([TEST_EMPTY_PTE; ENTRIES_PER_TABLE]));
            let pa = page.0.as_ptr() as u64;
            pages_cell.borrow_mut().push(page);
            Some(pa)
        };
        // SAFETY: hosted synthetic tree; alloc owns every table page.
        assert_eq!(unsafe { map_device_4k::<HostWalker, _>(TEST_VA, TEST_PRESENT_PA, TEST_HHDM_OFFSET, &mut alloc) }, Ok(()));
        // SAFETY: SERIAL protects the test root; its address is the synthetic root PA.
        let root = (&raw const FAKE_ROOT).cast::<u8>() as u64;
        let entry = SwapEntry::new(TEST_SWAP_KIND, TEST_SWAP_OFFSET).unwrap();
        // SAFETY: test owns this root and no concurrent walker exists.
        assert_eq!(unsafe { replace_present_4k_with_swap_if_pa_at_root::<HostWalker>(root, TEST_VA, TEST_STALE_PA, entry, TEST_HHDM_OFFSET) }, None);
        // SAFETY: test owns this root and no concurrent walker exists.
        assert!(unsafe {
            replace_present_4k_flags_if_pa_at_root::<HostWalker>(
                root, TEST_VA, TEST_PRESENT_PA, crate::PageFlags::USER, TEST_HHDM_OFFSET,
            )
        });
        // SAFETY: same synthetic root; read-only translation.
        assert_eq!(unsafe { translate_4k_at_root::<HostWalker>(root, TEST_VA, TEST_HHDM_OFFSET) }.map(|(pa, _)| pa & HostWalker::PHYS_MASK), Some(TEST_PRESENT_PA));
    }

    #[test]
    fn tree_teardown_visits_nonpresent_swap_and_migration_leaves_once() {
        const TEST_VA: u64 = 0x0000_0000_4321_1000;
        const TEST_MIGRATION_VA: u64 = 0x0000_0000_4321_2000;
        const TEST_PRESENT_PA: u64 = 0x0000_0000_dead_e000;
        const TEST_SWAP_KIND: u8 = 4;
        const TEST_SWAP_OFFSET: u64 = 0x12347;
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let pages_cell = core::cell::RefCell::new(reset());
        let mut alloc = || -> Option<u64> {
            let page = alloc::boxed::Box::new(AlignedTable([TEST_EMPTY_PTE; ENTRIES_PER_TABLE]));
            let pa = page.0.as_ptr() as u64;
            pages_cell.borrow_mut().push(page);
            Some(pa)
        };
        // SAFETY: hosted synthetic tree; alloc retains every child table.
        assert_eq!(unsafe { map_device_4k::<HostWalker, _>(TEST_VA, TEST_PRESENT_PA, TEST_HHDM_OFFSET, &mut alloc) }, Ok(()));
        let root = (&raw const FAKE_ROOT).cast::<u8>() as u64;
        let entry = SwapEntry::new(TEST_SWAP_KIND, TEST_SWAP_OFFSET).unwrap();
        let migration = MigrationEntry::new(0x43212).unwrap();
        // SAFETY: test owns and serializes the synthetic root.
        assert!(unsafe { replace_present_4k_with_swap_at_root::<HostWalker>(root, TEST_VA, entry, TEST_HHDM_OFFSET) }.is_some());
        // SAFETY: same owned root; install a second leaf and make it a marker.
        assert_eq!(unsafe { map_device_4k::<HostWalker, _>(TEST_MIGRATION_VA, TEST_PRESENT_PA + 0x1000, TEST_HHDM_OFFSET, &mut alloc) }, Ok(()));
        assert!(unsafe {
            replace_present_4k_with_migration_if_pa_at_root::<HostWalker>(
                root, TEST_MIGRATION_VA, TEST_PRESENT_PA + 0x1000, migration, TEST_HHDM_OFFSET,
            )
        });
        let mut released = alloc::vec::Vec::new();
        let mut migrations = alloc::vec::Vec::new();
        let mut free_leaf = |_va: u64, _pa: u64| panic!("swap leaf must not reach resident callback");
        let mut free_swap = |va, found| released.push((va, found));
        let mut free_migration = |va, found| migrations.push((va, found));
        let mut free_table = |_pa: u64| {};
        // SAFETY: test owns this quiescent root and callbacks only observe it.
        unsafe {
            free_user_tree_leafmap::<HostWalker, _, _, _, _>(
                root, TEST_HHDM_OFFSET, &mut free_leaf, &mut free_swap, &mut free_migration, &mut free_table,
            );
        }
        assert_eq!(released.as_slice(), &[(TEST_VA, entry)]);
        assert_eq!(migrations.as_slice(), &[(TEST_MIGRATION_VA, migration)]);
    }

    /// F156: when callers want to overwrite an existing leaf with a
    /// new PA (COW split, mremap, MAP_FIXED-over-existing), the
    /// canonical sequence is `unmap_at_va` then `map_at_level`. This
    /// test pins that sequence in place — the fix in
    /// `hal-x86_64::mmu_ops::map` and `hal-aarch64::mmu_ops::map`
    /// routes through it on `WalkErr::AlreadyMapped`.
    #[test]
    fn unmap_then_remap_at_same_va_overwrites_with_new_pa() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let pages_cell = core::cell::RefCell::new(reset());
        let mut alloc = || -> Option<u64> {
            let p = alloc::boxed::Box::new(AlignedTable([0u64; ENTRIES_PER_TABLE]));
            let pa = p.0.as_ptr() as u64;
            pages_cell.borrow_mut().push(p);
            Some(pa)
        };
        let va = 0x0000_1234_0005_6000_u64;
        let pa1: u64 = 0xaaaa_b000;
        let pa2: u64 = 0xbbbb_b000;
        // First install — populates intermediate tables and leaf.
        // SAFETY: hosted test under SERIAL mutex; FAKE_ROOT static is single-threaded for the test duration.
        let r1 = unsafe { map_device_4k::<HostWalker, _>(va, pa1, 0, &mut alloc) };
        assert_eq!(r1, Ok(()));

        // Direct second install with a different PA → AlreadyMapped.
        // SAFETY: hosted test under SERIAL mutex; FAKE_ROOT static is single-threaded for the test duration.
        let r2 = unsafe { map_device_4k::<HostWalker, _>(va, pa2, 0, &mut alloc) };
        assert_eq!(r2, Err(WalkErr::AlreadyMapped));

        // Unmap, then remap — the production fix path. New PA wins.
        // SAFETY: hosted test under SERIAL mutex; FAKE_ROOT static is single-threaded for the test duration.
        unsafe {
            let cleared = unmap_at_va::<HostWalker>(va, 0);
            assert!(cleared.is_some(), "unmap reports the cleared leaf");
        }
        // SAFETY: hosted test under SERIAL mutex; FAKE_ROOT static is single-threaded for the test duration.
        let r3 = unsafe { map_device_4k::<HostWalker, _>(va, pa2, 0, &mut alloc) };
        assert_eq!(r3, Ok(()), "remap after unmap succeeds with new PA");

        // Verify the leaf now points at pa2.
        // SAFETY: hosted test under SERIAL mutex; FAKE_ROOT static is single-threaded for the test duration.
        let resolved = unsafe { translate_4k::<HostWalker>(va, 0) };
        let (rpa, _) = resolved.expect("leaf present");
        assert_eq!(rpa & HostWalker::PHYS_MASK, pa2 & HostWalker::PHYS_MASK);
    }

    #[test]
    fn map_at_level_2m_writes_at_l2_index() {
        // 2 MiB block leaf: walker descends L0 → L1 → L2, then
        // writes the leaf at L2[i_l2]. Two table allocs (L1 + L2);
        // the L3 step is skipped entirely.
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let pages_cell = core::cell::RefCell::new(reset());
        let mut allocated = 0usize;
        let mut alloc = || -> Option<u64> {
            allocated += 1;
            let p = alloc::boxed::Box::new(AlignedTable([0u64; ENTRIES_PER_TABLE]));
            let pa = p.0.as_ptr() as u64;
            pages_cell.borrow_mut().push(p);
            Some(pa)
        };
        let va = 0x0000_1234_0020_0000_u64;             // 2 MiB-aligned
        let pa = 0x0000_0000_dee0_0000_u64;             // 2 MiB-aligned
        let leaf = HostWalker::pack_block_leaf(pa, crate::PageFlags::READ | crate::PageFlags::WRITE);
        // SAFETY: hosted test; synthetic root + boxed children owned by this scope.
        let r = unsafe { map_at_level::<HostWalker, _>(va, 2, leaf, 0, &mut alloc) };
        assert_eq!(r, Ok(()));
        assert_eq!(allocated, 2, "L1 + L2 tables allocated; L3 skipped");
        let i_l0 = ((va >> L0_SHIFT) & TABLE_IDX_MASK) as usize;
        let i_l1 = ((va >> L1_SHIFT) & TABLE_IDX_MASK) as usize;
        let i_l2 = ((va >> L2_SHIFT) & TABLE_IDX_MASK) as usize;
        // SAFETY: SERIAL held; FAKE_ROOT + child boxes single-thread accessible in-test.
        unsafe {
            let l1_pa = FAKE_ROOT[i_l0] & HostWalker::PHYS_MASK;
            let l1 = l1_pa as *const u64;
            let l2_pa = (*l1.add(i_l1)) & HostWalker::PHYS_MASK;
            let l2 = l2_pa as *const u64;
            assert_eq!(*l2.add(i_l2), leaf);
        }
    }

    #[test]
    fn map_at_level_1g_writes_at_l1_index() {
        // 1 GiB block leaf: walker descends L0 → L1, writes leaf at
        // L1[i_l1]. One table alloc.
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let pages_cell = core::cell::RefCell::new(reset());
        let mut allocated = 0usize;
        let mut alloc = || -> Option<u64> {
            allocated += 1;
            let p = alloc::boxed::Box::new(AlignedTable([0u64; ENTRIES_PER_TABLE]));
            let pa = p.0.as_ptr() as u64;
            pages_cell.borrow_mut().push(p);
            Some(pa)
        };
        let va = 0x0000_1234_4000_0000_u64;             // 1 GiB-aligned
        let pa = 0x0000_0000_4000_0000_u64;             // 1 GiB-aligned
        let leaf = HostWalker::pack_block_leaf(pa, crate::PageFlags::READ);
        // SAFETY: hosted test; synthetic root + boxed children owned by this scope.
        let r = unsafe { map_at_level::<HostWalker, _>(va, 1, leaf, 0, &mut alloc) };
        assert_eq!(r, Ok(()));
        assert_eq!(allocated, 1, "L1 table allocated; L2/L3 skipped");
    }

    #[test]
    fn translate_at_va_recognises_2m_block_leaf() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let pages_cell = core::cell::RefCell::new(reset());
        let mut alloc = || -> Option<u64> {
            let p = alloc::boxed::Box::new(AlignedTable([0u64; ENTRIES_PER_TABLE]));
            let pa = p.0.as_ptr() as u64;
            pages_cell.borrow_mut().push(p);
            Some(pa)
        };
        let va = 0x0000_1234_0020_0000_u64;
        let pa = 0x0000_0000_dee0_0000_u64;
        let leaf = HostWalker::pack_block_leaf(pa, crate::PageFlags::READ | crate::PageFlags::WRITE);
        // SAFETY: hosted test; SERIAL mutex serializes the FAKE_ROOT static accessed by HostWalker.
        let r = unsafe { map_at_level::<HostWalker, _>(va, 2, leaf, 0, &mut alloc) };
        assert_eq!(r, Ok(()));

        // Pick an in-block offset whose only set bits are below the
        // 4 KiB page-frame boundary so `resolved & PHYS_MASK` still
        // equals `pa`. Larger offsets within the 2 MiB block also
        // work but mask differently; the tested invariant here is
        // that the walker reconstructs `pa | offset` verbatim.
        let off = 0xa3_u64;
        // SAFETY: hosted test; SERIAL mutex serializes the FAKE_ROOT static accessed by HostWalker.
        let t = unsafe { translate_at_va::<HostWalker>(va | off, 0) };
        let (resolved, raw, level) = t.expect("leaf should be present");
        assert_eq!(level, 2);
        assert_eq!(raw, leaf);
        assert_eq!(resolved, pa | off);
    }

    #[test]
    fn unmap_at_va_clears_2m_block_leaf() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let pages_cell = core::cell::RefCell::new(reset());
        let mut alloc = || -> Option<u64> {
            let p = alloc::boxed::Box::new(AlignedTable([0u64; ENTRIES_PER_TABLE]));
            let pa = p.0.as_ptr() as u64;
            pages_cell.borrow_mut().push(p);
            Some(pa)
        };
        let va = 0x0000_1234_0020_0000_u64;
        let pa = 0x0000_0000_dee0_0000_u64;
        let leaf = HostWalker::pack_block_leaf(pa, crate::PageFlags::READ);
        // SAFETY: hosted test; SERIAL mutex serializes the FAKE_ROOT static accessed by HostWalker.
        let _ = unsafe { map_at_level::<HostWalker, _>(va, 2, leaf, 0, &mut alloc) };

        // SAFETY: hosted test; SERIAL mutex serializes the FAKE_ROOT static accessed by HostWalker.
        let u = unsafe { unmap_at_va::<HostWalker>(va, 0) };
        let (got, level) = u.expect("leaf should have been there");
        assert_eq!(level, 2);
        assert_eq!(got, leaf);
        // After unmap, translate returns None.
        // SAFETY: hosted test; SERIAL mutex serializes the FAKE_ROOT static accessed by HostWalker.
        assert_eq!(unsafe { translate_at_va::<HostWalker>(va, 0) }, None);
    }

    #[test]
    fn map_device_4k_propagates_alloc_failure() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let _ = reset();
        let alloc = || -> Option<u64> { None };
        // SAFETY: hosted test; allocator returns None at the first request.
        let r = unsafe { map_device_4k::<HostWalker, _>(0, 0x1000, 0, alloc) };
        assert_eq!(r, Err(WalkErr::AllocFailed));
    }
