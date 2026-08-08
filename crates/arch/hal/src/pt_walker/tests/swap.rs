// The non-present leaf encodings: swap slots, pages in transit, and the tree
// teardown that has to visit each exactly once.

use super::super::*;
use super::harness::*;

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
        assert_eq!(unsafe { install_swap_4k_at_root::<HostWalker, _>(root, TEST_CHILD_SWAP_VA, entry, false, TEST_HHDM_OFFSET, &mut alloc) }, Ok(()));
        // SAFETY: same owned root; the non-present leaf must decode exactly.
        assert_eq!(unsafe { swap_entry_4k_at_root::<HostWalker>(root, TEST_CHILD_SWAP_VA, TEST_HHDM_OFFSET) }, Some(entry));
        // A child construction path must never overwrite an existing leaf.
        // SAFETY: same owned root; no concurrent walker exists.
        assert_eq!(unsafe { install_swap_4k_at_root::<HostWalker, _>(root, TEST_CHILD_SWAP_VA, entry, false, TEST_HHDM_OFFSET, &mut alloc) }, Err(WalkErr::AlreadyMapped));
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
