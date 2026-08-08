// Installing, replacing and tearing down leaves at each level, and the
// reverse translation that must agree with them.

use super::super::*;
use super::harness::*;

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
