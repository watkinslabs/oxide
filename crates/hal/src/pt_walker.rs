// Arch-generic 4-level 4 KiB page-table walker per `20§5` / `21§5`.
//
// Both x86_64 (PML4→PDPT→PD→PT) and aarch64 EL1 with 4 KiB granule
// (L0→L1→L2→L3) use a 4-level table tree with 512 entries per
// table and the same VA-bit shifts (39/30/21/12). Only the entry
// bit semantics + privileged register access differ. The walk
// driver here owns the loop and HHDM-based table access; the
// per-arch `PtWalker` impl supplies the bit semantics.
//
// Used so far for splicing Device-attr MMIO leaves into the live
// tables; future callers (real `MmuOps::map`, page-fault handler
// installs) ride the same driver.

use core::ptr;

/// Entries per 4 KiB page table — fixed for both arches.
pub const ENTRIES_PER_TABLE: usize = 512;

/// VA-bit shift for the L0/PML4 index (4-level walk).
pub const L0_SHIFT: u32 = 39;
/// VA-bit shift for the L1/PDPT index.
pub const L1_SHIFT: u32 = 30;
/// VA-bit shift for the L2/PD index.
pub const L2_SHIFT: u32 = 21;
/// VA-bit shift for the L3/PT index (leaf).
pub const L3_SHIFT: u32 = 12;
/// Mask of one table-index field (9 bits = 512 entries).
pub const TABLE_IDX_MASK: u64 = 0x1ff;

/// Errors `map_device_4k` can return.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum WalkErr {
    /// Frame allocator returned `None` mid-walk.
    AllocFailed,
    /// An intermediate entry is a huge page / block descriptor and
    /// would need to be split. Caller policy decides if that's an
    /// error or a "split first then retry"; this driver doesn't.
    HitHugeOrBlock,
    /// Leaf already present at `va` and points elsewhere.
    AlreadyMapped,
}

/// Per-arch bit semantics for the 4-level walker. Static methods
/// only; impls are zero-sized markers.
///
/// Generic at the call site (per `07§5` no-`dyn` rule): the walker
/// monomorphizes per impl.
///
/// # C: each method is O(1).
pub trait PtWalker {
    /// Mask of the physical-address field in a PTE (12-bit aligned;
    /// excludes flag bits). `0x000f_ffff_ffff_f000` on x86_64,
    /// `0x0000_ffff_ffff_f000` on aarch64.
    const PHYS_MASK: u64;

    /// Read the active page-table base PA for this walker
    /// (`CR3 & PHYS_MASK` on x86; `TTBR1_EL1 & PHYS_MASK` on arm).
    /// # SAFETY: privileged read; legal at CPL=0 / EL1.
    unsafe fn read_pt_base() -> u64;

    /// Local-CPU TLB invalidate of a single 4 KiB page at `va`.
    /// # SAFETY: privileged.
    unsafe fn flush_va(va: u64);

    /// True when `entry`'s "present/valid" bit is set.
    fn is_valid(entry: u64) -> bool;

    /// True when a present `entry` describes a leaf at a
    /// non-bottom level (huge page on x86; block descriptor on
    /// arm). At L3 this is always false because L3 entries are
    /// always page leaves.
    fn is_huge_or_block(entry: u64) -> bool;

    /// Pack a fresh intermediate (table) entry pointing to
    /// `child_pa`. Sets only the table-descriptor bits — child
    /// permissions ride through as the leaf is installed.
    fn pack_table(child_pa: u64) -> u64;

    /// Pack a 4 KiB Device-attr leaf at `pa` (PCD|PWT|NX on x86;
    /// AttrIdx=Device|Inner-Shareable|AF|PXN|UXN on arm).
    fn pack_device_leaf(pa: u64) -> u64;
}

/// Install a Device-attr 4 KiB leaf `va → pa` in the active 4-level
/// page-table tree. Walks via HHDM, allocating intermediate tables
/// from `alloc_pa` as needed; zero-initializes new tables before
/// linking so partial walks behave as "not present".
///
/// `alloc_pa()` returns the physical address of a fresh, page-
/// aligned, kernel-owned 4 KiB frame. Caller (kernel) typically
/// wraps PMM: `|| pmm.alloc(Order(0)).ok().map(|pfn| pfn.0 * 4096)`.
///
/// # SAFETY: caller asserts (a) `va` is canonical and not currently
/// owned by another subsystem, (b) `pa` is a real device MMIO base,
/// (c) `hhdm_offset` covers RAM holding page-table memory, (d)
/// `alloc_pa` returns frames the kernel exclusively owns. Single-
/// CPU, IRQ-off context (no concurrent walkers).
/// # C: O(walk depth) = O(4)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn map_device_4k<W: PtWalker, F: FnMut() -> Option<u64>>(
    va: u64,
    pa: u64,
    hhdm_offset: u64,
    mut alloc_pa: F,
) -> Result<(), WalkErr> {
    // SAFETY: per fn contract — privileged register read, legal in
    // kernel mode; result is the live root-table PA.
    let l0_pa = unsafe { W::read_pt_base() };

    let i_l0 = ((va >> L0_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l1 = ((va >> L1_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l2 = ((va >> L2_SHIFT) & TABLE_IDX_MASK) as usize;
    let i_l3 = ((va >> L3_SHIFT) & TABLE_IDX_MASK) as usize;

    // SAFETY: per fn contract — HHDM covers page-table memory; alloc_pa returns kernel-owned frames; single-CPU + IRQs off prevents concurrent walkers; the leaf write at the bottom runs only after every intermediate is in place.
    unsafe {
        let l1_pa = walk_or_alloc::<W, _>(l0_pa, i_l0, hhdm_offset, &mut alloc_pa)?;
        let l2_pa = walk_or_alloc::<W, _>(l1_pa, i_l1, hhdm_offset, &mut alloc_pa)?;
        let l3_pa = walk_or_alloc::<W, _>(l2_pa, i_l2, hhdm_offset, &mut alloc_pa)?;
        let l3_va = (hhdm_offset.wrapping_add(l3_pa)) as *mut u64;
        let slot = l3_va.add(i_l3);
        let cur = ptr::read_volatile(slot);
        if W::is_valid(cur) && (cur & W::PHYS_MASK) != (pa & W::PHYS_MASK) {
            return Err(WalkErr::AlreadyMapped);
        }
        ptr::write_volatile(slot, W::pack_device_leaf(pa));
        W::flush_va(va);
    }
    Ok(())
}

/// Read entry `[idx]` in the table at PA `parent_pa` (via HHDM).
/// If empty, allocate + zero-init + link a fresh child table and
/// return its PA. If present and a non-bottom-level leaf, error.
///
/// # SAFETY: see `map_device_4k`.
unsafe fn walk_or_alloc<W: PtWalker, F: FnMut() -> Option<u64>>(
    parent_pa: u64,
    idx: usize,
    hhdm_offset: u64,
    alloc_pa: &mut F,
) -> Result<u64, WalkErr> {
    // SAFETY: parent_pa references a 4 KiB-aligned table page; HHDM maps it into kernel VA; single-CPU/IRQs-off per `map_device_4k`'s contract.
    unsafe {
        let parent_va = (hhdm_offset.wrapping_add(parent_pa)) as *mut u64;
        let slot = parent_va.add(idx);
        let entry = ptr::read_volatile(slot);
        if !W::is_valid(entry) {
            let child_pa = alloc_pa().ok_or(WalkErr::AllocFailed)?;
            // Fresh kernel-owned frame; zero every entry through HHDM
            // so a missing leaf below acts as "not present".
            let child_va = (hhdm_offset.wrapping_add(child_pa)) as *mut u64;
            for k in 0..ENTRIES_PER_TABLE {
                ptr::write_volatile(child_va.add(k), 0);
            }
            ptr::write_volatile(slot, W::pack_table(child_pa));
            return Ok(child_pa);
        }
        if W::is_huge_or_block(entry) {
            return Err(WalkErr::HitHugeOrBlock);
        }
        Ok(entry & W::PHYS_MASK)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Tests share the static fake-root tree; `cargo test` runs in
    // parallel by default. Serialize via this mutex.
    static SERIAL: Mutex<()> = Mutex::new(());

    /// Hosted PtWalker stub — verifies the walk-driver loop end-to-
    /// end on a synthetic in-memory tree without privileged regs.
    struct HostWalker;
    static mut FAKE_ROOT: [u64; ENTRIES_PER_TABLE] = [0; ENTRIES_PER_TABLE];
    static mut FAKE_FLUSH_COUNT: u32 = 0;

    /// HHDM offset = 0 for the host test (PA == VA on the in-process heap).
    impl PtWalker for HostWalker {
        const PHYS_MASK: u64 = 0xffff_ffff_ffff_f000;
        unsafe fn read_pt_base() -> u64 {
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
    fn map_device_4k_propagates_alloc_failure() {
        let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let _ = reset();
        let alloc = || -> Option<u64> { None };
        // SAFETY: hosted test; allocator returns None at the first request.
        let r = unsafe { map_device_4k::<HostWalker, _>(0, 0x1000, 0, alloc) };
        assert_eq!(r, Err(WalkErr::AllocFailed));
    }
}

#[cfg(test)]
extern crate alloc;
#[cfg(test)]
extern crate std;
