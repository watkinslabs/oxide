// `hal::MmuOps` impl for aarch64 per `21§5`.
//
// Mirror of `hal_x86_64::mmu_ops`. Stateless trait + arch-state in
// static atomics initialised by the boot path. v1 scope: 4 KiB
// leaves only; huge-leaf walker support is a follow-up.

use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use hal::{kassert, pt_walker, MmuOps, Pa, PageFlags, PageSize, Va};
use hal::pt_walker::PtWalker;
use crate::vmm::PtWalkerArm;

/// Bytes covered by each `PageSize` per `01§1` + `21§5`.
const PAGE_BYTES_4K: u64 = 4 * 1024;
const PAGE_BYTES_2M: u64 = 2 * 1024 * 1024;
const PAGE_BYTES_1G: u64 = 1024 * 1024 * 1024;

static HHDM_OFFSET: AtomicU64 = AtomicU64::new(0);
static FRAME_ALLOC: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Set the kernel HHDM offset for `MmuOps` walks. Idempotent only
/// if invoked with the same value.
/// # SAFETY: caller is the boot path; single-CPU; no concurrent
/// MmuOps users.
/// # C: O(1)
pub unsafe fn set_hhdm_offset(offset: u64) {
    let prev = HHDM_OFFSET.swap(offset, Ordering::Release);
    kassert!(prev == 0 || prev == offset, "MmuOps HHDM offset double-init mismatch");
}

/// Set the frame allocator the walker uses for intermediate tables.
/// # SAFETY: caller is the boot path; `f` lives for the rest of
/// the kernel's lifetime; single-CPU; no concurrent MmuOps users.
/// # C: O(1)
pub unsafe fn set_frame_alloc(f: fn() -> Option<u64>) {
    let p = f as *const () as *mut ();
    let prev = FRAME_ALLOC.swap(p, Ordering::Release);
    kassert!(prev.is_null() || prev == p, "MmuOps frame alloc double-init mismatch");
}

fn alloc_frame() -> Option<u64> {
    let p = FRAME_ALLOC.load(Ordering::Acquire);
    if p.is_null() { return None; }
    // SAFETY: only `set_frame_alloc` writes this slot, and it only
    // accepts `fn() -> Option<u64>` values. The transmute back to
    // the same type is sound.
    let f: fn() -> Option<u64> = unsafe { core::mem::transmute(p) };
    f()
}

/// Captured kernel-half page-table base — TTBR1_EL1 at boot. arm
/// keeps user (TTBR0_EL1) and kernel (TTBR1_EL1) trees separate, so
/// there's no kernel-half copy required for new user roots: a fresh
/// zeroed L0 root suffices. We still record TTBR1 so debug paths
/// can validate it hasn't drifted across an AS-switch.
static MASTER_TTBR1: AtomicU64 = AtomicU64::new(0);

/// Capture the current `TTBR1_EL1` as the kernel-half master.
/// Idempotent only with the same value.
/// # SAFETY: caller is the boot path; runs at EL1 single-CPU; no
/// per-AS TTBR0 has been installed yet.
/// # C: O(1)
pub unsafe fn capture_kernel_master() -> u64 {
    let ttbr1 = crate::regs::read_ttbr1_el1() & !0xfff;
    let prev = MASTER_TTBR1.swap(ttbr1, Ordering::Release);
    kassert!(prev == 0 || prev == ttbr1, "capture_kernel_master double-init mismatch");
    ttbr1
}

/// Read the captured master TTBR1, or 0 if not yet captured.
/// # C: O(1)
pub fn kernel_master() -> u64 {
    MASTER_TTBR1.load(Ordering::Acquire)
}

/// Allocate a fresh user-AS L0 root: PMM frame, zero. arm separates
/// user from kernel via TTBR0/TTBR1 so no kernel-half copy is needed
/// — TTBR1_EL1 (set by Limine, captured by `capture_kernel_master`)
/// remains live during AS-switch via `MmuOps::activate(root_pa)`
/// which writes TTBR0_EL1 only.
///
/// # SAFETY: caller is the boot path or AS constructor; HHDM covers
/// page-table memory; FRAME_ALLOC set; single-CPU pre-init.
/// # C: O(1)
pub unsafe fn new_user_l0() -> Option<u64> {
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    if hhdm == 0 { return None; }
    let pa = alloc_frame()?;
    // SAFETY: pa is a freshly-allocated PMM frame; HHDM mirror is
    // mapped writable in the kernel master tables; no other CPU can
    // observe this frame yet.
    unsafe {
        let dst = (hhdm.wrapping_add(pa)) as *mut u64;
        core::ptr::write_bytes(dst, 0, 512);
    }
    Some(pa)
}

/// Marker type implementing `hal::MmuOps` for aarch64. Methods are
/// stateless; arch state lives in this module's static atomics.
pub struct ArmMmu;

impl MmuOps for ArmMmu {
    /// Install a 4 KiB leaf `va → pa` with `flags` in the active
    /// TTBR1_EL1 tree. v1 only supports `PageSize::P4K`.
    /// # SAFETY: per `MmuOps::map`.
    /// # C: O(walk depth) = O(4)
    /// # Ctx: pre-init or under PT lock.
    unsafe fn map(va: Va, pa: Pa, flags: PageFlags, size: PageSize) {
        let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
        kassert!(hhdm != 0, "MmuOps::map called before set_hhdm_offset");
        let (leaf_level, page_bytes, leaf) = match size {
            PageSize::P4K => (3u8, PAGE_BYTES_4K, PtWalkerArm::pack_4k_leaf(pa.0, flags)),
            PageSize::P2M => (2u8, PAGE_BYTES_2M, PtWalkerArm::pack_block_leaf(pa.0, flags)),
            PageSize::P1G => (1u8, PAGE_BYTES_1G, PtWalkerArm::pack_block_leaf(pa.0, flags)),
        };
        kassert!(va.0 % page_bytes == 0, "MmuOps::map va not aligned to page size");
        kassert!(pa.0 % page_bytes == 0, "MmuOps::map pa not aligned to page size");
        // SAFETY: caller asserts MmuOps::map preconditions; HHDM
        // covers page-table memory; frame allocator returns kernel-
        // owned frames; the leaf packer encodes a leaf bit pattern
        // appropriate to `size`.
        let r = unsafe {
            pt_walker::map_at_level::<PtWalkerArm, _>(va.0, leaf_level, leaf, hhdm, alloc_frame)
        };
        kassert!(r.is_ok(), "MmuOps::map walker failure");
    }

    /// Tear down a 4 KiB leaf at `va`. v1 only supports
    /// `PageSize::P4K`.
    /// # SAFETY: per `MmuOps::unmap`.
    /// # C: O(walk depth) = O(4)
    /// # Ctx: pre-init or under PT-write lock.
    unsafe fn unmap(va: Va, size: PageSize) {
        let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
        kassert!(hhdm != 0, "MmuOps::unmap called before set_hhdm_offset");
        let want_level: u8 = match size {
            PageSize::P4K => 3,
            PageSize::P2M => 2,
            PageSize::P1G => 1,
        };
        // SAFETY: caller asserts the VA is exclusively owned; HHDM
        // covers page-table memory; the walker stops at the first
        // leaf encountered.
        if let Some((_leaf, level)) = unsafe { pt_walker::unmap_at_va::<PtWalkerArm>(va.0, hhdm) } {
            kassert!(level == want_level, "MmuOps::unmap size mismatch with installed leaf");
        }
    }

    /// Translate `va` to (`pa`, flags) by walking the live tables.
    /// Recognises huge / block leaves at L1 / L2 in addition to L3
    /// page leaves; the returned `pa` includes the in-leaf offset.
    /// # C: O(walk depth) = O(4)
    fn translate(va: Va) -> Option<(Pa, PageFlags)> {
        let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
        if hhdm == 0 { return None; }
        // SAFETY: HHDM covers page-table memory; reads only.
        let (pa, leaf, _level) = unsafe { pt_walker::translate_at_va::<PtWalkerArm>(va.0, hhdm)? };
        Some((Pa(pa), unpack_flags(leaf)))
    }

    /// Local-CPU TLB invalidate of a single 4 KiB page.
    /// # SAFETY: privileged TLBI; legal at EL1.
    /// # C: O(1)
    unsafe fn flush_va(va: Va) {
        // SAFETY: caller asserts EL1; TLBI VAE1IS affects matching
        // TLB entries across the inner-shareable domain.
        unsafe { <PtWalkerArm as pt_walker::PtWalker>::flush_va(va.0); }
    }

    /// Flush the entire local TLB via TLBI VMALLE1.
    /// # C: O(1)
    fn flush_all_local() {
        #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
        {
            // SAFETY: `tlbi vmalle1` invalidates all stage-1 EL1
            // entries on this CPU; dsb+isb serialize page-table
            // writes vs. subsequent loads.
            unsafe {
                core::arch::asm!(
                    "tlbi vmalle1",
                    "dsb ish",
                    "isb",
                    options(nostack, preserves_flags),
                );
            }
        }
    }

    /// Install `root_pa` as `TTBR0_EL1` — switches the user-half
    /// page-table tree per `13§8`. `TTBR1_EL1` (kernel half) is
    /// untouched. ASID = 0 for v1; PCID-equivalent landings rest
    /// on the SMP+process-ID work later.
    /// # SAFETY: per trait contract.
    /// # C: O(1) reg write + TLBI VMALLE1
    unsafe fn activate(root_pa: u64) {
        kassert!(root_pa & 0xfff == 0, "MmuOps::activate root_pa not page-aligned");
        #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
        // SAFETY: privileged TTBR0_EL1 write at EL1; the TLBI VMALLE1 invalidates stale user-half translations; dsb+isb serialize. Caller asserts the new tree is consistent (TTBR1 kernel mappings unaffected).
        unsafe {
            core::arch::asm!(
                "msr ttbr0_el1, {pa}",
                "isb",
                "tlbi vmalle1",
                "dsb ish",
                "isb",
                pa = in(reg) root_pa,
                options(nostack, preserves_flags),
            );
        }
        #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
        let _ = root_pa;
    }
}

/// Reverse-translate an arm L3 leaf entry to `PageFlags`. Drops
/// AP/AttrIdx subtleties that don't have a 1:1 neutral counterpart;
/// the goal is round-trip equivalence for the bits PageFlags
/// expresses.
fn unpack_flags(leaf: u64) -> PageFlags {
    let mut n = PageFlags::READ;
    let ap = ((leaf >> 6) & 0b11) as u8;
    let user = (ap & 0b01) != 0;
    let writable = (ap & 0b10) == 0;
    if writable { n |= PageFlags::WRITE; }
    if user     { n |= PageFlags::USER;  }
    let attr1 = (leaf & (1 << 3)) != 0;
    if attr1 { n |= PageFlags::NO_CACHE; }
    let pxn = (leaf & (1 << 53)) != 0;
    let uxn = (leaf & (1 << 54)) != 0;
    // For kernel mappings (USER=0): EXEC ↔ !PXN.
    // For user   mappings (USER=1): EXEC ↔ !UXN.
    // Round-trip through `pack_4k_leaf` preserves the right bit.
    let exec = if user { !uxn } else { !pxn };
    if exec { n |= PageFlags::EXEC; }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpack_flags_roundtrip_kernel_rw_no_exec() {
        use hal::pt_walker::PtWalker;
        let pa = 0xdead_b000_u64;
        let want = PageFlags::READ | PageFlags::WRITE;
        let leaf = PtWalkerArm::pack_4k_leaf(pa, want);
        let got = unpack_flags(leaf);
        assert_eq!(got, want);
    }

    #[test]
    fn unpack_flags_roundtrip_user_rwx() {
        use hal::pt_walker::PtWalker;
        let pa = 0xcafe_b000_u64;
        let want = PageFlags::READ | PageFlags::WRITE | PageFlags::EXEC | PageFlags::USER;
        let leaf = PtWalkerArm::pack_4k_leaf(pa, want);
        let got = unpack_flags(leaf);
        assert_eq!(got, want);
    }
}
