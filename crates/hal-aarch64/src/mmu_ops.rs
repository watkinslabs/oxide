// `hal::MmuOps` impl for aarch64 per `21§5`.
//
// Mirror of `hal_x86_64::mmu_ops`. Stateless trait + arch-state in
// static atomics initialised by the boot path. v1 scope: 4 KiB
// leaves only; huge-leaf walker support is a follow-up.

use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use hal::{kassert, pt_walker, MmuOps, Pa, PageFlags, PageSize, Va};
use crate::vmm::PtWalkerArm;

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
    let p = f as *mut ();
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
        kassert!(matches!(size, PageSize::P4K), "MmuOps::map huge-leaf NYI");
        let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
        kassert!(hhdm != 0, "MmuOps::map called before set_hhdm_offset");
        // SAFETY: caller asserts MmuOps::map preconditions; HHDM
        // covers page-table memory; frame allocator returns kernel-
        // owned frames.
        let r = unsafe {
            pt_walker::map_4k::<PtWalkerArm, _>(va.0, pa.0, flags, hhdm, alloc_frame)
        };
        kassert!(r.is_ok(), "MmuOps::map walker failure");
    }

    /// Tear down a 4 KiB leaf at `va`. v1 only supports
    /// `PageSize::P4K`.
    /// # SAFETY: per `MmuOps::unmap`.
    /// # C: O(walk depth) = O(4)
    /// # Ctx: pre-init or under PT-write lock.
    unsafe fn unmap(va: Va, size: PageSize) {
        kassert!(matches!(size, PageSize::P4K), "MmuOps::unmap huge-leaf NYI");
        let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
        kassert!(hhdm != 0, "MmuOps::unmap called before set_hhdm_offset");
        // SAFETY: caller asserts the VA is exclusively owned; HHDM
        // covers page-table memory.
        let _ = unsafe { pt_walker::unmap_4k::<PtWalkerArm>(va.0, hhdm) };
    }

    /// Translate `va` to (`pa`, flags) by walking the live tables.
    /// # C: O(walk depth) = O(4)
    fn translate(va: Va) -> Option<(Pa, PageFlags)> {
        let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
        if hhdm == 0 { return None; }
        // SAFETY: HHDM covers page-table memory; reads only.
        let (pa, leaf) = unsafe { pt_walker::translate_4k::<PtWalkerArm>(va.0, hhdm)? };
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
