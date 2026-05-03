// `hal::MmuOps` impl for x86_64 per `20§5`.
//
// The trait is stateless (no `&self`); arch-specific state lives
// in static atomics initialised by the boot path:
//
//   - HHDM offset (set when the bootloader's HHDM response is read).
//   - Frame allocator (set when PMM init publishes a stable handle).
//
// Both must be initialised before any `MmuOps::map`/`unmap`/`translate`
// call. The setup APIs `set_hhdm_offset` and `set_frame_alloc` panic
// if invoked twice with conflicting values to catch double-init bugs.
//
// v1 scope: 4 KiB leaves only. Huge-page support (`PageSize::P2M` /
// `PageSize::P1G`) lands alongside the kernel-text remap that wants
// 2 MiB+1 GiB block leaves; today's only caller is the device-MMIO
// mapper which is 4 KiB by definition.

use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use hal::{kassert, pt_walker, MmuOps, Pa, PageFlags, PageSize, Va};
use crate::vmm::PtWalkerX86;

/// Kernel HHDM offset (the linear `pa → va` translation Limine
/// publishes via the HHDM response). 0 = uninitialised; the boot
/// path calls `set_hhdm_offset` once with the real value.
static HHDM_OFFSET: AtomicU64 = AtomicU64::new(0);

/// Frame allocator function pointer. Stored as `*mut ()` because
/// `AtomicPtr<fn() -> Option<u64>>` isn't a stable form. The
/// transmute back is sound: we only ever store `fn() -> Option<u64>`
/// values and only read them via the same type.
static FRAME_ALLOC: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Set the kernel HHDM offset for `MmuOps` walks. Idempotent only
/// if invoked with the same value; conflicting values panic via
/// `kassert!` to surface a double-init bug at boot.
/// # SAFETY: caller is the boot path; single-CPU; no concurrent
/// `MmuOps` users.
/// # C: O(1)
pub unsafe fn set_hhdm_offset(offset: u64) {
    let prev = HHDM_OFFSET.swap(offset, Ordering::Release);
    kassert!(prev == 0 || prev == offset, "MmuOps HHDM offset double-init mismatch");
}

/// Set the frame allocator the walker uses for intermediate tables.
/// `f` returns the PA of a fresh, page-aligned, kernel-owned 4 KiB
/// frame, or `None` on exhaustion. Idempotent only if invoked with
/// the same fn pointer.
/// # SAFETY: caller is the boot path; `f` lives for the rest of
/// the kernel's lifetime; single-CPU; no concurrent MmuOps users.
/// # C: O(1)
pub unsafe fn set_frame_alloc(f: fn() -> Option<u64>) {
    let p = f as *mut ();
    let prev = FRAME_ALLOC.swap(p, Ordering::Release);
    kassert!(prev.is_null() || prev == p, "MmuOps frame alloc double-init mismatch");
}

/// Read the configured frame allocator. Returns `None` if not yet
/// set or if the allocator itself returns `None`.
fn alloc_frame() -> Option<u64> {
    let p = FRAME_ALLOC.load(Ordering::Acquire);
    if p.is_null() { return None; }
    // SAFETY: only `set_frame_alloc` writes this slot, and it only
    // accepts `fn() -> Option<u64>` values. The transmute back to
    // the same type is sound.
    let f: fn() -> Option<u64> = unsafe { core::mem::transmute(p) };
    f()
}

/// Marker type implementing `hal::MmuOps` for x86_64. Methods are
/// stateless; arch state lives in this module's static atomics.
pub struct X86Mmu;

impl MmuOps for X86Mmu {
    /// Install a 4 KiB leaf `va → pa` with `flags` in the active
    /// PML4 tree. v1 only supports `PageSize::P4K`; larger sizes
    /// kassert pending huge-leaf walker support.
    /// # SAFETY: per `MmuOps::map` (`14§4` link).
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
            pt_walker::map_4k::<PtWalkerX86, _>(va.0, pa.0, flags, hhdm, alloc_frame)
        };
        kassert!(r.is_ok(), "MmuOps::map walker failure");
    }

    /// Tear down a 4 KiB leaf at `va`. v1 only supports
    /// `PageSize::P4K`; larger sizes kassert.
    /// # SAFETY: per `MmuOps::unmap`.
    /// # C: O(walk depth) = O(4)
    /// # Ctx: pre-init or under PT-write lock.
    unsafe fn unmap(va: Va, size: PageSize) {
        kassert!(matches!(size, PageSize::P4K), "MmuOps::unmap huge-leaf NYI");
        let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
        kassert!(hhdm != 0, "MmuOps::unmap called before set_hhdm_offset");
        // SAFETY: caller asserts the VA is exclusively owned; HHDM
        // covers page-table memory.
        let _ = unsafe { pt_walker::unmap_4k::<PtWalkerX86>(va.0, hhdm) };
    }

    /// Translate `va` to (`pa`, flags) by walking the live tables.
    /// Returns `None` if the leaf is missing or sits at a non-
    /// bottom level.
    /// # C: O(walk depth) = O(4)
    fn translate(va: Va) -> Option<(Pa, PageFlags)> {
        let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
        if hhdm == 0 { return None; }
        // SAFETY: HHDM covers page-table memory; reads only.
        let (pa, leaf) = unsafe { pt_walker::translate_4k::<PtWalkerX86>(va.0, hhdm)? };
        Some((Pa(pa), unpack_flags(leaf)))
    }

    /// Local-CPU TLB invalidate of a single 4 KiB page.
    /// # SAFETY: privileged INVLPG; legal at CPL=0.
    /// # C: O(1)
    unsafe fn flush_va(va: Va) {
        // SAFETY: caller asserts CPL=0; INVLPG affects only the
        // local TLB.
        unsafe { <PtWalkerX86 as pt_walker::PtWalker>::flush_va(va.0); }
    }

    /// Flush the entire local TLB via CR3 reload (non-global).
    /// # C: O(1)
    fn flush_all_local() {
        crate::mmu::flush_local_all();
    }
}

/// Reverse-translate an x86 leaf entry to `PageFlags`. Drops
/// ACCESSED/DIRTY/HUGE which have no neutral counterpart.
fn unpack_flags(leaf: u64) -> PageFlags {
    let mut n = PageFlags::READ;
    if (leaf & (1 << 1)) != 0 { n |= PageFlags::WRITE; }
    if (leaf & (1 << 2)) != 0 { n |= PageFlags::USER; }
    if (leaf & (1 << 3)) != 0 { n |= PageFlags::WRITE_THROUGH; }
    if (leaf & (1 << 4)) != 0 { n |= PageFlags::NO_CACHE; }
    if (leaf & (1 << 8)) != 0 { n |= PageFlags::GLOBAL; }
    if (leaf & (1u64 << 63)) == 0 { n |= PageFlags::EXEC; }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpack_flags_roundtrip_writable_nonexec() {
        // Pack via the walker's `pack_4k_leaf`, unpack here, expect
        // identical bits — confirms the two halves agree on the bit
        // layout.
        use hal::pt_walker::PtWalker;
        let pa = 0xdead_b000_u64;
        let want = PageFlags::READ | PageFlags::WRITE; // EXEC clear → NX set
        let leaf = PtWalkerX86::pack_4k_leaf(pa, want);
        let got = unpack_flags(leaf);
        assert_eq!(got, want);
    }

    #[test]
    fn unpack_flags_roundtrip_exec_user() {
        use hal::pt_walker::PtWalker;
        let pa = 0xcafe_b000_u64;
        let want = PageFlags::READ | PageFlags::WRITE | PageFlags::EXEC | PageFlags::USER;
        let leaf = PtWalkerX86::pack_4k_leaf(pa, want);
        let got = unpack_flags(leaf);
        assert_eq!(got, want);
    }
}
