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
use hal::pt_walker::PtWalker;
use crate::vmm::PtWalkerX86;

/// Bytes covered by each `PageSize` per `01§1` + `20§5`.
const PAGE_BYTES_4K: u64 = 4 * 1024;
const PAGE_BYTES_2M: u64 = 2 * 1024 * 1024;
const PAGE_BYTES_1G: u64 = 1024 * 1024 * 1024;
const PAGE_MASK: u64 = hal::PAGE_SIZE_BYTES - 1;

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

/// Read the published HHDM offset. Returns 0 if not yet set.
/// # C: O(1)
pub fn hhdm_offset() -> u64 {
    HHDM_OFFSET.load(Ordering::Acquire)
}

/// Set the frame allocator the walker uses for intermediate tables.
/// `f` returns the PA of a fresh, page-aligned, kernel-owned 4 KiB
/// frame, or `None` on exhaustion. Idempotent only if invoked with
/// the same fn pointer.
/// # SAFETY: caller is the boot path; `f` lives for the rest of
/// the kernel's lifetime; single-CPU; no concurrent MmuOps users.
/// # C: O(1)
pub unsafe fn set_frame_alloc(f: fn() -> Option<u64>) {
    let p = f as *const () as *mut ();
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

/// Kernel master PML4 PA — captured at boot from CR3 before any
/// per-AS root is created. New per-AS PML4s copy entries 256..512
/// (the kernel half) from this master so kernel mappings (HHDM,
/// kernel image, device MMIO) remain reachable after `activate`
/// switches CR3 to the AS-private root. Per `11§2` invariant 5
/// (kernel mapping identical in every AS).
static MASTER_PML4_PA: AtomicU64 = AtomicU64::new(0);

/// Capture the current CR3 as the kernel master PML4 PA. Idempotent
/// only with the same value. Call once at boot, after every kernel
/// mapping the user-AS clones must observe is installed.
///
/// # SAFETY: caller is the boot path; CR3 references the live
/// kernel-only PML4 (Limine's, plus any device-MMIO splices); no
/// per-AS CR3 has been activated yet.
/// # C: O(1)
pub unsafe fn capture_kernel_master() -> u64 {
    // SAFETY: privileged CR3 read at CPL=0; no memory effect.
    let cr3 = crate::regs::read_cr3() & !PAGE_MASK;
    let prev = MASTER_PML4_PA.swap(cr3, Ordering::Release);
    kassert!(prev == 0 || prev == cr3, "capture_kernel_master double-init mismatch");
    cr3
}

/// Re-sync the master PML4's kernel-half entries (256..512) from the CURRENT
/// active CR3. Device-MMIO BARs (virtio etc.) are spliced into the active
/// boot-AS root AFTER `capture_kernel_master` froze the master — so the
/// master, and every AP that boots on it (`smp_x86` loads `kernel_master()`
/// as the AP CR3), was missing those top-level PML4 entries. A virtio access
/// in AP kernel context (e.g. an fbcon GPU-flush softirq on an idle AP) then
/// `#PF`s NP on the unmapped BAR VA. Call once after PCI enumeration, before
/// AP bring-up: the copied entries reference shared L3 tables, so later
/// splices into those sub-trees remain visible through the master too.
///
/// # SAFETY: boot path, single-CPU, pre-AP-bring-up; HHDM covers both PML4
/// frames; `MASTER_PML4_PA` already captured.
/// # C: O(1) (256-entry copy)
pub unsafe fn resync_kernel_master() {
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    let master_pa = MASTER_PML4_PA.load(Ordering::Acquire);
    if hhdm == 0 || master_pa == 0 { return; }
    // SAFETY: privileged CR3 read at CPL=0; pure read.
    let active_pa = unsafe { crate::regs::read_cr3() } & !PAGE_MASK;
    if active_pa == master_pa { return; } // already on the master
    // SAFETY: both PML4 frames are HHDM-mapped; single-CPU pre-AP bring-up;
    // copying only kernel-half entries (256..512), each referencing an L3
    // shared across every AS — so the master gains the post-PCI BAR entry
    // without disturbing the rest.
    unsafe {
        let dst = (hhdm.wrapping_add(master_pa)) as *mut u64;
        let src = (hhdm.wrapping_add(active_pa)) as *const u64;
        for i in 256..512 {
            core::ptr::write_volatile(dst.add(i), core::ptr::read_volatile(src.add(i)));
        }
    }
}

/// Read the captured master PML4 PA, or 0 if `capture_kernel_master`
/// hasn't run.
/// # C: O(1)
pub fn kernel_master() -> u64 {
    MASTER_PML4_PA.load(Ordering::Acquire)
}

/// Allocate a fresh user-AS PML4 root: PMM frame, zero, then copy
/// entries 256..512 from the captured kernel master. Returns the
/// root PA on success, or `None` if `capture_kernel_master` hasn't
/// run, the frame allocator is missing, or the alloc fails.
///
/// The copied PML4 entries point at the same physical L3 (PDPT)
/// tables as the master, so mutations to those sub-trees from any
/// AS are visible in every AS — exactly the kernel-mapping sharing
/// `11§2` invariant 5 demands.
///
/// # SAFETY: caller is the boot path or the AS constructor; HHDM
/// covers page-table memory; FRAME_ALLOC + MASTER_PML4_PA both set;
/// single-CPU pre-init.
/// # C: O(1) (256-entry copy)
pub unsafe fn new_user_pml4() -> Option<u64> {
    let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
    if hhdm == 0 { return None; }
    // F136: clone from the CURRENT active CR3, not the saved
    // MASTER_PML4_PA. Limine's master PT (the one MASTER_PML4_PA
    // captures at boot) is frozen before PCI enum runs — every
    // map_mmio_pages call after `user_as::init` activates the boot
    // AS root writes to the active CR3, leaving Limine's PML4
    // without the device-attr mappings. Cloning from active CR3
    // gives the new AS every kernel-half mapping the calling
    // context already has (including PCI MMIO BARs the device
    // drivers will reach for from syscall context).
    // SAFETY: CR3 read is privileged; legal at CPL=0; pure read.
    let src_pa = unsafe { crate::regs::read_cr3() } & !PAGE_MASK;
    if src_pa == 0 { return None; }
    let pa = alloc_frame()?;
    // SAFETY: pa is a freshly-allocated PMM frame; HHDM mirror at
    // hhdm + pa is mapped writable in the kernel master tables; no
    // other CPU can observe this frame yet.
    unsafe {
        let dst = (hhdm.wrapping_add(pa)) as *mut u64;
        hal::zerotrap::trap((dst) as *const u8, (512) as usize);
        core::ptr::write_bytes(dst, 0, 512);
        let src = (hhdm.wrapping_add(src_pa)) as *const u64;
        // Copy kernel-half PML4 entries 256..512. Each entry is one
        // u64 referencing an L3 (PDPT) table that's shared across
        // every AS for the lifetime of the kernel.
        for i in 256..512 {
            core::ptr::write_volatile(dst.add(i), core::ptr::read_volatile(src.add(i)));
        }
    }
    Some(pa)
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
    unsafe fn map(va: Va, pa: Pa, flags: PageFlags, size: PageSize) -> Option<Pa> {
        let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
        kassert!(hhdm != 0, "MmuOps::map called before set_hhdm_offset");
        let (leaf_level, page_bytes, leaf) = match size {
            PageSize::P4K => (3u8, PAGE_BYTES_4K, PtWalkerX86::pack_4k_leaf(pa.0, flags)),
            PageSize::P2M => (2u8, PAGE_BYTES_2M, PtWalkerX86::pack_block_leaf(pa.0, flags)),
            PageSize::P1G => (1u8, PAGE_BYTES_1G, PtWalkerX86::pack_block_leaf(pa.0, flags)),
        };
        kassert!(va.0 % page_bytes == 0, "MmuOps::map va not aligned to page size");
        kassert!(pa.0 % page_bytes == 0, "MmuOps::map pa not aligned to page size");
        // SAFETY: caller asserts MmuOps::map preconditions; HHDM
        // covers page-table memory; frame allocator returns kernel-
        // owned frames; the leaf packer encodes a leaf bit pattern
        // appropriate to `size`.
        // SAFETY: caller asserts MmuOps::map preconditions.
        let r = unsafe {
            pt_walker::map_at_level::<PtWalkerX86, _>(va.0, leaf_level, leaf, hhdm, alloc_frame)
        };
        let displaced = match r {
            // Slot was empty, or already held the SAME pa (a pure permission
            // rewrite: fork W-strip / shmem RO→RW). No frame displaced.
            Ok(()) => None,
            // F157-A1: a DIFFERENT present frame occupies the slot (COW copy,
            // MAP_FIXED-over-existing, demand-fault over a stale leaf). Tear
            // the old leaf down, capture its PA so the mm layer can `dec_ref`
            // the displaced frame, then install the new one. Previously this
            // arm silently dropped the old PA → refcount > live-PTE count →
            // leak/free-while-mapped aliasing (the RANK-1 boot corruption).
            Err(pt_walker::WalkErr::AlreadyMapped) => {
                // SAFETY: same-VA unmap-then-map sequence; PT lock per the
                // outer caller; no concurrent reader on UP single-CPU.
                let old = unsafe { pt_walker::unmap_at_va::<PtWalkerX86>(va.0, hhdm) };
                // SAFETY: re-install over the now-empty slot; preconditions as above.
                let r2 = unsafe {
                    pt_walker::map_at_level::<PtWalkerX86, _>(
                        va.0, leaf_level, leaf, hhdm, alloc_frame,
                    )
                };
                kassert!(r2.is_ok(), "MmuOps::map remap-after-unmap failed");
                old.map(|(old_leaf, _lvl)| Pa(old_leaf & PtWalkerX86::PHYS_MASK))
            }
            Err(_) => {
                kassert!(false, "MmuOps::map walker failure");
                None
            }
        };
        // Invalidate the local TLB for this VA. `map` mutates the ACTIVE
        // CR3's tables, so any stale entry (a present→present permission
        // change like fork's W-strip, or a cached not-present/negative
        // entry from a prior demand-fault) MUST be flushed or the CPU keeps
        // using the old translation. Linux flushes on every such PTE update
        // (ptep_set_wrprotect + flush_tlb_page). Omitting it let fork's
        // parent-side RO-remap leave a stale WRITABLE entry, so the parent
        // wrote straight into the now-COW-shared frame — write-while-shared
        // corruption invisible to refcount/poison/FWM detectors. `map_at`
        // (non-active child root) deliberately does NOT flush.
        // SAFETY: CPL=0; INVLPG affects only the local TLB for this VA.
        unsafe { <PtWalkerX86 as pt_walker::PtWalker>::flush_va(va.0); }
        displaced
    }

    /// Tear down a 4 KiB leaf at `va`. v1 only supports
    /// `PageSize::P4K`; larger sizes kassert.
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
        if let Some((_leaf, level)) = unsafe { pt_walker::unmap_at_va::<PtWalkerX86>(va.0, hhdm) } {
            kassert!(level == want_level, "MmuOps::unmap size mismatch with installed leaf");
        }
    }

    /// Translate `va` to (`pa`, flags) by walking the live tables.
    /// Recognises huge / block leaves at L1 (1 GiB) and L2 (2 MiB)
    /// in addition to 4 KiB page leaves; the returned `pa` includes
    /// the in-leaf offset so `va`'s low bits appear in the result.
    /// Returns `None` if no leaf is present along the walk.
    /// # C: O(walk depth) = O(4)
    fn translate(va: Va) -> Option<(Pa, PageFlags)> {
        let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
        if hhdm == 0 { return None; }
        // SAFETY: HHDM covers page-table memory; reads only.
        let (pa, leaf, _level) = unsafe { pt_walker::translate_at_va::<PtWalkerX86>(va.0, hhdm)? };
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

    /// Install a 4 KiB / 2 MiB / 1 GiB leaf into the tree rooted at
    /// `root_pa` instead of CR3. Mirror of `map` but for a non-active
    /// PT root (the child PT during `fork`).
    /// # SAFETY: per trait contract.
    /// # C: O(walk depth)
    unsafe fn map_at(root_pa: u64, va: Va, pa: Pa, flags: PageFlags, size: PageSize) -> Option<Pa> {
        let hhdm = HHDM_OFFSET.load(Ordering::Acquire);
        kassert!(hhdm != 0, "MmuOps::map_at called before set_hhdm_offset");
        let (leaf_level, page_bytes, leaf) = match size {
            PageSize::P4K => (3u8, PAGE_BYTES_4K, PtWalkerX86::pack_4k_leaf(pa.0, flags)),
            PageSize::P2M => (2u8, PAGE_BYTES_2M, PtWalkerX86::pack_block_leaf(pa.0, flags)),
            PageSize::P1G => (1u8, PAGE_BYTES_1G, PtWalkerX86::pack_block_leaf(pa.0, flags)),
        };
        kassert!(va.0 % page_bytes == 0, "MmuOps::map_at va misaligned");
        kassert!(pa.0 % page_bytes == 0, "MmuOps::map_at pa misaligned");
        let mut alloc = alloc_frame;
        // SAFETY: caller asserts root_pa valid + caller holds PT lock; HHDM covers PT memory; alloc_frame returns kernel-owned frames.
        let r = unsafe {
            pt_walker::map_at_level_with_root::<PtWalkerX86, _>(
                root_pa, va.0, leaf_level, leaf, hhdm, &mut alloc,
            )
        };
        // Fork populates a FRESH child root, so the leaf slot is always empty
        // (a present leaf here is a build-the-child-over-dirty-root bug → the
        // kassert fires). Hence no frame is ever displaced: return `None`. The
        // `Option<Pa>` return only exists to keep `map_at` symmetric with
        // `map` for callers that account displaced frames generically.
        kassert!(r.is_ok(), "MmuOps::map_at walker failure");
        None
    }

    /// Install `root_pa` as CR3 — switches the active address space
    /// per `13§8`. The 12 low bits of CR3 carry PCD/PWT/PCID; v1 sets
    /// them all to zero (no PCID; cache attributes inherit kernel
    /// defaults). The implicit TLB flush triggered by every CR3 write
    /// (when PCID is off) is the AS-switch's TLB invalidation.
    /// # SAFETY: per trait contract.
    /// # C: O(1) reg write + implicit TLB flush
    unsafe fn activate(root_pa: u64) {
        kassert!(root_pa & (hal::PAGE_SIZE_BYTES - 1) == 0, "MmuOps::activate root_pa not page-aligned");
        #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
        // SAFETY: privileged CR3 write at CPL=0. Caller asserts the new tree's kernel-half is coherent with the master kernel PML4 (else the next instr-fetch faults).
        unsafe {
            core::arch::asm!(
                "mov cr3, {pa}",
                pa = in(reg) root_pa,
                options(nostack, preserves_flags),
            );
        }
        #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
        let _ = root_pa;
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
