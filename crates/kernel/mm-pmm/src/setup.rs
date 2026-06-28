// PMM bring-up from `BootInfo` per `10§6.3` boot rule.
//
// Walks the bootloader memmap, picks one Usable region big enough to
// host the per-order bitmap pool, carves the bitmap from the front
// of that region, and feeds the remaining Usable regions to
// `Pmm::init`. KernelImage / Reserved / Bootloader* pages are
// filtered upstream by the memmap classification — they never enter
// PMM. Single-shot from `kernel_main`.
//
// `52§3` domain crate. Imports `boot-info` for the memmap shape,
// `pmm` for the allocator + per-PFN PageMeta, `vmm` for the AnonVma
// type bound to PageMeta.mapping by the F156 rmap adapter.



use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};

use hal::{Pfn, PAGE_SHIFT, PAGE_SIZE_BYTES};
use crate::{Error as PmmError, PageBacking, Pmm, UsableRegion, ORDERS};

use boot_info::{BootInfo, BootMemKind, BootMemRegion};

/// Reasons `init_from_boot_info` can refuse PMM bring-up.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SetupError {
    /// `info.memmap_count == 0`.
    NoMemmap,
    /// `info.hhdm_offset == 0`.
    NoHhdm,
    /// No `Usable` region in the memmap.
    NoUsableRegion,
    /// Largest Usable region is smaller than the bitmap pool we need
    /// to carve from it. Practically: tiny VM (<8 MiB).
    NoSpaceForBitmaps,
    /// More usable regions than `MAX_REGIONS`. Bump the bound.
    TooManyRegions,
    /// `Pmm::init` rejected the inputs.
    PmmInit(PmmError),
    /// Already initialized in this boot.
    AlreadyInit,
}

/// Maximum number of Usable regions we propagate into PMM. QEMU
/// virtual machines emit ≤ 8 normally, but the aarch64 EFI path reclaims
/// fragmented EfiBootServices regions (each a separate Usable block), so
/// allow well above that.
pub const MAX_REGIONS: usize = 128;

// ---------------------------------------------------------------------------
// HhdmBacking — `PageBacking` impl for the kernel direct-map.
// ---------------------------------------------------------------------------

/// `PageBacking` over Limine HHDM. `page_ptr(pfn) = hhdm + pfn*4096`.
/// Bitmap slices are pre-sliced into a single carved-out pool during
/// `init_from_boot_info` and remembered here.
pub struct HhdmBacking {
    hhdm: u64,
    bitmaps: [&'static [core::sync::atomic::AtomicU64]; ORDERS],
}

impl PageBacking for HhdmBacking {
    /// # SAFETY: caller asserts `pfn` is within Usable RAM the
    /// bootloader covered with HHDM. PMM only invokes this for
    /// pages on its free-lists or about to be returned from `alloc`.
    /// # C: O(1)
    unsafe fn page_ptr(&self, pfn: Pfn) -> *mut u8 {
        self.hhdm.wrapping_add(pfn.0 * PAGE_SIZE_BYTES) as *mut u8
    }

    /// # C: O(1)
    fn bitmap_storage(
        &self,
        order: u8,
        len_u64: usize,
    ) -> &'static [core::sync::atomic::AtomicU64] {
        let s = self.bitmaps[order as usize];
        debug_assert!(s.len() >= len_u64);
        &s[..len_u64]
    }
}

// ---------------------------------------------------------------------------
// One-shot static storage for the live `Pmm` and the region buffer.
// ---------------------------------------------------------------------------

struct PmmCell(UnsafeCell<MaybeUninit<Pmm<HhdmBacking>>>);
// SAFETY: Initialized exactly once before any other CPU is alive
// (single-shot from `kernel_main`); afterwards `Pmm` is internally
// `Sync` via its own `Spinlock`.
unsafe impl Sync for PmmCell {}

static PMM_STORAGE: PmmCell = PmmCell(UnsafeCell::new(MaybeUninit::uninit()));
static PMM_READY: AtomicBool = AtomicBool::new(false);

// F157: Per-page metadata array backing COW + Linux-style page
// refcount. `init_page_meta` installs a `Box::leak`'d
// `PageMetaArr` covering [0, pfn_max). Pre-init the global is
// null; alloc/free fall back to no-refcount semantics so the boot
// path before `init_page_meta` keeps working. Once installed, every
// alloc bumps refcount to 1 and every dec_and_maybe_free decrements
// + frees on zero — Linux-equivalent struct page lifecycle.
static PAGE_META_PTR: core::sync::atomic::AtomicPtr<crate::PageMetaArr>
    = core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

struct RegionBuf(UnsafeCell<[UsableRegion; MAX_REGIONS]>);
// SAFETY: Written exactly once during single-CPU init; read once
// (passed into `Pmm::init` by reference); never mutated afterwards.
unsafe impl Sync for RegionBuf {}
static REGION_BUF: RegionBuf = RegionBuf(UnsafeCell::new(
    [UsableRegion { start: Pfn(0), len_pfn: 0 }; MAX_REGIONS],
));

/// Bring PMM up from a `BootInfo`. Single-call.
///
/// # SAFETY: caller is `kernel_main` before any other path touches
/// physical memory; `info.memmap_ptr` is a valid slice of length
/// `info.memmap_count` for the duration of this call; `info.hhdm_offset`
/// (when non-zero) is the live HHDM offset under which all Usable
/// physical pages are reachable as kernel VAs.
/// # C: O(memmap.len + bitmap_words)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn init_from_boot_info(
    info: &BootInfo,
) -> Result<&'static Pmm<HhdmBacking>, SetupError> {
    if PMM_READY.load(Ordering::Acquire) {
        return Err(SetupError::AlreadyInit);
    }
    if info.memmap_count == 0 {
        return Err(SetupError::NoMemmap);
    }
    if info.hhdm_offset == 0 {
        return Err(SetupError::NoHhdm);
    }

    // SAFETY: caller-asserted memmap_ptr/memmap_count contract.
    let regions: &[BootMemRegion] = unsafe {
        core::slice::from_raw_parts(info.memmap_ptr, info.memmap_count as usize)
    };

    // Compute pfn_max across all Usable regions.
    let mut pfn_max: u64 = 0;
    for r in regions {
        if r.kind != BootMemKind::Usable { continue; }
        let end_pa = r.base_pa.saturating_add(r.len);
        let end_pfn = end_pa >> PAGE_SHIFT;
        if end_pfn > pfn_max { pfn_max = end_pfn; }
    }
    if pfn_max == 0 {
        return Err(SetupError::NoUsableRegion);
    }

    // Per-order bitmap byte requirements + total. PMM stores one
    // bitmap per order from 0..=MAX_ORDER, sized by ceil(pfn_max/2^o).
    // All math is overflow-safe; saturating semantics are fine
    // because oversized inputs just produce a too-large pool that
    // fails the next find-region step.
    let mut per_order_words: [usize; ORDERS] = [0; ORDERS];
    let mut total_bytes: u64 = 0;
    let mut o = 0usize;
    while o < ORDERS {
        let stride = 1u64 << (o as u32);
        let plus = pfn_max.saturating_add(stride.saturating_sub(1));
        let blocks = plus >> (o as u32);
        let words = blocks.saturating_add(63) >> 6;
        per_order_words[o] = words as usize;
        total_bytes = total_bytes.saturating_add(words.saturating_mul(8));
        o += 1;
    }
    // Round pool size up to a page.
    let pool_pages = total_bytes
        .checked_add(PAGE_SIZE_BYTES - 1)
        .map(|x| x / PAGE_SIZE_BYTES)
        .unwrap_or(u64::MAX / PAGE_SIZE_BYTES);
    let pool_bytes = pool_pages.saturating_mul(PAGE_SIZE_BYTES);

    // Pick the first Usable region with `len >= pool_bytes + slack`.
    let needed = pool_bytes.saturating_add(PAGE_SIZE_BYTES);
    let chosen_idx = regions
        .iter()
        .position(|r| r.kind == BootMemKind::Usable && r.len >= needed)
        .ok_or(SetupError::NoSpaceForBitmaps)?;
    let chosen = regions[chosen_idx];

    // Carve the pool from the front of `chosen`. HHDM gives us a
    // kernel VA covering the whole pool at `hhdm + chosen.base_pa`.
    let pool_va: *mut u8 = info.hhdm_offset.wrapping_add(chosen.base_pa) as *mut u8;
    // SAFETY: pool memory is RAM (chosen.kind == Usable), HHDM-mapped by the bootloader, page-aligned (Limine memmap entries are page-aligned), and not yet touched by any kernel subsystem because we run before kernel_main hands control to anything else.
    unsafe {
        core::ptr::write_bytes(pool_va as *mut u64, 0, (pool_bytes / 8) as usize);
    }

    // Slice the pool into per-order bitmap views.
    let mut bitmaps: [&'static [core::sync::atomic::AtomicU64]; ORDERS] = [&[][..]; ORDERS];
    let mut cursor: *mut u8 = pool_va;
    let mut o = 0usize;
    while o < ORDERS {
        let words = per_order_words[o];
        if words > 0 {
            // SAFETY: cursor stays within `pool_va..pool_va+pool_bytes`
            // by construction (sum of per_order_words ≤ pool_bytes/8).
            // AtomicU64 has the same layout as u64; the slab was
            // zero-initialized just above.
            let slice = unsafe {
                core::slice::from_raw_parts(
                    cursor as *const core::sync::atomic::AtomicU64,
                    words,
                )
            };
            bitmaps[o] = slice;
            // SAFETY: still inside the pool by construction.
            cursor = unsafe { cursor.add(words * 8) };
        }
        o += 1;
    }

    // Build the UsableRegion list, shrinking the chosen region.
    let mut n_regions = 0usize;
    for (i, r) in regions.iter().enumerate() {
        if r.kind != BootMemKind::Usable { continue; }
        if n_regions >= MAX_REGIONS {
            return Err(SetupError::TooManyRegions);
        }
        let (base_pa, len) = if i == chosen_idx {
            (
                r.base_pa.saturating_add(pool_bytes),
                r.len.saturating_sub(pool_bytes),
            )
        } else {
            (r.base_pa, r.len)
        };
        let start_pfn = base_pa
            .checked_add(PAGE_SIZE_BYTES - 1)
            .map(|x| x >> PAGE_SHIFT)
            .unwrap_or(u64::MAX >> PAGE_SHIFT);
        let end_pfn = base_pa
            .checked_add(len)
            .map(|x| x >> PAGE_SHIFT)
            .unwrap_or(u64::MAX >> PAGE_SHIFT);
        if end_pfn <= start_pfn { continue; }
        // SAFETY: REGION_BUF written only here, single-CPU, before
        // PMM_READY flips.
        unsafe {
            (*REGION_BUF.0.get())[n_regions] = UsableRegion {
                start: Pfn(start_pfn),
                len_pfn: end_pfn - start_pfn,
            };
        }
        n_regions += 1;
    }

    let backing = HhdmBacking { hhdm: info.hhdm_offset, bitmaps };
    // SAFETY: same single-CPU init invariant; we read what we just wrote.
    let regs: &[UsableRegion] = unsafe {
        let base: *const UsableRegion = REGION_BUF.0.get() as *const UsableRegion;
        core::slice::from_raw_parts(base, n_regions)
    };
    let pmm = Pmm::<HhdmBacking>::init(backing, regs).map_err(SetupError::PmmInit)?;
    // SAFETY: PMM_STORAGE written only here, single-CPU, before
    // PMM_READY flips.
    let pmm_ref: &'static Pmm<HhdmBacking> = unsafe {
        let cell = &mut *PMM_STORAGE.0.get();
        cell.write(pmm);
        cell.assume_init_ref()
    };
    PMM_READY.store(true, Ordering::Release);
    Ok(pmm_ref)
}

/// Get a `&'static` reference to the PMM after `init_from_boot_info`
/// has run, or `None` if PMM is not yet initialised. Used by bare-fn
/// frame allocators (e.g. the one registered with `MmuOps`) that
/// can't capture state in a closure.
/// # C: O(1)
pub fn pmm_static() -> Option<&'static Pmm<HhdmBacking>> {
    if !PMM_READY.load(Ordering::Acquire) { return None; }
    // SAFETY: PMM_READY went true only after the cell was written;
    // no further writes occur. The reference's lifetime is tied to
    // `PMM_STORAGE` which is `'static`.
    Some(unsafe { (*PMM_STORAGE.0.get()).assume_init_ref() })
}

/// Bare-fn frame allocator wrapping `pmm_static().alloc(Order(0))`.
/// Suitable for `MmuOps::set_frame_alloc`. Returns the PA of a
/// fresh, page-aligned, kernel-owned 4 KiB frame, or `None` on
/// exhaustion / pre-init.
///
/// F157: when the per-page metadata array is installed, the new
/// frame's refcount is set to 1 (Linux `struct page` semantics —
/// freshly allocated page has one mapping pending). Pre-init
/// (during boot before `init_page_meta`), refcount is implicit.
/// # C: O(1) amortised (PMM buddy alloc).
pub fn alloc_one_frame() -> Option<u64> {
    use core::sync::atomic::Ordering;
    let p = pmm_static()?;
    // Linux page-allocator invariant (`mm/page_alloc.c` `check_new_page`):
    // a frame on the free list is unreferenced — its struct-page refcount
    // is 0. If the buddy hands back a frame whose refcount is non-zero it
    // is still mapped in some live AS (a buddy/struct-page desync — e.g. a
    // frame that re-entered the free list while a peer mapping still holds
    // it). Returning it would alias two unrelated pages onto one frame
    // (the wedge: libc's .bss lock frame reused for another libc page →
    // garbage lock → glibc deadlock). Skip such a frame — consume it off
    // the free list, leave it to its real owner — and try the next.
    // Bounded so a fully-corrupt heap still terminates with NoMem.
    for _ in 0..64 {
        let pa = p.alloc(crate::Order(0)).ok().map(|pfn| pfn.0 * 4096)?;
        // PAGE POISONING check (debug-watchdog): if this frame's tail still
        // carries the 0xAA poison (so it WAS freed via free_one_frame, not
        // boot-fresh) but some earlier byte differs, something wrote to it
        // WHILE FREE — a use-after-free / write-while-mapped the PT-walk FWM
        // detector can't catch (e.g. a stale TLB write). Names pa + offset.
        #[cfg(feature = "debug-watchdog")]
        {
            let hhdm = crate::user_as::hhdm_offset();
            if hhdm != 0 {
                let base = (hhdm + pa) as *const u8;
                // SAFETY: pa freshly off the free list; HHDM mirror readable; 4 KiB.
                let tail_poison = (0..16).all(|i| unsafe { core::ptr::read_volatile(base.add(4080 + i)) } == 0xAA);
                if tail_poison {
                    for off in 0..4080usize {
                        // SAFETY: within the 4 KiB frame's HHDM mirror.
                        let b = unsafe { core::ptr::read_volatile(base.add(off)) };
                        if b != 0xAA {
                            klog::write_raw(b"[POISON] write-while-free pa="); klog::write_hex_u64(pa);
                            klog::write_raw(b" off="); klog::write_hex_u64(off as u64);
                            klog::write_raw(b" val="); klog::write_hex_u64(b as u64);
                            klog::write_raw(b"\n");
                            break;
                        }
                    }
                }
            }
        }
        // debug-cow item 3: same write-while-free check against the 0xCC
        // poison that free_one_frame stamps. A freed frame must read back all
        // 0xCC; the first byte that differs was written after the frame was
        // freed = free-while-mapped (stale TLB), double-alloc, or the buddy
        // returned a frame still in use. Tail-gated so a boot-fresh (never
        // poisoned) frame isn't flagged.
        #[cfg(feature = "debug-cow")]
        {
            let hhdm = crate::user_as::hhdm_offset();
            if hhdm != 0 {
                let base = (hhdm + pa) as *const u8;
                // SAFETY: pa freshly off the free list; HHDM mirror readable; 4 KiB.
                let tail_poison = (0..16).all(|i| unsafe { core::ptr::read_volatile(base.add(4080 + i)) } == 0xCC);
                if tail_poison {
                    for off in 0..4080usize {
                        // SAFETY: within the 4 KiB frame's HHDM mirror.
                        let b = unsafe { core::ptr::read_volatile(base.add(off)) };
                        if b != 0xCC {
                            klog::write_raw(b"[POISON] frame="); klog::write_hex_u64(pa);
                            klog::write_raw(b" dirtied-while-free off="); klog::write_hex_u64(off as u64);
                            klog::write_raw(b" val="); klog::write_hex_u64(b as u64);
                            klog::write_raw(b"\n");
                            break;
                        }
                    }
                }
            }
        }
        if let Some(meta) = page_meta() {
            if let Some(m) = meta.get(hal::Pfn(pa / 4096)) {
                let rc = m.refcount.load(Ordering::Acquire);
                // debug-cow probe 1 (ALLOCATOR INTEGRITY): a frame the buddy
                // just returned MUST be unreferenced (rc==0), unmapped
                // (mapcount==0), and NOT still marked allocated in the shadow
                // bitmap. A violation is a FRAME DOUBLE-ALLOCATION the content
                // checksum cannot see: the buddy handed out a frame a live AS
                // still owns/maps, so two address spaces map one physical page
                // writable and one's normal writes corrupt the other's random
                // code/data/stack page -> random-victim SEGV. The shadow bitmap
                // (test_and_set here, cleared in free_one_frame) catches a frame
                // handed out twice WITHOUT ever being freed — which POISON, an
                // rc check, and the checksum all miss. Marking happens even on
                // the rc!=0 skip path below: the bit then reflects the real
                // owner's allocation and its eventual free clears it.
                #[cfg(feature = "debug-cow")]
                {
                    let pfn = pa / 4096;
                    let mc = m.mapcount.load(Ordering::Acquire);
                    let still = alloc_integrity::test_and_set(pfn);
                    if still || rc != 0 || mc != 0 {
                        klog::write_raw(b"[DOUBLE-ALLOC] pa=");
                        klog::write_hex_u64(pa);
                        klog::write_raw(b" rc=");
                        klog::write_dec_u64(rc as u64);
                        klog::write_raw(b" mapcount=");
                        klog::write_dec_u64(mc as u64);
                        klog::write_raw(b" still-marked-allocated=");
                        klog::write_dec_u64(still as u64);
                        klog::write_raw(b"\n");
                        // Name who still maps it (rmap walk over the anon_vma
                        // chain, PTE-verified). Same authoritative oracle the
                        // [COW-LEAK] free-while-mapped path uses.
                        cow_dbg_rmap_report(pa);
                    }
                }
                if rc != 0 {
                    klog::write_raw(b"[PMM] alloc skipped in-use frame pa=");
                    klog::write_hex_u64(pa);
                    klog::write_raw(b" rc=");
                    klog::write_dec_u64(rc as u64);
                    klog::write_raw(b"\n");
                    continue; // never hand out a live frame
                }
                m.refcount.store(1, Ordering::Release);
                // F157-A1: a freshly-allocated frame is about to receive its
                // first user PTE (anon zero-fill / file-private snapshot /
                // KernelBytes copy / COW destination). Seed mapcount to 1 to
                // match the pending mapping, mirroring rc=1. Shmem inode base
                // frames also alloc here; their later `inc_ref` per mapper and
                // the inode-drop `dec_and_maybe_free_frame` keep the count
                // self-consistent (every inc paired with a dec).
                m.mapcount.store(1, Ordering::Release);
            }
        }
        return Some(pa);
    }
    None
}

/// F157: bump refcount on a frame already returned by `alloc_one_frame`.
/// Called by COW fork when adding a second mapping of the same physical
/// page. Mirrors Linux `get_page()`. No-op pre-init.
/// # SAFETY: caller is the COW fork path or another callsite that holds
/// a reference to a live PMM-allocated frame; we don't validate that the
/// page is actually mapped or owned, just that it's within PMM range.
/// # C: O(1)
pub unsafe fn inc_ref(pa: u64) {
    if let Some(meta) = page_meta() {
        let pfn = hal::Pfn(pa / 4096);
        let _ = meta.inc_ref(pfn);
        // F157-A1: every `inc_ref` call adds one user PTE to an existing
        // frame (fork child install, shmem MAP_SHARED fault, KernelFrame
        // vvar fault), so the live-mapping count rises in lock-step.
        let _ = meta.inc_map(pfn);
        // F157-A3 (THE load-bearing CLEAR, Linux `copy_present_pte` ->
        // `folio_clear_anon_exclusive`): `inc_ref` is precisely "a second
        // reference now exists for this frame" — a fork child installing
        // the parent's page, a second MAP_SHARED mapper, etc. The frame is
        // therefore no longer exclusively owned, so the COW-reuse fast path
        // must not fire for it. Clearing here covers EVERY fork-shared anon
        // page (fork_cow_pages calls inc_ref per shared PTE). Clearing on
        // non-anon frames (shmem/KernelFrame) is a harmless no-op — the bit
        // was never set on them.
        let _ = meta.clear_flags(pfn, crate::PageFlags::ANON_EXCLUSIVE);
    }
}

/// F157-A3: the `wp_page_reuse` predicate. True iff `pa` is an
/// exclusively-owned anonymous frame — Linux `wp_can_reuse_anon_folio`'s
/// proof that a write fault may reuse the frame in place (flip W, no
/// copy) instead of COW-splitting it. Four conjuncts, all read from
/// `PageMeta`:
///   * `ANON`            — never reuse a file / page-cache-aliased frame.
///   * `ANON_EXCLUSIVE`  — set at anon birth, CLEARED on every fork-share
///                         (`inc_ref`); proves no fork ever shared it.
///   * `mapcount == 1`   — exactly one live PTE references it.
///   * `refcount == 1`   — exactly one *reference* exists. Linux's
///                         `wp_can_reuse_anon_folio` bails on
///                         `folio_ref_count(folio) > 1`: a non-PTE
///                         reference (GUP/io_uring pin, an in-flight
///                         drop not yet observed, or any path that
///                         bumped refcount) means another holder may
///                         still read/write the frame, so reusing it in
///                         place corrupts that holder. This was MISSING
///                         (only mapcount was checked) — an asymmetry
///                         with the sole-survivor RESTORE in
///                         `dec_and_maybe_free_frame`, which already
///                         requires `refcount == 1` before re-setting
///                         ANON_EXCLUSIVE. Restoring the symmetry: the
///                         exclusive bit may be set with refcount>1 only
///                         transiently (a peer dropped its PTE but its
///                         refcount dec is not yet visible / ordered
///                         after this read); the refcount guard fails
///                         such a window safe to a copy rather than a
///                         cross-process peer corruption — the residual
///                         non-COW SEGV signature.
/// Returns false pre-init / out-of-range (→ copy path, always correct).
/// # C: O(1)
pub fn can_reuse_anon_exclusive(pa: u64) -> bool {
    let meta = match page_meta() { Some(m) => m, None => return false };
    let pfn = hal::Pfn(pa / 4096);
    let f = match meta.flags(pfn) { Some(f) => f, None => return false };
    f.contains(crate::PageFlags::ANON)
        && f.contains(crate::PageFlags::ANON_EXCLUSIVE)
        && meta.mapcount(pfn) == Some(1)
        && meta.refcount(pfn) == Some(1)
}

/// F157: refcount snapshot. Returns 0 if pre-init or out-of-range.
/// # C: O(1)
pub fn frame_refcount(pa: u64) -> u32 {
    page_meta()
        .and_then(|m| m.refcount(hal::Pfn(pa / 4096)))
        .unwrap_or(0)
}

/// F157: decrement refcount; if it reaches 0, return the frame to
/// the PMM. The standard "drop a page reference" path used by
/// AS-teardown leaf walk and COW shared-page split. Mirrors Linux
/// `put_page()` + `__free_pages()` when refcount hits zero.
/// Pre-init: falls back to `free_one_frame` (always frees).
/// # SAFETY: `pa` is a page-aligned PA originally returned by
/// `alloc_one_frame`; the caller asserts the calling site has
/// dropped its reference. If refcount reaches 0 the page must not
/// be reachable via any live PTE.
/// # C: O(1) amortised
#[track_caller]
pub unsafe fn dec_and_maybe_free_frame(pa: u64) {
    let pfn = hal::Pfn(pa / 4096);
    if let Some(meta) = page_meta() {
        // F157-A1: this drop corresponds to one user PTE being torn down
        // (munmap / AS-teardown leaf / madvise DONTNEED / COW-displaced
        // frame). Decrement the live-mapping count alongside the refcount.
        // Out-of-range pfns (device/MMIO PhysRange) return `None` here, same
        // as `dec_ref` below, so the early-return path is unaffected.
        let new_mc = meta.dec_map(pfn);
        if let Some(new) = meta.dec_ref(pfn) {
            // F157-A3 (RESTORE, Linux do_wp_page's reuse-path re-marks the
            // sole survivor exclusive): one mapper of a fork-shared anon
            // frame just went away. If exactly one PTE and one reference
            // remain, the survivor is the exclusive owner again — re-set
            // ANON_EXCLUSIVE so its next write fault can reuse in place
            // instead of pointlessly COW-copying a page nobody else maps.
            // Requires refcount==1 too so a GUP/io_uring pin (a non-PTE
            // reference that could still write) keeps the page non-exclusive.
            if new_mc == Some(1) && new == 1 {
                if meta.flags(pfn).map_or(false, |f| f.contains(crate::PageFlags::ANON)) {
                    let _ = meta.set_flags(pfn, crate::PageFlags::ANON_EXCLUSIVE);
                    // debug-cow: sole survivor is exclusive again and may
                    // legitimately write the page in place — drop its RO-shared
                    // snapshot so a later free doesn't false-positive.
                    #[cfg(feature = "debug-cow")]
                    vmm::debug_cow::forget(pa);
                }
            }
            // LOUD over-dec detection: dec on a refcount-0 frame wraps to a huge
            // value — a PTE was torn down whose inc_ref was never paired (the
            // under-count root) OR a frame was dec'd twice. Names the frame.
            #[cfg(feature = "debug-watchdog")]
            if new > 0x8000_0000 {
                klog::write_raw(b"[REFBUG] dec-underflow pa="); klog::write_hex_u64(pa);
                klog::write_raw(b" new="); klog::write_hex_u64(new as u64);
                klog::write_raw(b"\n");
                if let Some(m) = meta.get(pfn) {
                    m.refcount.store(0, core::sync::atomic::Ordering::Release);
                    m.mapcount.store(0, core::sync::atomic::Ordering::Release);
                }
                return;
            }
            if new == 0 {
                // DIAG (debug-noreclaim): leak instead of freeing. If this
                // makes the boot wedge vanish, the wedge is a free-while-mapped
                // aliasing (a frame dec'd to 0 while a peer still maps it, then
                // realloc'd onto another page).
                // BISECT (debug-leak-teardown): leak ONLY frees coming from
                // as_teardown (caller file user_as.rs); munmap/COW go through
                // rmap_aware_dec (caller file setup.rs) and still reclaim. If
                // this clears the corruption, the bad free is at teardown.
                #[cfg(feature = "debug-leak-teardown")]
                if core::panic::Location::caller().file().contains("user_as") {
                    return;
                }
                #[cfg(not(feature = "debug-noreclaim"))]
                // SAFETY: refcount hit zero — no other AS holds this
                // frame; caller asserts the leaf PTE was already torn
                // down. Same preconditions as free_one_frame.
                unsafe { free_one_frame(pa); }
            }
            return;
        }
        // PageMeta is installed but this pfn has NO slot ⇒ it is OUTSIDE the
        // PMM-managed RAM range: device/MMIO memory mapped via
        // `VmaBacking::PhysRange` (remap_pfn_range / VM_PFNMAP) — e.g. the
        // virtio-gpu scanout. Such mappings are NEVER refcounted and MUST NOT
        // be returned to the buddy (Linux `vm_normal_page` returns NULL for
        // PFNMAP, so zap_pte_range never frees them). Freeing it would hand a
        // live device frame to the allocator → free-while-mapped aliasing.
        return;
    }
    // Pre-init only (no PageMeta yet): the buddy isn't refcount-tracked, so a
    // direct free is the documented fallback. Post-init, the branch above
    // handles both in-range (dec) and out-of-range (skip) frames.
    // SAFETY: same as free_one_frame; caller assertion stands.
    unsafe { free_one_frame(pa); }
}

/// F157: install the per-page metadata array covering [0, pfn_max).
/// Called from `kernel_main` once after `init_from_boot_info` so the
/// COW path has refcount storage to use. Idempotent: a second call
/// is a no-op (first installer wins). Storage is `Box::leak`'d to
/// give the `&'static` lifetime PageMetaArr requires.
/// # C: O(pfn_max) — zero-fill the slab once.
pub fn init_page_meta(pfn_max: u64) {
    use core::sync::atomic::Ordering;
    if pfn_max == 0 { return; }
    if !PAGE_META_PTR.load(Ordering::Acquire).is_null() { return; }
    let n = pfn_max as usize;
    let mut v: alloc::vec::Vec<crate::PageMeta>
        = alloc::vec::Vec::with_capacity(n);
    for _ in 0..n { v.push(crate::PageMeta::new()); }
    let leaked: &'static [crate::PageMeta] =
        alloc::boxed::Box::leak(v.into_boxed_slice());
    let arr = crate::PageMetaArr::new(0, leaked);
    let arr_box = alloc::boxed::Box::new(arr);
    let raw = alloc::boxed::Box::leak(arr_box) as *mut _;
    PAGE_META_PTR.store(raw, Ordering::Release);
    // debug-cow probe 1: size the allocated-frame shadow bitmap to the same
    // [0, pfn_max) span as the PageMeta array, so every frame the buddy can
    // hand out has a tracking bit. Idempotent.
    #[cfg(feature = "debug-cow")]
    alloc_integrity::init(pfn_max);
}

/// F156-rmap: install the AnonVma reference for a frame. Mirrors
/// Linux `page_add_anon_rmap` shape — the page now belongs to that
/// anon-VMA family, with `page_index` as the page offset within the
/// originating VMA. Bumps the AnonVma's strong count via
/// `Arc::into_raw` and stashes the raw pointer in `PageMeta.mapping`.
/// If a previous AnonVma was bound it gets dropped (rare path:
/// re-bind on a recycled frame; the dec_and_maybe_free path normally
/// clears mapping before the frame is reused).
///
/// # SAFETY: `pa` is a live PMM-allocated frame whose PageMeta slot
/// belongs to the caller's mapping; `av` is alive at call time.
/// # C: O(1)
pub unsafe fn set_anon_rmap_for_pa(
    pa: u64,
    av: &alloc::sync::Arc<vmm::AnonVma>,
    page_index: u32,
) {
    let meta = match page_meta() { Some(m) => m, None => return };
    let pfn = hal::Pfn(pa / 4096);
    let raw = alloc::sync::Arc::into_raw(alloc::sync::Arc::clone(av)) as *mut ();
    if let Some(prev) = meta.swap_mapping(pfn, raw) {
        if !prev.is_null() {
            // SAFETY: previous slot was set via set_anon_rmap_for_pa's
            // Arc::into_raw; reclaiming and dropping it balances that
            // strong-count bump.
            unsafe { drop(alloc::sync::Arc::from_raw(prev as *const vmm::AnonVma)); }
        }
    }
    let _ = meta.set_page_index(pfn, page_index);
    // F157-A3 (Linux `page_add_new_anon_rmap` -> the folio is born
    // exclusive): `set_anon_rmap_for_pa` is called exactly at the two
    // sites that mint a freshly-owned anon frame — the do_anonymous_page
    // zero-fill and the COW-copy destination — and only for VMAs that
    // carry an anon_vma (`VmaBacking::Anonymous`). Both produce a page
    // mapped by exactly one writable owner, so mark it ANON +
    // ANON_EXCLUSIVE. The exclusivity is revoked later by `inc_ref` the
    // moment a fork shares it.
    let _ = meta.set_flags(pfn, crate::PageFlags::ANON | crate::PageFlags::ANON_EXCLUSIVE);
}

/// Inverse of `set_anon_rmap_for_pa`. Loads the stored raw pointer,
/// stores null, drops the Arc. Idempotent on null. Called from
/// `dec_and_maybe_free_frame` when the refcount hits zero — the
/// frame is about to return to PMM, so we must drop our chain
/// reference first or leak the AnonVma.
///
/// # SAFETY: `pa` is a frame whose mapping slot is owned by the
/// caller's flow (no concurrent reader of the slot's pointee).
/// # C: O(1)
pub unsafe fn clear_anon_rmap_for_pa(pa: u64) {
    let meta = match page_meta() { Some(m) => m, None => return };
    let pfn = hal::Pfn(pa / 4096);
    if let Some(prev) = meta.swap_mapping(pfn, core::ptr::null_mut()) {
        if !prev.is_null() {
            // SAFETY: prev was installed via set_anon_rmap_for_pa's
            // Arc::into_raw; we now reclaim ownership and drop.
            unsafe { drop(alloc::sync::Arc::from_raw(prev as *const vmm::AnonVma)); }
        }
    }
    let _ = meta.set_page_index(pfn, 0);
}

/// Snapshot the AnonVma stored at `pa`. Bumps the strong count so
/// the caller's clone is independent. `None` if no anon_vma is
/// bound or pre-init.
/// # C: O(1)
pub fn anon_vma_for_pa(pa: u64) -> Option<alloc::sync::Arc<vmm::AnonVma>> {
    let meta = page_meta()?;
    let pfn = hal::Pfn(pa / 4096);
    let raw = meta.mapping(pfn)?;
    if raw.is_null() { return None; }
    // SAFETY: raw was installed via set_anon_rmap_for_pa's into_raw;
    // increment the strong count and reconstruct an owned Arc.
    unsafe {
        alloc::sync::Arc::increment_strong_count(raw as *const vmm::AnonVma);
        Some(alloc::sync::Arc::from_raw(raw as *const vmm::AnonVma))
    }
}

/// Snapshot the page_index stored at `pa`. 0 pre-init or out-of-range.
/// # C: O(1)
pub fn page_index_for_pa(pa: u64) -> u32 {
    page_meta()
        .and_then(|m| m.page_index(hal::Pfn(pa / 4096)))
        .unwrap_or(0)
}

/// debug-fwm: count live address spaces OTHER than `exclude_root` that still
/// map VA `va` to physical frame `pa`. Used at as_teardown free-to-zero to
/// catch free-while-mapped aliasing — a frame about to return to PMM while a
/// peer task's PTE still maps it (refcount under-counted). Works for ALL
/// backings (not just anon, unlike an rmap walk) by enumerating live tasks'
/// address spaces. `hhdm` is the HHDM offset for foreign-PT reads.
/// # C: O(N_tasks)
#[cfg(feature = "debug-fwm")]
pub fn fwm_peer_maps(va: u64, pa: u64, exclude_root: u64, hhdm: u64) -> usize {
    let target = pa & !0xfff;
    let tasks = match sched::registry::try_snapshot() { Some(t) => t, None => return 0 };
    let mut count = 0usize;
    let mut seen: [u64; 96] = [0; 96];
    let mut n_seen = 0usize;
    for t in tasks.iter() {
        // SAFETY: smp=1 debug detector; no other task executes during this
        // teardown, so reading a peer task's mm root is a stable read.
        let root = match unsafe { t.mm_ref() } { Some(mm) => mm.root_pa(), None => continue };
        if root == exclude_root || root == 0 { continue; }
        if seen[..n_seen].contains(&root) { continue; } // dedup threads sharing an mm
        if n_seen < seen.len() { seen[n_seen] = root; n_seen += 1; }
        // SAFETY: read-only foreign-mm PT walk; root is a live AS root frame;
        // HHDM covers page-table memory.
        #[cfg(target_arch = "x86_64")]
        let tr = unsafe { hal::pt_walker::translate_4k_at_root::<hal_x86_64::vmm::PtWalkerX86>(root, va, hhdm) };
        #[cfg(target_arch = "aarch64")]
        let tr = unsafe { hal::pt_walker::translate_4k_at_root::<hal_aarch64::vmm::PtWalkerArm>(root, va, hhdm) };
        if let Some((mapped, _)) = tr {
            if (mapped & !0xfff) == target { count += 1; }
        }
    }
    count
}

/// F156-rmap: drop the rmap edge before the frame returns to PMM.
/// Wraps `dec_and_maybe_free_frame` so callers that don't carry an
/// AnonVma reference still keep the chain consistent. Intended for
/// the COW split + munmap leaf-walk paths.
/// # SAFETY: same as `dec_and_maybe_free_frame`.
/// # C: O(1)
pub unsafe fn rmap_aware_dec_and_maybe_free(pa: u64) {
    // SAFETY: clear_anon_rmap_for_pa drops the Arc bound to this
    // frame's PageMeta.mapping; subsequent dec_ref handles refcount.
    unsafe { clear_anon_rmap_for_pa(pa); }
    // SAFETY: caller asserts the frame's leaf PTE has been removed.
    unsafe { dec_and_maybe_free_frame(pa); }
}

/// F157: compute pfn_max from a `BootInfo`. Used by `kernel_main` to
/// size the per-page metadata array. Same walk as
/// `init_from_boot_info`; lifted here so callers don't have to
/// touch `BootMemRegion` themselves.
/// # C: O(memmap.len)
pub fn pfn_max_from_boot_info(info: &BootInfo) -> u64 {
    if info.memmap_count == 0 { return 0; }
    // SAFETY: caller passed valid memmap_ptr/count per BootInfo contract.
    let regions: &[BootMemRegion] = unsafe {
        core::slice::from_raw_parts(info.memmap_ptr, info.memmap_count as usize)
    };
    let mut pfn_max: u64 = 0;
    for r in regions {
        if r.kind != BootMemKind::Usable { continue; }
        let end_pa = r.base_pa.saturating_add(r.len);
        let end_pfn = end_pa >> PAGE_SHIFT;
        if end_pfn > pfn_max { pfn_max = end_pfn; }
    }
    pfn_max
}

/// debug-cow: identify the current task (Linux pid == kernel tid) and CPU
/// for [COW-CORRUPT] / [COW-LEAK] attribution. Returns (0,0) pre-sched.
/// # C: O(1)
#[cfg(feature = "debug-cow")]
fn cow_dbg_who() -> (u32, u32) {
    let tid = sched::current().map(|t| t.tid).unwrap_or(0);
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    let cpu = { use hal::CpuOps; hal_x86_64::X86CpuOps::current_cpu() };
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    let cpu = { use hal::CpuOps; hal_aarch64::ArmCpuOps::current_cpu() };
    #[cfg(not(target_os = "oxide-kernel"))]
    let cpu = 0u32;
    (tid, cpu)
}

/// debug-cow item 2: authoritative "who still maps this frame" report.
/// The O(1) mapcount check can itself be under-counted (the residual-bug
/// hypothesis), so on a [COW-LEAK] hit we walk the frame's anon_vma rmap
/// chain and PTE-verify each candidate, naming a concrete still-mapping
/// (AS-root, VA) pair: `[COW-LEAK]  still-mapped-by root=R va=V`.
/// # C: O(N_chain) page-table walks
#[cfg(feature = "debug-cow")]
fn cow_dbg_rmap_report(pa: u64) {
    crate::user_as::rmap_walk_anon_pa(pa, |root, va| {
        klog::write_raw(b"[COW-LEAK]  still-mapped-by root="); klog::write_hex_u64(root);
        klog::write_raw(b" va="); klog::write_hex_u64(va);
        klog::write_raw(b"\n");
    });
}

/// Internal: snapshot the metadata array if installed.
fn page_meta() -> Option<&'static crate::PageMetaArr> {
    let p = PAGE_META_PTR.load(core::sync::atomic::Ordering::Acquire);
    if p.is_null() { return None; }
    // SAFETY: PAGE_META_PTR is set exactly once via Box::leak in
    // init_page_meta; the pointee has 'static lifetime; never freed.
    Some(unsafe { &*p })
}

/// Allocate a single contiguous physical region of `2^order` 4 KiB
/// frames; return its base PA (aligned to the region size). Used
/// by huge-page smokes / future huge-leaf consumers. `Order(0)` =
/// 4 KiB, `Order(9)` = 2 MiB, `Order(18)` = 1 GiB.
/// # C: O(log heap) (PMM buddy alloc at higher order).
pub fn alloc_contig(order: crate::Order) -> Option<u64> {
    let p = pmm_static()?;
    p.alloc(order).ok().map(|pfn| pfn.0 * 4096)
}

/// Free a single 4 KiB frame back to the kernel-owned PMM. Pair of
/// `alloc_one_frame`; the PA must originally have come from a PMM
/// alloc and not be currently mapped in any live page table (caller's
/// responsibility — `vmm::munmap` walks PTs first, then frees here).
/// # SAFETY: `pa` is a page-aligned PA originally returned by
/// `alloc_one_frame` (or huge-leaf split that wasn't promoted), no
/// longer reachable via any live PTE; single-CPU pre-userspace v1.
/// # C: O(1) amortised (PMM buddy free).
#[track_caller]
pub unsafe fn free_one_frame(pa: u64) {
    let p = match pmm_static() { Some(p) => p, None => return };
    let pfn = hal::Pfn(pa / 4096);
    // Defense in depth: once PageMeta is installed, a pfn with no slot is
    // outside PMM-managed RAM (device/MMIO PhysRange) and must never reach the
    // buddy — returning it would corrupt the allocator and alias live device
    // memory. `dec_and_maybe_free_frame` already filters these, but a stray
    // direct caller must not slip one through.
    if let Some(meta) = page_meta() {
        if meta.get(pfn).is_none() { return; }
    }
    // Reset struct-page refcount to 0 before the frame re-enters the free
    // list, so the buddy free-list and per-page refcount stay in sync and
    // the alloc-side `check_new_page` invariant (free frame ⇒ refcount 0)
    // holds for frames freed directly (PT tables, AS root) as well as via
    // dec_and_maybe_free. Mirrors Linux `free_pages_prepare` zeroing.
    if let Some(meta) = page_meta() {
        if let Some(m) = meta.get(pfn) {
            // LOUD free-while-referenced: a RAW free (PT table / AS root / direct
            // caller) of a frame whose refcount is still >1 means it's freed
            // while another reference (PTE) maps it → free-while-mapped aliasing.
            #[cfg(feature = "debug-watchdog")]
            {
                let rc = m.refcount.load(core::sync::atomic::Ordering::Acquire);
                if rc > 1 {
                    klog::write_raw(b"[REFBUG] free-while-ref pa="); klog::write_hex_u64(pa);
                    klog::write_raw(b" rc="); klog::write_dec_u64(rc as u64);
                    klog::write_raw(b"\n");
                }
            }
            // debug-cow item 1: re-verify the RO-shared anon checksum before
            // the frame is recycled (a peer may have written it after the last
            // mapper's view was taken). item 2: refcount==live-PTE assert —
            // mapcount MUST be 0 at free; a non-zero mapcount means a live PTE
            // still points here (free-while-mapped, the inverse RANK-1 bug).
            #[cfg(feature = "debug-cow")]
            {
                let (tid, cpu) = cow_dbg_who();
                vmm::debug_cow::check_free(pa, crate::user_as::hhdm_offset(), tid, cpu);
                let mc = m.mapcount.load(core::sync::atomic::Ordering::Acquire);
                let rc = m.refcount.load(core::sync::atomic::Ordering::Acquire);
                if mc != 0 {
                    // flags: ANON(1<<4)/ANON_EXCLUSIVE(1<<9) distinguish a real
                    // data-page free-while-mapped (ANON set ⇒ a leaf user page
                    // freed with a live PTE = corruption) from a benign recycled
                    // PT-table/file frame carrying a stale mapcount (ANON clear).
                    let fl = meta.flags(pfn).map(|f| f.bits()).unwrap_or(0);
                    klog::write_raw(b"[COW-LEAK] free-while-mapped pa="); klog::write_hex_u64(pa);
                    klog::write_raw(b" mapcount="); klog::write_dec_u64(mc as u64);
                    klog::write_raw(b" refcount="); klog::write_dec_u64(rc as u64);
                    klog::write_raw(b" flags="); klog::write_hex_u64(fl as u64);
                    klog::write_raw(b"\n");
                    // Sampled rmap cross-check: name a concrete still-mapping VA
                    // (the O(1) mapcount may itself be under-counted; the rmap
                    // walk over the anon_vma chain is the authoritative oracle).
                    cow_dbg_rmap_report(pa);
                }
            }
            m.refcount.store(0, core::sync::atomic::Ordering::Release);
            // F157-A1: a frame re-entering the free list has no mappings —
            // reset mapcount to 0 so the next `alloc_one_frame` starts clean
            // (Linux `free_pages_prepare` zeroes `_mapcount`). Direct frees
            // (PT tables, AS root) never had a mapcount; this is idempotent.
            m.mapcount.store(0, core::sync::atomic::Ordering::Release);
            // F157-A3: clear the page-class bits (Linux `free_pages_prepare`
            // -> `__folio_clear_anon`/`PAGE_FLAGS_CHECK_AT_FREE`). A recycled
            // frame must not inherit a stale ANON / ANON_EXCLUSIVE from its
            // previous life, or the COW-reuse fast path could fire on a fresh
            // non-anon allocation. set_anon_rmap_for_pa re-establishes them
            // for the next anon owner.
            let _ = meta.clear_flags(pfn,
                crate::PageFlags::ANON | crate::PageFlags::ANON_EXCLUSIVE);
        }
    }
    // PAGE POISONING (debug-watchdog): fill the freed frame with 0xAA so a
    // later alloc can detect a write-while-free (use-after-free / stale-TLB
    // write that the PT-walk-based FWM detector can't see). Linux PAGE_POISONING.
    #[cfg(feature = "debug-watchdog")]
    {
        let hhdm = crate::user_as::hhdm_offset();
        if hhdm != 0 {
            // SAFETY: pa is a just-freed PMM frame; HHDM mirror is kernel-writable; 4 KiB granule.
            unsafe { core::ptr::write_bytes((hhdm + pa) as *mut u8, 0xAA, 4096); }
        }
    }
    // debug-cow item 3: poison freed frames with 0xCC. `alloc_one_frame`
    // checks the pattern; any non-0xCC byte on a frame coming off the free
    // list = it was written WHILE FREE (free-while-mapped via a stale TLB,
    // double-alloc, or the allocator handed out an in-use frame). 0xCC is
    // distinct from debug-watchdog's 0xAA so the two probes don't alias.
    #[cfg(feature = "debug-cow")]
    {
        // debug-cow probe 1: the frame is leaving for the free list — clear
        // its allocated bit so a later alloc that finds the bit still set
        // (test_and_set returns true) is a genuine double-alloc, not a stale
        // mark from this frame's previous life.
        alloc_integrity::clear(pa / 4096);
        let hhdm = crate::user_as::hhdm_offset();
        if hhdm != 0 {
            // SAFETY: pa is a just-freed PMM frame; HHDM mirror is kernel-writable; 4 KiB granule.
            unsafe { core::ptr::write_bytes((hhdm + pa) as *mut u8, 0xCC, 4096); }
        }
    }
    // SAFETY: caller asserts pa was a prior alloc and is no longer mapped per fn contract; crate::Buddy::free's preconditions reduce to "page aligned + within range" which alloc_one_frame guarantees.
    unsafe { p.free(pfn, crate::Order(0)); }
}

/// debug-cow probe 1 (ALLOCATOR INTEGRITY): authoritative allocated-frame
/// shadow bitmap. One bit per PFN — SET the instant `alloc_one_frame` hands
/// the frame out, CLEARED when `free_one_frame` returns it. The PMM buddy
/// free-list + per-page refcount are the production truth; this independent
/// bitmap catches a FRAME DOUBLE-ALLOCATION that neither the 0xCC poison
/// (only sees a frame dirtied WHILE FREE, not one never freed) nor a content
/// checksum (a never-freed frame's content is self-consistent) can detect:
/// the buddy returns a frame still owned/mapped by a live AS — its bit is
/// still set — so `test_and_set` reports the prior bit and `alloc_one_frame`
/// fires [DOUBLE-ALLOC].
#[cfg(feature = "debug-cow")]
mod alloc_integrity {
    use core::sync::atomic::{AtomicPtr, AtomicU64, AtomicUsize, Ordering};

    /// Data pointer to the leaked `[AtomicU64]` shadow bitmap (null until init).
    static BITS: AtomicPtr<AtomicU64> = AtomicPtr::new(core::ptr::null_mut());
    /// Word count of the bitmap (ceil(pfn_max/64)).
    static WORDS: AtomicUsize = AtomicUsize::new(0);

    /// Allocate the shadow bitmap covering [0, pfn_max). Idempotent (first
    /// caller wins). Called from `init_page_meta` once pfn_max is known.
    /// # C: O(pfn_max / 64)
    pub fn init(pfn_max: u64) {
        if pfn_max == 0 || !BITS.load(Ordering::Acquire).is_null() { return; }
        let words = ((pfn_max + 63) / 64) as usize;
        let mut v: alloc::vec::Vec<AtomicU64> = alloc::vec::Vec::with_capacity(words);
        for _ in 0..words { v.push(AtomicU64::new(0)); }
        let leaked: &'static [AtomicU64] = alloc::boxed::Box::leak(v.into_boxed_slice());
        // Publish WORDS before BITS so any reader that observes a non-null
        // BITS also observes the correct length.
        WORDS.store(words, Ordering::Release);
        BITS.store(leaked.as_ptr() as *mut AtomicU64, Ordering::Release);
    }

    /// `&AtomicU64` for `pfn`'s word, or `None` pre-init / out-of-range.
    /// # C: O(1)
    fn word(pfn: u64) -> Option<&'static AtomicU64> {
        let p = BITS.load(Ordering::Acquire);
        if p.is_null() { return None; }
        let w = (pfn >> 6) as usize;
        if w >= WORDS.load(Ordering::Acquire) { return None; }
        // SAFETY: BITS is a Box::leak'd 'static [AtomicU64] of WORDS elements;
        // `w` is bounds-checked above; a shared &AtomicU64 is sound (atomics).
        Some(unsafe { &*p.add(w) })
    }

    /// Mark `pfn` allocated; return the PRIOR bit (true ⇒ already allocated
    /// = double-alloc). No-op (returns false) pre-init / out-of-range.
    /// # C: O(1)
    pub fn test_and_set(pfn: u64) -> bool {
        let bit = 1u64 << (pfn & 63);
        match word(pfn) {
            Some(w) => (w.fetch_or(bit, Ordering::AcqRel) & bit) != 0,
            None    => false,
        }
    }

    /// Mark `pfn` free. Idempotent; no-op pre-init / out-of-range.
    /// # C: O(1)
    pub fn clear(pfn: u64) {
        let bit = 1u64 << (pfn & 63);
        if let Some(w) = word(pfn) { w.fetch_and(!bit, Ordering::AcqRel); }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_error_distinct() {
        assert_ne!(SetupError::NoMemmap,        SetupError::NoHhdm);
        assert_ne!(SetupError::NoUsableRegion,  SetupError::NoSpaceForBitmaps);
    }

    #[test]
    fn empty_memmap_returns_nomemmap() {
        let info = BootInfo {
            memmap_count: 0,
            memmap_ptr: core::ptr::null(),
            seed: [0; 32],
            boot_ns: 0,
            rsdp_pa: 0,
            hhdm_offset: 0xFFFF_8000_0000_0000,
            smp_info_array: 0,
            smp_count: 0,
            bsp_lapic_id: 0,
            _pad: 0,
        };
        // SAFETY: hosted test; memmap_count is 0 so memmap_ptr is
        // never dereferenced.
        assert_eq!(unsafe { init_from_boot_info(&info).err() }, Some(SetupError::NoMemmap));
    }

    #[test]
    fn missing_hhdm_returns_nohhdm() {
        let r = [BootMemRegion { base_pa: 0, len: 4096, kind: BootMemKind::Usable }];
        let info = BootInfo {
            memmap_count: 1,
            memmap_ptr: r.as_ptr(),
            seed: [0; 32],
            boot_ns: 0,
            rsdp_pa: 0,
            hhdm_offset: 0,
            smp_info_array: 0,
            smp_count: 0,
            bsp_lapic_id: 0,
            _pad: 0,
        };
        // SAFETY: hosted test; r outlives the call.
        assert_eq!(unsafe { init_from_boot_info(&info).err() }, Some(SetupError::NoHhdm));
    }
}
