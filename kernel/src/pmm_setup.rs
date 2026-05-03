// PMM bring-up from `BootInfo` per `10§6.3` boot rule.
//
// Walks the bootloader memmap, picks one Usable region big enough to
// host the per-order bitmap pool, carves the bitmap from the front
// of that region, and feeds the remaining Usable regions to
// `Pmm::init`. KernelImage / Reserved / Bootloader* pages are
// filtered upstream by the memmap classification — they never enter
// PMM. Single-shot from `kernel_main`.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicBool, Ordering};

use hal::{Pfn, PAGE_SHIFT, PAGE_SIZE_BYTES};
use pmm::{Error as PmmError, PageBacking, Pmm, UsableRegion, ORDERS};

use crate::{BootInfo, BootMemKind, BootMemRegion};

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
/// virtual machines emit ≤ 8; bump if a real platform overshoots.
pub const MAX_REGIONS: usize = 32;

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
/// # C: O(1) amortised (PMM buddy alloc).
pub fn alloc_one_frame() -> Option<u64> {
    let p = pmm_static()?;
    p.alloc(pmm::Order(0)).ok().map(|pfn| pfn.0 * 4096)
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
        };
        // SAFETY: hosted test; r outlives the call.
        assert_eq!(unsafe { init_from_boot_info(&info).err() }, Some(SetupError::NoHhdm));
    }
}
