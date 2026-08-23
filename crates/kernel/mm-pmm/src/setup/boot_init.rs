use super::*;
use core::sync::atomic::AtomicU64;

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
    /// Largest Usable region cannot hold the canonical struct-page array
    /// reserved during bootstrap.
    NoSpaceForPageMeta,
    /// More usable regions than `MAX_REGIONS`. Bump the bound.
    TooManyRegions,
    /// More normalized boot-map entries than the retained topology bound.
    TooManyTopologyRegions,
    /// Page-normalized boot-map entries overlap.
    OverlappingTopology,
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

/// `PageBacking` over the boot HHDM. `page_ptr(pfn) = hhdm + pfn*4096`.
/// Bitmap slices are pre-sliced into a single carved-out pool during
/// `init_from_boot_info` and remembered here.
pub struct HhdmBacking {
    hhdm: u64,
    bitmaps: [&'static [core::sync::atomic::AtomicU64]; BITMAP_SLOTS],
    pcp: &'static PcpStorage,
}

// The live PMM is reached from hard-IRQ paths (page-table allocation and
// fault handling).  Its buddy lock must therefore mask local IRQs while it
// is held: a plain spinlock permits an interrupt on the owning CPU to recurse
// into the allocator and spin indefinitely.  Hosted tests deliberately keep
// using `NoopIrq` through their own `Pmm<HostedBacking>` instances.
#[cfg(target_arch = "x86_64")]
pub type KernelIrqGate = hal_x86_64::X86IrqGate;
#[cfg(target_arch = "aarch64")]
pub type KernelIrqGate = hal_aarch64::ArmIrqGate;

/// Concrete live-kernel PMM type used by integration adapters.
pub type KernelPmm = Pmm<HhdmBacking, KernelIrqGate>;
/// One live-kernel hibernation frame with ownership tied to the boot PMM.
pub type KernelHibernateFrame = crate::HibernateFrame<'static, HhdmBacking, KernelIrqGate>;
/// Saved continuation state: owned like a hibernation frame but image-saveable.
pub type KernelHibernateSavedFrame = crate::HibernateSavedFrame<'static, HhdmBacking, KernelIrqGate>;

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
        slot: u8,
        len_u64: usize,
    ) -> &'static [core::sync::atomic::AtomicU64] {
        let s = self.bitmaps[slot as usize];
        debug_assert!(s.len() >= len_u64);
        &s[..len_u64]
    }

    /// # C: O(1)
    fn pcp_storage(&self) -> &'static PcpStorage { self.pcp }
}

// ---------------------------------------------------------------------------
// One-shot static storage for the live `Pmm` and the region buffer.
// ---------------------------------------------------------------------------

struct PmmCell(UnsafeCell<MaybeUninit<Pmm<HhdmBacking, KernelIrqGate>>>);
// SAFETY: Initialized exactly once before any other CPU is alive
// (single-shot from `kernel_main`); afterwards `Pmm` is internally
// `Sync` via its own `Spinlock`.
unsafe impl Sync for PmmCell {}

static PMM_STORAGE: PmmCell = PmmCell(UnsafeCell::new(MaybeUninit::uninit()));
struct PcpCell(UnsafeCell<MaybeUninit<PcpStorage>>);
// SAFETY: `init_from_boot_info` initializes this exactly once before any CPU
// can allocate, then the contained spinlocks provide the synchronization.
unsafe impl Sync for PcpCell {}
static PCP_STORAGE: PcpCell = PcpCell(UnsafeCell::new(MaybeUninit::uninit()));
static PMM_READY: AtomicBool = AtomicBool::new(false);
static DIRECT_MAP_BASE: AtomicU64 = AtomicU64::new(0);
struct RegionBuf(UnsafeCell<[UsableRegion; MAX_REGIONS]>);
// SAFETY: Written exactly once during single-CPU init; read once
// (passed into `Pmm::init` by reference); never mutated afterwards.
unsafe impl Sync for RegionBuf {}
static REGION_BUF: RegionBuf = RegionBuf(UnsafeCell::new(
    [UsableRegion { start: Pfn(0), len_pfn: 0 }; MAX_REGIONS],
));
/// Entries of `REGION_BUF` that `init_from_boot_info` filled.
static REGION_COUNT: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Cached usable-RAM projection derived from [`memory_topology`], in physical
/// order — the reference's `pfn_mapped`. Empty before setup succeeds.
///
/// Published because a caller building page tables that must cover all of RAM
/// (kexec's identity map) needs the same list the buddy was seeded with; a
/// The cache exists for the legacy slice API; the normalized topology remains
/// the sole classification owner.
/// # C: O(1)
pub fn usable_regions() -> &'static [UsableRegion] {
    let n = REGION_COUNT.load(Ordering::Acquire);
    // SAFETY: `REGION_BUF[0..n]` was written once during single-CPU init and
    // never mutated afterwards; `REGION_COUNT` is published with release
    // ordering after those writes.
    unsafe { core::slice::from_raw_parts(REGION_BUF.0.get() as *const UsableRegion, n) }
}

/// Kernel direct-map base published by boot memory setup, or zero before PMM setup.
/// # C: O(1)
pub fn direct_map_base() -> u64 { DIRECT_MAP_BASE.load(Ordering::Acquire) }

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
) -> Result<&'static Pmm<HhdmBacking, KernelIrqGate>, SetupError> {
    if PMM_READY.load(Ordering::Acquire) {
        return Err(SetupError::AlreadyInit);
    }
    if info.memmap_count == 0 {
        return Err(SetupError::NoMemmap);
    }
    if info.hhdm_offset == 0 {
        return Err(SetupError::NoHhdm);
    }
    DIRECT_MAP_BASE.store(info.hhdm_offset, Ordering::Release);

    // SAFETY: caller-asserted memmap_ptr/memmap_count contract.
    let regions: &[BootMemRegion] = unsafe {
        core::slice::from_raw_parts(info.memmap_ptr, info.memmap_count as usize)
    };
    super::topology::publish(regions)?;

    let topology = super::topology::memory_topology();

    // Compute pfn_max from the one normalized topology owner.
    let mut pfn_max: u64 = 0;
    for r in topology {
        if r.kind != BootMemKind::Usable { continue; }
        if r.end.0 > pfn_max { pfn_max = r.end.0; }
    }
    if pfn_max == 0 {
        return Err(SetupError::NoUsableRegion);
    }

    // Per-order bitmap byte requirements + total. PMM stores one
    // bitmap per order from 0..=MAX_ORDER, sized by ceil(pfn_max/2^o).
    // All math is overflow-safe; saturating semantics are fine
    // because oversized inputs just produce a too-large pool that
    // fails the next find-region step.
    let mut per_order_words: [usize; BITMAP_SLOTS] = [0; BITMAP_SLOTS];
    let mut total_bytes: u64 = 0;
    let mut o = 0usize;
    while o < BITMAP_SLOTS {
        let words = if o == PAGEBLOCK_TYPE_SLOT {
            let pageblocks = pfn_max.saturating_add(crate::zone::PAGEBLOCK_PAGES - 1) / crate::zone::PAGEBLOCK_PAGES;
            pageblocks.saturating_add(31) / 32
        } else {
            let blocks = if o == PCP_BITMAP_SLOT || o == HIBERNATE_FORBIDDEN_SLOT {
                pfn_max
            } else {
                let stride = 1u64 << (o as u32);
                let plus = pfn_max.saturating_add(stride.saturating_sub(1));
                plus >> (o as u32)
            };
            blocks.saturating_add(63) >> 6
        };
        per_order_words[o] = words as usize;
        total_bytes = total_bytes.saturating_add(words.saturating_mul(8));
        o += 1;
    }
    // Round bitmap pool size up to a page.
    let bitmap_pool_pages = total_bytes
        .checked_add(PAGE_SIZE_BYTES - 1)
        .map(|x| x / PAGE_SIZE_BYTES)
        .unwrap_or(u64::MAX / PAGE_SIZE_BYTES);
    let bitmap_pool_bytes = bitmap_pool_pages.saturating_mul(PAGE_SIZE_BYTES);

    // Reserve the Linux struct-page equivalent directly from the boot map.
    // It cannot come from kalloc: kalloc growth itself must be classified in
    // this metadata before it can be exposed to the allocator.
    let page_meta_bytes = pfn_max
        .checked_mul(core::mem::size_of::<crate::PageMeta>() as u64)
        .ok_or(SetupError::NoSpaceForPageMeta)?;
    let page_meta_pages = page_meta_bytes
        .checked_add(PAGE_SIZE_BYTES - 1)
        .map(|bytes| bytes / PAGE_SIZE_BYTES)
        .ok_or(SetupError::NoSpaceForPageMeta)?;
    let page_meta_pool_bytes = page_meta_pages
        .checked_mul(PAGE_SIZE_BYTES)
        .ok_or(SetupError::NoSpaceForPageMeta)?;
    let native_page_bytes = pfn_max
        .checked_mul(core::mem::size_of::<crate::NativePage>() as u64)
        .ok_or(SetupError::NoSpaceForPageMeta)?;
    let native_page_pages = native_page_bytes
        .checked_add(PAGE_SIZE_BYTES - 1)
        .map(|bytes| bytes / PAGE_SIZE_BYTES)
        .ok_or(SetupError::NoSpaceForPageMeta)?;
    let native_page_pool_bytes = native_page_pages
        .checked_mul(PAGE_SIZE_BYTES)
        .ok_or(SetupError::NoSpaceForPageMeta)?;
    let pool_bytes = bitmap_pool_bytes
        .checked_add(page_meta_pool_bytes)
        .and_then(|bytes| bytes.checked_add(native_page_pool_bytes))
        .ok_or(SetupError::NoSpaceForPageMeta)?;

    // Pick the first Usable region with `len >= pool_bytes + slack`.
    let needed = pool_bytes.saturating_add(PAGE_SIZE_BYTES);
    let chosen_idx = topology
        .iter()
        .position(|r| r.kind == BootMemKind::Usable
            && r.end.0.saturating_sub(r.start.0).saturating_mul(PAGE_SIZE_BYTES) >= needed)
        .ok_or(SetupError::NoSpaceForBitmaps)?;
    let chosen = topology[chosen_idx];
    let chosen_base_pa = chosen.start.0.saturating_mul(PAGE_SIZE_BYTES);

    // Carve the pool from the front of `chosen`. HHDM gives us a
    // kernel VA covering the whole pool at `hhdm + chosen.base_pa`.
    let pool_va: *mut u8 = info.hhdm_offset.wrapping_add(chosen_base_pa) as *mut u8;
    // SAFETY: pool memory is RAM (chosen.kind == Usable), HHDM-mapped by the bootloader, page-aligned (boot memmap entries are page-aligned), and not yet touched by any kernel subsystem because we run before kernel_main hands control to anything else.
    unsafe {
        hal::zerotrap::trap(pool_va as *const u8, (pool_bytes / 8) as usize);
        core::ptr::write_bytes(pool_va, 0, pool_bytes as usize);
    }

    // Slice the pool into per-order bitmap views.
    let mut bitmaps: [&'static [core::sync::atomic::AtomicU64]; BITMAP_SLOTS] = [&[][..]; BITMAP_SLOTS];
    let mut cursor: *mut u8 = pool_va;
    let mut o = 0usize;
    while o < BITMAP_SLOTS {
        let words = per_order_words[o];
        if words > 0 {
            // SAFETY: cursor stays within `pool_va..pool_va+pool_bytes`
            // by construction (sum of per_order_words ≤ bitmap_pool_bytes/8).
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

    // The remaining reserved pool is the permanent PageMeta array.  It is
    // initialized and published before PMM readiness below, so no PMM-backed
    // heap arena can ever exist without canonical ownership metadata.
    // SAFETY: `pool_bytes = bitmap_pool_bytes + page_meta_pool_bytes` and the
    // chosen region was required to hold `pool_bytes + PAGE_SIZE_BYTES`, so
    // this offset lands strictly inside the single HHDM allocation `pool_va`
    // names — the one-past-the-end rule `ptr::add` requires.
    let page_meta_ptr = unsafe { pool_va.add(bitmap_pool_bytes as usize) } as *mut crate::PageMeta;
    // SAFETY: native descriptor storage follows the rounded PageMeta slab within the same reservation.
    let native_page_ptr = unsafe { (page_meta_ptr as *mut u8).add(page_meta_pool_bytes as usize) } as *mut crate::NativePage;

    // Build the UsableRegion list, shrinking the chosen region.
    let mut n_regions = 0usize;
    for (i, r) in topology.iter().enumerate() {
        if r.kind != BootMemKind::Usable { continue; }
        if n_regions >= MAX_REGIONS {
            return Err(SetupError::TooManyRegions);
        }
        let base_pa = r.start.0.saturating_mul(PAGE_SIZE_BYTES);
        let len = r.end.0.saturating_sub(r.start.0).saturating_mul(PAGE_SIZE_BYTES);
        let (base_pa, len) = if i == chosen_idx {
            (base_pa.saturating_add(pool_bytes), len.saturating_sub(pool_bytes))
        } else {
            (base_pa, len)
        };
        let mut start_pfn = base_pa
            .checked_add(PAGE_SIZE_BYTES - 1)
            .map(|x| x >> PAGE_SHIFT)
            .unwrap_or(u64::MAX >> PAGE_SHIFT);
        let end_pfn = base_pa
            .checked_add(len)
            .map(|x| x >> PAGE_SHIFT)
            .unwrap_or(u64::MAX >> PAGE_SHIFT);
        // PFN 0 (physical page 0) is never handed to the buddy allocator,
        // matching Linux's unconditional `memblock_reserve(0, PAGE_SIZE)` —
        // firmware/BIOS low-memory structures live there, and callers
        // throughout this codebase (virtqueue setup, `frame_ptr` checks,
        // etc.) treat a raw PA of 0 as a null/failure sentinel. Handing out
        // real PFN 0 makes an allocation silently indistinguishable from
        // "allocation failed" to those callers.
        if start_pfn == 0 { start_pfn = 1; }
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

    REGION_COUNT.store(n_regions, Ordering::Release);
    // The firmware projection is derived from the same retained topology; it
    // is a byte-range cache for existing consumers, not an independent map.
    super::fwmap::publish(topology);
    // SAFETY: single-CPU one-shot setup; this BSS storage has no reference
    // until the completed PMM is published below.
    let pcp = unsafe {
        PcpStorage::init_in_place(PCP_STORAGE.0.get().cast::<PcpStorage>());
        (&*PCP_STORAGE.0.get()).assume_init_ref()
    };
    let backing = HhdmBacking { hhdm: info.hhdm_offset, bitmaps, pcp };
    // SAFETY: same single-CPU init invariant; we read what we just wrote.
    let regs: &[UsableRegion] = unsafe {
        let base: *const UsableRegion = REGION_BUF.0.get() as *const UsableRegion;
        core::slice::from_raw_parts(base, n_regions)
    };
    // SAFETY: PMM_STORAGE written only here, single-CPU, before
    // PMM_READY flips.
    let pmm_ref: &'static Pmm<HhdmBacking, KernelIrqGate> = unsafe {
        let cell = &mut *PMM_STORAGE.0.get();
        let limits = crate::zone::apply_memory_core_request(
            crate::zone::ZoneLimits::arch_default(pfn_max, PAGE_SIZE_BYTES), cmdline::get(), pfn_max, PAGE_SIZE_BYTES,
        );
        Pmm::<HhdmBacking, KernelIrqGate>::init_zoned_in_place(backing, regs, Some(limits), cell)
            .map_err(SetupError::PmmInit)?;
        cell.assume_init_ref()
    };
    // SAFETY: `page_meta_ptr` names the page-aligned boot reservation carved
    // out above; it has room for exactly `pfn_max` PageMeta values and is not
    // present in any PMM usable region.
    unsafe { super::metadata::init_page_meta_with_native_storage(page_meta_ptr, native_page_ptr, pfn_max as usize); }
    // Stamp MANAGED on exactly the PFNs just seeded into the buddy (`regs`,
    // the same list `Pmm::init` consumed above) so a bare `page_meta().get
    // (pfn)` hit can tell "buddy-managed, currently free" apart from a
    // kernel-image/reserved hole below `pfn_max` that was never seeded —
    // both would otherwise read as identical zeroed metadata.
    for r in regs {
        for off in 0..r.len_pfn {
            let pfn = r.start.0 + off;
            // SAFETY: pfn < pfn_max by construction of `regs` (every entry
            // came from the same Usable-region loop that bounds pfn_max);
            // page_meta_ptr names exactly pfn_max contiguous PageMeta slots,
            // single-CPU init, before PMM_READY flips.
            unsafe {
                (*page_meta_ptr.add(pfn as usize)).flags.store(crate::PageFlags::MANAGED.bits(), Ordering::Relaxed);
            }
        }
    }
    PMM_READY.store(true, Ordering::Release);
    // Linux reserves HugeTLB pages from the early command line before normal
    // boot activity can fragment the buddy allocator. The PMM is fully seeded
    // here, while userspace and ordinary boot allocations have not started.
    crate::hugetlb::initialize_from_cmdline(cmdline::get());
    // Every zone is seeded by this point, so the managed totals the watermarks
    // are proportional to are final. This is the one producer of both the
    // per-zone allocation gate and the aggregate the reclaim policy reads.
    pmm_ref.refresh_watermarks(crate::watermark::tunables::current());
    // A cached page can become a machine frame from the moment there is an
    // allocator to take one from, which is HERE — not at the kernel-only wiring
    // below. A hosted test that brings this PMM up gets the same page cache the
    // machine gets, which is what makes a shared writable mapping of a file
    // checkable without a boot.
    super::install_page_cache_frames();
    #[cfg(target_os = "oxide-kernel")]
    install_oom_accounting(pmm_ref);
    Ok(pmm_ref)
}

/// Wire the OOM selector to the two PMM-owned truths once both the PMM and
/// user page-table observer exist. Hosted PMM tests intentionally have no
/// scheduler OOM runtime to configure.
#[cfg(target_os = "oxide-kernel")]
fn install_oom_accounting(pmm: &Pmm<HhdmBacking, KernelIrqGate>) {
    sched::oom::install_managed_pages(pmm.snapshot().managed_pages);
    sched::oom::install_memory_observer(crate::user_as::oom_memory);
    // Same truth, second consumer: the page cache's dirty thresholds are a
    // percentage of the machine's managed pages (`17§4.3`), and PMM is the
    // only thing that knows that number. Installed here rather than counted
    // again elsewhere.
    block::pagecache::install_totalram_pages(pmm.snapshot().managed_pages);
}

/// Get a `&'static` reference to the PMM after `init_from_boot_info`
/// has run, or `None` if PMM is not yet initialised. Used by bare-fn
/// frame allocators (e.g. the one registered with `MmuOps`) that
/// can't capture state in a closure.
/// # C: O(1)
pub fn pmm_static() -> Option<&'static KernelPmm> {
    if !PMM_READY.load(Ordering::Acquire) { return None; }
    // SAFETY: PMM_READY went true only after the cell was written;
    // no further writes occur. The reference's lifetime is tied to
    // `PMM_STORAGE` which is `'static`.
    Some(unsafe { (*PMM_STORAGE.0.get()).assume_init_ref() })
}
