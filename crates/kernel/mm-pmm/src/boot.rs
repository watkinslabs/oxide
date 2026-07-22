//! Boot-time helpers the kernel wires in (docs/56): the kalloc grow
//! callback (pages from the buddy allocator when the static heap dries)
//! and the memmap dump. The logic lives here in the memory manager; the
//! kernel only installs/calls it.
#[cfg(target_os = "oxide-kernel")]
use crate::{setup, Order, PageFlags};
#[cfg(target_os = "oxide-kernel")]
use core::sync::atomic::Ordering;
#[cfg(target_os = "oxide-kernel")]
const MIB: usize = 1024 * 1024;

/// kalloc grow callback (matches `kalloc::GrowFn`): allocate a
/// power-of-two run (≥1 MiB) from the buddy allocator, return its HHDM VA
/// + size, else None. Mirrors Linux `__get_free_pages(GFP_KERNEL)`.
/// # C: O(MAX_ORDER) bounded
#[cfg(target_os = "oxide-kernel")]
pub fn kalloc_grow(min_extra: usize, memcg: u64) -> Option<(usize, usize)> {
    let pmm = setup::pmm_static()?;
    let hhdm = crate::user_as::hhdm_offset();
    if hhdm == 0 { return None; }
    const PAGE_SIZE: usize = hal::PAGE_SIZE_BYTES as usize;
    const PAGES_PER_MIB: usize = MIB / PAGE_SIZE;
    let mut pages = min_extra.div_ceil(PAGE_SIZE);
    if pages == 0 { pages = 1; }
    if !pages.is_power_of_two() { pages = pages.next_power_of_two(); }
    if pages < PAGES_PER_MIB { pages = PAGES_PER_MIB; }
    let order = pages.trailing_zeros() as u8;
    let bytes = (pages * PAGE_SIZE) as u64;
    if memcg != cgroup::NO_MEMCG
        && !cgroup::try_charge_memory(memcg, cgroup::MemoryKind::SlabUnreclaimable, bytes) {
        return None;
    }
    let pfn = match pmm.alloc(Order(order)) {
        Ok(pfn) => pfn,
        Err(_) => {
            if memcg != cgroup::NO_MEMCG {
                cgroup::uncharge_memory(memcg, cgroup::MemoryKind::SlabUnreclaimable, bytes);
            }
            return None;
        }
    };
    // Heap arenas are permanent PMM allocations.  Classify every constituent
    // frame before handing the run to kalloc: generic object/page free paths
    // must never be able to return it to the buddy.  This is the same single
    // struct-page ownership truth used for PageSlab in Linux.
    let meta = setup::page_meta().expect("PMM heap growth before PageMeta publication");
    for offset in 0..pages as u64 {
        let frame = hal::Pfn(pfn.0 + offset);
        let page = meta.get(frame).expect("PMM heap growth outside PageMeta range");
        assert_eq!(page.refcount.compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire), Ok(0),
            "PMM heap growth received referenced frame");
        let old = page.flags.fetch_or(PageFlags::KHEAP.bits(), Ordering::AcqRel);
        assert_eq!(old & PageFlags::KHEAP.bits(), 0, "PMM heap growth received KHEAP frame");
        // `free_one_frame` scrubs mapcount/mapping on every mechanical free
        // path, but `free_contig` does not — a frame freed through it while
        // still (wrongly) mapped would carry a live PTE straight into the
        // kernel heap. refcount==0 alone doesn't catch that: a caller-side
        // refcount/mapcount pairing bug can zero refcount while mapcount
        // stays nonzero. Assert both are clean before this frame becomes
        // heap-backing memory — turns a silent "dirty frame in the heap"
        // into a located panic naming the frame, not a random downstream
        // victim three allocations later.
        assert_eq!(page.mapcount.load(Ordering::Acquire), 0, "PMM heap growth received mapped frame");
        assert!(page.mapping.load(Ordering::Acquire).is_null(), "PMM heap growth received frame with live mapping");
    }
    let pa = (pfn.0 as usize) * PAGE_SIZE;
    let va = hhdm.wrapping_add(pa as u64) as usize;
    Some((va, pages * PAGE_SIZE))
}

/// `kalloc::CorruptionProbeFn` callback: given the VA of a free-list node
/// `HoleList::validate`/`try_merge` found corrupted, check whether its
/// backing physical frame's struct-page metadata looks abnormal (mapped
/// somewhere, referenced, or missing the KHEAP classification a kalloc
/// heap-growth frame must carry) — a real double-mapped-frame /
/// wild-cross-write would show up here directly, distinct from every
/// other diagnostic this hunt has tried, which only ever inspect the
/// corrupted bytes themselves, never the frame's OWNERSHIP metadata.
///
/// Only resolves addresses inside the HHDM-mapped PMM-growth heap
/// (`addr >= hhdm_offset` AND the resulting PFN is within this system's
/// actual managed range); the static BSS heap's addresses are ordinary
/// kernel-image VAs this crate has no VA->PFN reverse map for, so those
/// are reported as unresolved rather than guessed at. The `addr >=
/// hhdm_offset` check alone is NOT sufficient to distinguish the two: a
/// kernel-image VA (e.g. `0xffffffff8...`) can be numerically >= a small
/// `hhdm_offset`, producing a PFN wildly beyond the system's real page
/// count — checked explicitly against `Pmm::pfn_max()` rather than
/// silently reported as a confusing "out-of-range" from the page-meta
/// lookup below (first caught live: B1322's initial version misreported
/// a static-heap VA this way).
/// # C: O(1)
#[cfg(all(target_os = "oxide-kernel", feature = "debug-heappoison"))]
pub fn corruption_probe(addr: u64) {
    let hhdm = crate::user_as::hhdm_offset();
    let pfn_max = setup::pmm_static().map(|p| p.pfn_max());
    let in_hhdm_range = hhdm != 0 && addr >= hhdm
        && pfn_max.is_some_and(|max| (addr - hhdm) / hal::PAGE_SIZE_BYTES < max);
    if !in_hhdm_range {
        klog::write_primary_raw(b"[KALLOC] corruption-probe addr=");
        klog::write_primary_hex_u64(addr);
        klog::write_primary_raw(b" unresolved (not an HHDM address -- static-heap/kernel-image VA, no PFN map)\n");
        return;
    }
    let pa = addr - hhdm;
    let pfn = hal::Pfn(pa / hal::PAGE_SIZE_BYTES);
    let Some(meta) = setup::page_meta() else {
        klog::write_primary_raw(b"[KALLOC] corruption-probe addr=");
        klog::write_primary_hex_u64(addr);
        klog::write_primary_raw(b" pfn=");
        klog::write_primary_hex_u64(pfn.0);
        klog::write_primary_raw(b" page-meta-unavailable\n");
        return;
    };
    let Some(page) = meta.get(pfn) else {
        klog::write_primary_raw(b"[KALLOC] corruption-probe addr=");
        klog::write_primary_hex_u64(addr);
        klog::write_primary_raw(b" pfn=");
        klog::write_primary_hex_u64(pfn.0);
        klog::write_primary_raw(b" out-of-range\n");
        return;
    };
    let refcount = page.refcount.load(Ordering::Acquire);
    let mapcount = page.mapcount.load(Ordering::Acquire);
    let flags = page.flags.load(Ordering::Acquire);
    klog::write_primary_raw(b"[KALLOC] corruption-probe addr=");
    klog::write_primary_hex_u64(addr);
    klog::write_primary_raw(b" pfn=");
    klog::write_primary_hex_u64(pfn.0);
    klog::write_primary_raw(b" refcount=");
    klog::write_primary_dec_u64(refcount as u64);
    klog::write_primary_raw(b" mapcount=");
    klog::write_primary_dec_u64(mapcount as u64);
    klog::write_primary_raw(b" flags=");
    klog::write_primary_hex_u64(flags as u64);
    klog::write_primary_raw(b" kheap=");
    klog::write_primary_dec_u64((flags & PageFlags::KHEAP.bits()) as u64);
    klog::write_primary_raw(b"\n");
}

/// Map `BootMemKind` to a short ASCII tag for memmap dumps.
#[cfg(feature = "debug-pmm")]
fn kind_tag(k: boot_info::BootMemKind) -> &'static [u8] {
    use boot_info::BootMemKind::*;
    match k {
        Usable => b"USABLE", Reserved => b"RESV  ", AcpiReclaim => b"ACPI-R",
        AcpiNvs => b"ACPI-N", BadMem => b"BAD   ", BootloaderUsed => b"BL-USE",
        KernelImage => b"KERNEL", Initramfs => b"INITRD",
    }
}

/// Emit one line per memmap region + totals. Cheap O(N) at boot.
/// # C: O(N regions)
#[cfg(feature = "debug-pmm")]
pub fn log_memmap(regions: &[boot_info::BootMemRegion]) {
    use boot_info::BootMemKind;
    let (mut usable, mut reserved, mut bootloader): (u64, u64, u64) = (0, 0, 0);
    for r in regions {
        klog::write_raw(b"[INFO]    "); klog::write_raw(kind_tag(r.kind));
        klog::write_raw(b" base="); klog::write_hex_u64(r.base_pa);
        klog::write_raw(b" len="); klog::write_hex_u64(r.len); klog::write_raw(b"\n");
        match r.kind {
            BootMemKind::Usable => usable = usable.saturating_add(r.len),
            BootMemKind::BootloaderUsed => bootloader = bootloader.saturating_add(r.len),
            _ => reserved = reserved.saturating_add(r.len),
        }
    }
    klog::write_raw(b"[INFO]    memmap totals: ");
    klog::write_dec_u64(usable / MIB as u64); klog::write_raw(b" MiB usable, ");
    klog::write_dec_u64(bootloader / MIB as u64); klog::write_raw(b" MiB bootloader-reclaim, ");
    klog::write_dec_u64(reserved / MIB as u64); klog::write_raw(b" MiB reserved\n");
}
