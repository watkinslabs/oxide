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
