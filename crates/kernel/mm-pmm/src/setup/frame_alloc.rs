use super::*;
const PAGE_BYTES: u64 = hal::PAGE_SIZE_BYTES;
const PAGE_BYTES_USIZE: usize = hal::PAGE_SIZE_BYTES as usize;
const ALLOCATOR_INTEGRITY_RETRY_COUNT: usize = 64;
#[cfg(feature = "debug-cow")]
use super::metadata::cow_dbg_rmap_report;

fn alloc_frame_with_meta(refcount: u32, mapcount: u32) -> Option<u64> {
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
    for _ in 0..ALLOCATOR_INTEGRITY_RETRY_COUNT {
        let Some(pa) = p.alloc(crate::Order(0)).ok().map(|pfn| pfn.0 * PAGE_BYTES) else {
            break;
        };
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
                let tail_poison = (0..16).all(|i| unsafe { core::ptr::read_volatile(base.add(PAGE_BYTES_USIZE - 16 + i)) } == 0xAA);
                if tail_poison {
                    for off in 0..PAGE_BYTES_USIZE - 16 {
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
                let tail_poison = (0..16).all(|i| unsafe { core::ptr::read_volatile(base.add(PAGE_BYTES_USIZE - 16 + i)) } == 0xCC);
                if tail_poison {
                    for off in 0..PAGE_BYTES_USIZE - 16 {
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
            if let Some(m) = meta.get(hal::Pfn(pa / PAGE_BYTES)) {
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
                    let pfn = pa / PAGE_BYTES;
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
                m.refcount.store(refcount, Ordering::Release);
                m.mapcount.store(mapcount, Ordering::Release);
            }
        }
        return Some(pa);
    }
    None
}

/// Allocate a frame for a user PTE that will be installed by the caller.
/// The returned frame starts with one struct-page reference and one live
/// mapping, matching the immediately-following PTE install in the fault path.
/// # C: O(1) amortised (PMM buddy alloc).
pub fn alloc_one_frame() -> Option<u64> {
    alloc_frame_with_meta(1, 1)
}

/// Allocate a frame owned by a kernel object, not by a user PTE.
/// Examples: shmem/tmpfs inode storage and vvar. The object holds one
/// refcount reference; user mappings of the object must call `inc_ref`,
/// which bumps both refcount and mapcount for each PTE.
/// # C: O(1) amortised (PMM buddy alloc).
pub fn alloc_object_frame() -> Option<u64> {
    alloc_frame_with_meta(1, 0)
}

/// Allocate a raw kernel frame with no PageMeta ownership. Used for page
/// tables and device rings that are freed directly with `free_one_frame`
/// and are never normal user leaves.
/// # C: O(1) amortised (PMM buddy alloc).
pub fn alloc_raw_frame() -> Option<u64> {
    alloc_frame_with_meta(0, 0)
}

/// Kernel/hosted pointer for a frame owned by the caller.
///
/// In the kernel this resolves through the HHDM-backed PMM; in hosted tests it
/// resolves through the test backing. Callers must own the frame.
/// # C: O(1)
pub fn frame_ptr(pa: u64) -> Option<*mut u8> {
    let p = pmm_static()?;
    // SAFETY: caller owns the frame; Pmm::page_ptr validates only by backing
    // arithmetic and is the common kernel/hosted translation point.
    Some(unsafe { p.page_ptr(crate::Pfn(pa / PAGE_BYTES)) })
}

/// Release one PMM page held solely by a movable kernel object such as a
/// zsmalloc zspage. It has no user PTE mapping; its object reference is the
/// canonical lifetime owner. # C: O(1) amortised
pub fn release_object_frame(pa: u64) {
    // SAFETY: zsmalloc calls this only after its table no longer exposes the
    // frame and after its provider page lock has been released.
    unsafe { super::refs::dec_object_ref_and_maybe_free_frame(pa); }
}
