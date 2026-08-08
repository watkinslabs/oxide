use super::*;
const PAGE_BYTES: u64 = hal::PAGE_SIZE_BYTES;
const ALLOCATOR_INTEGRITY_RETRY_COUNT: usize = 64;
#[cfg(feature = "debug-cow")]
use super::metadata::cow_dbg_rmap_report;

fn alloc_frame_with_meta(refcount: u32, mapcount: u32) -> Option<u64> {
    use core::sync::atomic::Ordering;
    let p = pmm_static()?;
    // Linux page-allocator invariant: a frame on the free list is
    // unreferenced — its struct-page refcount
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
        if let Some(meta) = page_meta() {
            if let Some(m) = meta.get(hal::Pfn(pa / PAGE_BYTES)) {
                let rc = m.refcount.load(Ordering::Acquire);
                let flags = crate::PageFlags::from_bits_retain(m.flags.load(Ordering::Acquire));
                // A KHEAP frame appearing on a buddy free list is an ownership
                // violation. Do not silently skip it: leaving it classified
                // while allocating another frame would preserve a corrupted
                // PMM truth and make later failure nondeterministic.
                if flags.contains(crate::PageFlags::KHEAP) {
                    kassert!(false, "kernel-heap frame returned by buddy");
                }
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

/// Allocate and publish one PMM-owned movable object page. # C: O(pages)
pub fn alloc_movable_object_frame(owner: movable::OwnerId) -> Option<u64> {
    let pa = alloc_object_frame()?;
    if crate::movable::publish(owner, pa).is_ok() { Some(pa) }
    else { release_object_frame(pa); None }
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

/// Release an unreachable PMM movable object page. # C: O(pages)
pub fn release_movable_object_frame(owner: movable::OwnerId, pa: u64) -> bool {
    if crate::movable::release(owner, pa).is_err() { return false; }
    release_object_frame(pa);
    true
}

/// Migrate one registered movable object page to a fresh PMM frame. # C: O(pages)
pub fn migrate_movable_object_frame(pa: u64, mode: movable::Mode) -> Result<u64, movable::MoveError> {
    if !super::metadata::try_lock_page(pa) { return Err(movable::MoveError::Busy); }
    let Some(destination) = alloc_object_frame() else { let _ = super::metadata::unlock_page(pa); return Err(movable::MoveError::Busy); };
    if !super::metadata::try_lock_page(destination) { release_object_frame(destination); let _ = super::metadata::unlock_page(pa); return Err(movable::MoveError::Busy); }
    let result = crate::movable::migrate(pa, destination, mode);
    let _ = super::metadata::unlock_page(destination);
    let _ = super::metadata::unlock_page(pa);
    match result {
        Ok(()) => { release_object_frame(pa); Ok(destination) }
        Err(error) => { release_object_frame(destination); Err(error) }
    }
}
