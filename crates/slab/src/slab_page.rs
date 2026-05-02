// Slab page layout per `12§3.1`. 4 KiB page; header at offset 0;
// objects start at `obj_offset`; per-page intrusive freelist via
// u16 offsets (not pointers — corruption-detectable per `12§3.1`).

use core::ptr;

/// Header byte size. Reserved at the start of every slab page so the
/// list links + freelist head + per-page metadata live there.
pub(crate) const HEADER_SIZE: usize = 64;

/// Sentinel for "no next free object" inside a page.
pub(crate) const NULL_OFF: u16 = u16::MAX;

/// Poison cookie at offset 0 of every FREE object slot. Distinct from
/// the PMM's `0xDEADBEEFCAFEBABE` so corruption between layers is
/// distinguishable.
const OBJ_POISON: u64 = 0xCAFE_F00D_DEAD_BEEF;

/// Public re-export of `OBJ_POISON` for `Cache::free`'s common-path
/// double-free check. Same magic; pub(crate) for crate consumers.
pub(crate) const OBJ_POISON_MAGIC_PUB: u64 = OBJ_POISON;

/// Fill byte for the body of a freed object beyond the poison/offset
/// header. Allocator writes this on free; alloc-time check against it
/// is feature-gated (debug-alloc per `12§8`).
const FREED_FILL: u8 = 0xDD;

/// Header offsets within the slab page. Layout fits in 64 B.
const OFF_CACHE_ID: usize = 0;       // u32
const OFF_NR_OBJS: usize = 4;        // u16
const OFF_FREE_COUNT: usize = 6;     // u16
const OFF_NEXT_FREE_OFF: usize = 8;  // u16
const OFF_OBJ_SIZE: usize = 10;      // u16
const OFF_OBJ_ALIGN: usize = 12;     // u16
const OFF_OBJ_OFFSET: usize = 14;    // u16
const OFF_SELF_PFN: usize = 16;      // u64
const OFF_PARTIAL_NEXT: usize = 24;  // u64 — pfn of next partial slab
const OFF_PARTIAL_PREV: usize = 32;  // u64 — pfn of prev partial slab
const OFF_DRAINED_NEXT: usize = 40;  // u64 — pfn of next drained slab

/// Slot internal layout (when free):
///   [0..8)  poison cookie (OBJ_POISON)
///   [8..10) next-free offset (u16, 0xFFFF = end)
///   [10..)  freed-fill (0xDD)
const SLOT_OFF_POISON: usize = 0;
const SLOT_OFF_NEXT: usize = 8;
const SLOT_OFF_BODY: usize = 10;

/// View into a slab page. Owns no storage; just a `*mut u8` cursor.
pub(crate) struct SlabPage {
    base: *mut u8,
}

impl SlabPage {
    /// Wrap a page-aligned pointer for header / freelist access.
    /// # C: O(1)
    #[inline]
    pub(crate) fn from_raw(base: *mut u8) -> Self { Self { base } }

    /// Initialize an empty (all-free) slab page.
    ///
    /// # SAFETY: caller owns the page (just allocated from PMM); `base`
    /// is page-aligned for `PAGE_SIZE_BYTES`. Layout params consistent.
    pub(crate) unsafe fn init(
        base: *mut u8,
        self_pfn: u64,
        cache_id: u32,
        obj_size: u16,
        obj_align: u16,
        nr_objs: u16,
        obj_offset: u16,
    ) {
        let p = SlabPage { base };
        // SAFETY: header is 64B inside the 4 KiB caller-owned page.
        unsafe {
            p.write_u32(OFF_CACHE_ID, cache_id);
            p.write_u16(OFF_NR_OBJS, nr_objs);
            p.write_u16(OFF_FREE_COUNT, nr_objs);
            p.write_u16(OFF_NEXT_FREE_OFF, obj_offset);  // first free slot
            p.write_u16(OFF_OBJ_SIZE, obj_size);
            p.write_u16(OFF_OBJ_ALIGN, obj_align);
            p.write_u16(OFF_OBJ_OFFSET, obj_offset);
            p.write_u64(OFF_SELF_PFN, self_pfn);
            p.write_u64(OFF_PARTIAL_NEXT, u64::MAX);
            p.write_u64(OFF_PARTIAL_PREV, u64::MAX);
            p.write_u64(OFF_DRAINED_NEXT, u64::MAX);
        }
        // Build the freelist: each slot's next-offset points to slot+1,
        // last points to NULL_OFF. Stamp poison + freed-fill at every slot.
        for i in 0..nr_objs {
            let slot_off = obj_offset as usize + (i as usize) * obj_size as usize;
            let next_off = if i + 1 == nr_objs {
                NULL_OFF
            } else {
                (slot_off + obj_size as usize) as u16
            };
            // SAFETY: slot is inside caller-owned page; obj_size pre-validated.
            unsafe { p.stamp_free_slot(slot_off, next_off, obj_size as usize) };
        }
    }

    /// Stamp slot's poison cookie + freed-fill at `slot_off` on a
    /// caller-owned page (used by `Cache::free` common path before the
    /// fast-path magazine push).
    ///
    /// # SAFETY: `slot_off` is a valid slot offset inside cache-owned page.
    pub(crate) unsafe fn stamp_obj_freed(&self, slot_off: u16, obj_size: usize) {
        // SAFETY: caller-validated slot inside cache-owned page.
        unsafe { self.stamp_free_slot(slot_off as usize, NULL_OFF, obj_size) };
    }

    /// Read slot poison cookie. Used by `Cache::free` to detect
    /// double-free before stamping.
    ///
    /// # SAFETY: `slot_off` is a valid slot offset inside cache-owned page.
    pub(crate) unsafe fn read_obj_poison(&self, slot_off: u16) -> u64 {
        // SAFETY: header lives in first 8 B of the slot inside cache-owned page.
        unsafe { self.read_u64_at(slot_off as usize + SLOT_OFF_POISON) }
    }

    /// Clear slot poison cookie (used by fast-path alloc to take a
    /// magazine slot out of "freed" state).
    ///
    /// # SAFETY: `slot_off` is a valid slot offset inside cache-owned page.
    pub(crate) unsafe fn clear_obj_poison(&self, slot_off: u16) {
        // SAFETY: writing 8 B inside slot inside cache-owned page.
        unsafe { self.write_u64_at(slot_off as usize + SLOT_OFF_POISON, 0) };
    }


    /// Pop the head of the free-list. Verifies poison cookie (panic on
    /// mismatch — corruption per `12§1` I3); clears cookie so the slot
    /// no longer reads as free. Returns the slot offset.
    ///
    /// # SAFETY: caller holds the cache lock; page is cache-owned.
    pub(crate) unsafe fn pop_free_obj(&self, _obj_size: usize) -> u16 {
        // SAFETY: header inside cache-owned page.
        let head = unsafe { self.read_u16(OFF_NEXT_FREE_OFF) };
        debug_assert!(head != NULL_OFF, "pop from empty freelist");
        // SAFETY: slot offset taken from freelist head; head is a valid slot inside cache-owned page.
        let cookie = unsafe { self.read_u64_at(head as usize + SLOT_OFF_POISON) };
        if cookie != OBJ_POISON {
            panic!("slab corruption: obj poison mismatch on alloc");
        }
        // SAFETY: head is a valid slot offset inside the page.
        let next = unsafe { self.read_u16_at(head as usize + SLOT_OFF_NEXT) };
        // Clear the poison cookie so subsequent free of this slot does
        // not misread "still has poison" as a double-free.
        // SAFETY: writing into slot inside cache-owned page.
        unsafe { self.write_u64_at(head as usize + SLOT_OFF_POISON, 0) };
        // SAFETY: writing OFF_NEXT_FREE_OFF inside cache-owned page header.
        unsafe { self.write_u16(OFF_NEXT_FREE_OFF, next) };
        // SAFETY: reading OFF_FREE_COUNT inside cache-owned page header.
        let fc = unsafe { self.read_u16(OFF_FREE_COUNT) };
        // SAFETY: writing OFF_FREE_COUNT inside cache-owned page header.
        unsafe { self.write_u16(OFF_FREE_COUNT, fc - 1) };
        head
    }

    /// Push `slot_off` onto the head of the slab page's free-list.
    /// **Cookie management moves to the common-path `Cache::free`** —
    /// poison stamping + double-free detection happen before mag
    /// push or this slow-path call. This fn does freelist mechanics
    /// only: link in, increment free_count.
    ///
    /// # SAFETY: caller holds the cache lock; page is cache-owned;
    /// slot at `slot_off` has already been poison-stamped by the
    /// common-path free + the slot's `next` u16 must be writable.
    pub(crate) unsafe fn push_free_obj(&self, slot_off: u16, _obj_size: usize) {
        // SAFETY: header read inside cache-owned 4 KiB page; OFF_NEXT_FREE_OFF in 64 B header.
        let head = unsafe { self.read_u16(OFF_NEXT_FREE_OFF) };
        // SAFETY: writing slot's next-free-off inside cache-owned page.
        unsafe { self.write_u16_at(slot_off as usize + SLOT_OFF_NEXT, head) };
        // SAFETY: writing OFF_NEXT_FREE_OFF inside cache-owned page header.
        unsafe { self.write_u16(OFF_NEXT_FREE_OFF, slot_off) };
        // SAFETY: reading OFF_FREE_COUNT inside cache-owned page header.
        let fc = unsafe { self.read_u16(OFF_FREE_COUNT) };
        // SAFETY: writing OFF_FREE_COUNT inside cache-owned page header.
        unsafe { self.write_u16(OFF_FREE_COUNT, fc + 1) };
    }

    /// # SAFETY: page is cache-owned.
    pub(crate) unsafe fn free_count(&self) -> u16 {
        // SAFETY: header read inside owned page.
        unsafe { self.read_u16(OFF_FREE_COUNT) }
    }

    /// # SAFETY: page is cache-owned.
    pub(crate) unsafe fn partial_links(&self) -> (u64, u64) {
        // SAFETY: header reads inside owned page.
        unsafe { (self.read_u64(OFF_PARTIAL_NEXT), self.read_u64(OFF_PARTIAL_PREV)) }
    }

    /// # SAFETY: page is cache-owned.
    pub(crate) unsafe fn set_partial_links(&self, next: u64, prev: u64) {
        // SAFETY: header writes inside owned page.
        unsafe {
            self.write_u64(OFF_PARTIAL_NEXT, next);
            self.write_u64(OFF_PARTIAL_PREV, prev);
        }
    }

    /// # SAFETY: page is cache-owned.
    pub(crate) unsafe fn set_partial_next(&self, next: u64) {
        // SAFETY: header write inside owned page.
        unsafe { self.write_u64(OFF_PARTIAL_NEXT, next) };
    }

    /// # SAFETY: page is cache-owned.
    pub(crate) unsafe fn set_partial_prev(&self, prev: u64) {
        // SAFETY: header write inside owned page.
        unsafe { self.write_u64(OFF_PARTIAL_PREV, prev) };
    }

    /// # SAFETY: page is cache-owned.
    pub(crate) unsafe fn set_drained_link(&self, next: u64) {
        // SAFETY: header write inside owned page.
        unsafe { self.write_u64(OFF_DRAINED_NEXT, next) };
    }

    /// Pop the drained-list link from this slab and return it.
    ///
    /// # SAFETY: page is cache-owned.
    pub(crate) unsafe fn pop_drained_link(&self) -> u64 {
        // SAFETY: reading OFF_DRAINED_NEXT inside cache-owned page header.
        let next = unsafe { self.read_u64(OFF_DRAINED_NEXT) };
        // SAFETY: clearing OFF_DRAINED_NEXT inside cache-owned page header.
        unsafe { self.write_u64(OFF_DRAINED_NEXT, u64::MAX) };
        next
    }

    /// Read the `self_pfn` stamp from a page-aligned address. Used by
    /// `Cache::free` to identify the slab from an obj pointer alone.
    ///
    /// # SAFETY: `addr` is page-aligned and points to a slab page that
    /// belongs to a Cache (verified subsequently via cache_id check).
    pub(crate) unsafe fn read_self_pfn_from_addr(addr: *const u8) -> u64 {
        // SAFETY: addr is page-aligned, header at offset 0 is 64 B.
        unsafe { ptr::read_unaligned(addr.add(OFF_SELF_PFN) as *const u64) }
    }

    /// Read `cache_id` from a page-aligned address.
    ///
    /// # SAFETY: as above.
    pub(crate) unsafe fn read_cache_id_from_addr(addr: *const u8) -> u32 {
        // SAFETY: addr is page-aligned, header at offset 0 is 64 B.
        unsafe { ptr::read_unaligned(addr.add(OFF_CACHE_ID) as *const u32) }
    }

    // ----- internal -----

    #[inline]
    unsafe fn stamp_free_slot(&self, slot_off: usize, next_off: u16, obj_size: usize) {
        // SAFETY: slot inside owned page; obj_size validated by Cache::new.
        unsafe {
            self.write_u64_at(slot_off + SLOT_OFF_POISON, OBJ_POISON);
            self.write_u16_at(slot_off + SLOT_OFF_NEXT, next_off);
            // Fill body with FREED_FILL (after the 10-byte header bytes).
            let body_off = slot_off + SLOT_OFF_BODY;
            let body_len = obj_size.saturating_sub(SLOT_OFF_BODY);
            ptr::write_bytes(self.base.add(body_off), FREED_FILL, body_len);
        }
    }

    #[inline]
    unsafe fn write_u64(&self, off: usize, v: u64) {
        // SAFETY: off + 8 inside the 64 B header inside cache-owned page.
        unsafe { ptr::write_unaligned(self.base.add(off) as *mut u64, v) }
    }
    #[inline]
    unsafe fn write_u32(&self, off: usize, v: u32) {
        // SAFETY: off + 4 inside the 64 B header inside cache-owned page.
        unsafe { ptr::write_unaligned(self.base.add(off) as *mut u32, v) }
    }
    #[inline]
    unsafe fn write_u16(&self, off: usize, v: u16) {
        // SAFETY: off + 2 inside the 64 B header inside cache-owned page.
        unsafe { ptr::write_unaligned(self.base.add(off) as *mut u16, v) }
    }
    #[inline]
    unsafe fn read_u64(&self, off: usize) -> u64 {
        // SAFETY: off + 8 inside the 64 B header inside cache-owned page.
        unsafe { ptr::read_unaligned(self.base.add(off) as *const u64) }
    }
    #[inline]
    unsafe fn read_u16(&self, off: usize) -> u16 {
        // SAFETY: off + 2 inside the 64 B header inside cache-owned page.
        unsafe { ptr::read_unaligned(self.base.add(off) as *const u16) }
    }
    #[inline]
    unsafe fn write_u16_at(&self, off: usize, v: u16) {
        // SAFETY: off + 2 inside cache-owned page; obj_size validated.
        unsafe { ptr::write_unaligned(self.base.add(off) as *mut u16, v) }
    }
    #[inline]
    unsafe fn write_u64_at(&self, off: usize, v: u64) {
        // SAFETY: off + 8 inside cache-owned page; obj_size validated.
        unsafe { ptr::write_unaligned(self.base.add(off) as *mut u64, v) }
    }
    #[inline]
    unsafe fn read_u16_at(&self, off: usize) -> u16 {
        // SAFETY: off + 2 inside cache-owned page; obj_size + slot validated.
        unsafe { ptr::read_unaligned(self.base.add(off) as *const u16) }
    }
    #[inline]
    unsafe fn read_u64_at(&self, off: usize) -> u64 {
        // SAFETY: off + 8 inside cache-owned page; obj_size + slot validated.
        unsafe { ptr::read_unaligned(self.base.add(off) as *const u64) }
    }
}
