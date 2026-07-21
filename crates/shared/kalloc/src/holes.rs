// Sorted hole-list allocator (linked_list_allocator-style).
//
// Each free region carries a header at its start: `{ size, next }`. The
// list is kept sorted by address so dealloc can coalesce adjacent
// regions in `O(N)`. First-fit on alloc.
//
// Bounded waste: up to `MIN_HOLE_SIZE - 1` bytes can be absorbed into
// an allocation when the back padding is too small to host a fresh
// header — those bytes are lost until an adjacent free merges them
// back in. Over a 16 MiB heap this is negligible (`< 1 MiB` worst case
// across `≥ 64 K` allocations) and the allocator is replaced by a
// PMM-backed slab router (`12§2`) once a kernel binary stage exists.

use core::alloc::Layout;
use core::cmp::max;
use core::mem;
use core::ptr::NonNull;

/// Rejection reason for a free-list mutation that would violate ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HoleListError {
    /// Region arithmetic overflowed the machine address space.
    AddressOverflow,
    /// A linked node cannot describe a valid, strictly ordered free region.
    MalformedNode,
    /// The requested free region intersects a region already owned by the list.
    OverlappingFree,
    /// A free-list node lies outside allocator-owned backing memory.
    OutsideOwnedRegion,
}

/// Each free region begins with this header. `size` is the region's
/// total byte length including the header itself.
#[repr(C)]
pub struct HoleHdr {
    pub size: usize,
    pub next: Option<NonNull<HoleHdr>>,
}

/// Permanent metadata for one allocator-owned backing region. This prefix is
/// never returned to callers, so free-list corruption cannot alter it.
#[repr(C)]
struct RegionHdr {
    end: usize,
    next: Option<NonNull<RegionHdr>>,
}

/// Minimum size of a free region (must hold at least the header).
pub const MIN_HOLE_SIZE: usize = mem::size_of::<HoleHdr>();
/// Minimum alignment of a free region's start.
pub const MIN_HOLE_ALIGN: usize = mem::align_of::<HoleHdr>();
/// Reserved prefix for one backing-region descriptor, rounded for hole starts.
const REGION_HEADER_SIZE: usize = (mem::size_of::<RegionHdr>() + MIN_HOLE_ALIGN - 1) & !(MIN_HOLE_ALIGN - 1);

/// Round `addr` up to the next multiple of `align`. `align` must be a
/// power of two.
#[inline]
fn align_up(addr: usize, align: usize) -> Option<usize> {
    addr.checked_add(align - 1).map(|v| v & !(align - 1))
}

/// Sorted singly-linked list of free regions. The list is owned by
/// `HoleList`; `KAlloc` wraps it in a `Spinlock`.
pub struct HoleList {
    /// Sentinel header so all "list head" updates go through `next`,
    /// without a separate `head: Option<...>` case.
    first: HoleHdr,
    /// Region descriptors live in reserved prefixes of their backing ranges.
    regions: Option<NonNull<RegionHdr>>,
}

// SAFETY: `HoleList` mediates exclusive access to the heap region via
// the outer `Spinlock`; the `NonNull<HoleHdr>` chain only points into
// memory owned by the list, which the user reserves once at init.
unsafe impl Send for HoleList {}

impl HoleList {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { first: HoleHdr { size: 0, next: None }, regions: None }
    }

    /// Register an allocator-owned backing range and insert its usable suffix.
    /// The descriptor stays outside every allocation for the range lifetime.
    /// # SAFETY: caller exclusively owns the whole range for this allocator.
    /// # C: O(regions + holes)
    pub unsafe fn add_region(&mut self, addr: usize, size: usize) -> Result<(), HoleListError> {
        let aligned = align_up(addr, MIN_HOLE_ALIGN).ok_or(HoleListError::AddressOverflow)?;
        let skipped = aligned - addr;
        if skipped >= size { return Err(HoleListError::MalformedNode); }
        let size = (size - skipped) & !(MIN_HOLE_ALIGN - 1);
        let end = aligned.checked_add(size).ok_or(HoleListError::AddressOverflow)?;
        let usable = aligned.checked_add(REGION_HEADER_SIZE).ok_or(HoleListError::AddressOverflow)?;
        if end.checked_sub(usable).unwrap_or(0) < MIN_HOLE_SIZE { return Err(HoleListError::MalformedNode); }
        let mut region = self.regions;
        while let Some(node) = region {
            // SAFETY: region descriptors occupy reserved prefixes and only this
            // list mutates their links while the outer allocator lock is held.
            let existing = unsafe { node.as_ref() };
            let existing_start = node.as_ptr() as usize;
            if existing_start < end && aligned < existing.end { return Err(HoleListError::OverlappingFree); }
            region = existing.next;
        }
        let hdr = aligned as *mut RegionHdr;
        // SAFETY: `aligned` starts the caller-owned range and is never exposed
        // as allocatable storage after this descriptor is installed.
        unsafe { hdr.write(RegionHdr { end, next: self.regions }) };
        // SAFETY: `hdr` is aligned and initialized by the preceding write.
        self.regions = Some(unsafe { NonNull::new_unchecked(hdr) });
        // SAFETY: the usable suffix is contained in the freshly registered range.
        unsafe { self.add_free_region(usable, end - usable) }
    }

    /// True when `[start, end)` is allocatable storage in one registered region.
    /// # C: O(regions)
    fn owns_range(&self, start: usize, end: usize) -> bool {
        if start >= end { return false; }
        let mut region = self.regions;
        while let Some(node) = region {
            // SAFETY: descriptors are in permanently reserved backing prefixes,
            // never in a free block or a caller-visible allocation.
            let current = unsafe { node.as_ref() };
            let usable = (node.as_ptr() as usize).checked_add(REGION_HEADER_SIZE);
            if usable.is_some_and(|base| start >= base && end <= current.end) { return true; }
            region = current.next;
        }
        false
    }

    /// Validate a readable free-list header without trusting in-band links.
    /// # C: O(regions)
    fn owns_header(&self, addr: usize) -> bool {
        addr % MIN_HOLE_ALIGN == 0
            && addr.checked_add(MIN_HOLE_SIZE).is_some_and(|end| self.owns_range(addr, end))
    }

    /// Insert a free region `[addr, addr + size)` into the list.
    ///
    /// # SAFETY: caller asserts the byte range is valid, exclusively
    /// owned by this allocator, and not overlapping any other free
    /// region or live allocation. Used at init and from `dealloc`.
    /// # C: O(N)
    pub unsafe fn add_free_region(&mut self, addr: usize, size: usize) -> Result<(), HoleListError> {
        // Round addr up to header alignment; round size down accordingly.
        let aligned = align_up(addr, MIN_HOLE_ALIGN).ok_or(HoleListError::AddressOverflow)?;
        let drop = aligned - addr;
        if drop >= size { return Err(HoleListError::MalformedNode); }
        let mut size = size - drop;
        size &= !(MIN_HOLE_ALIGN - 1);
        if size < MIN_HOLE_SIZE { return Err(HoleListError::MalformedNode); }
        let end = aligned.checked_add(size).ok_or(HoleListError::AddressOverflow)?;
        if !self.owns_range(aligned, end) { return Err(HoleListError::OutsideOwnedRegion); }

        // Walk and validate before writing the candidate header. Writing first
        // lets a duplicate free overwrite its existing header and create a
        // self-loop, which later makes `alloc` dereference arbitrary metadata.
        let mut prev: *mut HoleHdr = &mut self.first;
        let mut prev_addr = None;
        loop {
            // SAFETY: `prev` is initialized to `&mut self.first` and
            // thereafter only advanced through `(*prev).next` pointers
            // that we ourselves inserted; every dereference targets a
            // header we own.
            let next = unsafe { (*prev).next };
            match next {
                Some(n) => {
                    let cur = n.as_ptr() as usize;
                    if !self.owns_header(cur) || prev_addr.is_some_and(|last| cur <= last) {
                        return Err(HoleListError::MalformedNode);
                    }
                    // SAFETY: alignment and strict ordering validate the link;
                    // the outer list contract gives this node readable metadata.
                    let cur_size = unsafe { (*n.as_ptr()).size };
                    if cur_size < MIN_HOLE_SIZE || cur_size % MIN_HOLE_ALIGN != 0 {
                        return Err(HoleListError::MalformedNode);
                    }
                    let cur_end = cur.checked_add(cur_size).ok_or(HoleListError::AddressOverflow)?;
                    if !self.owns_range(cur, cur_end) { return Err(HoleListError::OutsideOwnedRegion); }
                    if cur_end > aligned && cur < end {
                        return Err(HoleListError::OverlappingFree);
                    }
                    if cur >= end { break; }
                    prev_addr = Some(cur);
                    prev = n.as_ptr();
                }
                None => break,
            }
        }

        let new_ptr = aligned as *mut HoleHdr;
        // SAFETY: validation above proved this range is disjoint from all
        // list-owned free regions; the caller owns this writable region.
        unsafe { new_ptr.write(HoleHdr { size, next: None }) };
        // SAFETY: `new_ptr` is derived from the non-empty aligned free range.
        let new_nn = unsafe { NonNull::new_unchecked(new_ptr) };

        // SAFETY: `prev` is a list-owned header (sentinel or earlier
        // insert); `new_nn` was just constructed from caller-owned memory.
        // No other reference aliases either node while we hold this list.
        unsafe {
            let next = (*prev).next;
            (*new_nn.as_ptr()).next = next;
            (*prev).next = Some(new_nn);
        }

        // SAFETY: `prev` is a valid list-owned header, freshly linked to
        // the new region above; `try_merge` only walks `next` pointers
        // belonging to this same list.
        unsafe { self.try_merge(prev) }?;
        Ok(())
    }

    /// If `node` and `node.next` are address-adjacent, fold the
    /// successor into `node`. Repeats while merges succeed.
    /// # SAFETY: `node` is a valid header pointer in this list.
    unsafe fn try_merge(&self, mut node: *mut HoleHdr) -> Result<(), HoleListError> {
        loop {
            // SAFETY: caller-asserted; `next` is also a list-owned header
            // by construction.
            let cur = unsafe { &mut *node };
            let Some(nxt_nn) = cur.next else { return Ok(()); };
            let nxt = nxt_nn.as_ptr();
            let nxt_addr = nxt as usize;
            if !self.owns_header(nxt_addr) {
                return Err(HoleListError::OutsideOwnedRegion);
            }
            let Some(cur_end) = (node as usize).checked_add(cur.size) else { return Err(HoleListError::AddressOverflow); };
            // Skip the sentinel: it has size 0 and is at &self.first;
            // can never abut a real region.
            if cur.size == 0 {
                node = nxt;
                continue;
            }
            if nxt_addr <= node as usize {
                return Err(HoleListError::MalformedNode);
            }
            if cur_end == nxt as usize {
                // SAFETY: `nxt` came from `cur.next`, a list-owned header
                // pointer that the outer `try_merge` contract guarantees
                // is exclusively reachable through our list mutations.
                let nxt_ref = unsafe { &*nxt };
                let Some(merged) = cur.size.checked_add(nxt_ref.size) else { return Err(HoleListError::AddressOverflow); };
                cur.size = merged;
                cur.next = nxt_ref.next;
                // Don't advance — re-check the new successor.
                continue;
            }
            node = nxt;
        }
    }

    /// First-fit allocation. Returns `None` on OOM.
    /// # C: O(N)
    pub fn alloc(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        let (need, align) = normalize(layout)?;

        let mut prev: *mut HoleHdr = &mut self.first;
        loop {
            // SAFETY: list invariant — `prev` is always a valid header;
            // `prev.next` is `Some(NonNull)` into our owned heap or `None`.
            let cur_nn = unsafe { (*prev).next };
            let Some(cur_nn) = cur_nn else { return None; };
            let cur_ptr = cur_nn.as_ptr();
            if !self.owns_header(cur_ptr as usize) {
                #[cfg(feature = "debug-heappoison")]
                {
                    klog::write_raw(b"[KALLOC] invalid-free-header=");
                    klog::write_hex_u64(cur_ptr as usize as u64);
                    klog::write_raw(b"\n");
                }
                return None;
            }
            // SAFETY: list invariant — every `next`-reachable pointer is
            // a valid header inside the heap region the user passed at
            // init, exclusively owned through this list.
            let cur_size = unsafe { (*cur_ptr).size };
            let cur_addr = cur_ptr as usize;
            let cur_end = cur_addr.checked_add(cur_size)?;
            if cur_size < MIN_HOLE_SIZE || cur_size % MIN_HOLE_ALIGN != 0 || !self.owns_range(cur_addr, cur_end) {
                #[cfg(feature = "debug-heappoison")]
                {
                    klog::write_raw(b"[KALLOC] invalid-free-span=");
                    klog::write_hex_u64(cur_addr as u64);
                    klog::write_raw(b"\n");
                }
                return None;
            }

            // Try to carve `[user_start, user_start + need)` out of this hole.
            let mut user_start = align_up(cur_addr, align)?;
            // If the front padding is > 0 but < MIN_HOLE_SIZE, advance
            // user_start so the front padding becomes a valid hole.
            let front_pad = user_start - cur_addr;
            if front_pad > 0 && front_pad < MIN_HOLE_SIZE {
                user_start = align_up(cur_addr.checked_add(MIN_HOLE_SIZE)?, align)?;
            }
            let front_pad = user_start - cur_addr;
            let user_end = user_start.checked_add(need)?;
            let cur_end  = cur_end;

            if user_end > cur_end {
                // Doesn't fit; advance.
                prev = cur_ptr;
                continue;
            }

            let back_pad = cur_end - user_end;
            // Splice out cur, reinsert front/back fragments as new holes.
            // SAFETY: list invariant; we're only mutating headers we own.
            unsafe {
                (*prev).next = (*cur_ptr).next;
            }

            if front_pad >= MIN_HOLE_SIZE {
                // SAFETY: front padding region is within the formerly-free
                // hole; safe to construct a fresh header.
                assert!(unsafe { self.add_free_region(cur_addr, front_pad) }.is_ok(), "kalloc front fragment invalid");
            }
            if back_pad >= MIN_HOLE_SIZE {
                // SAFETY: back padding region is also within the former hole.
                assert!(unsafe { self.add_free_region(user_end, back_pad) }.is_ok(), "kalloc back fragment invalid");
            }
            // Front padding < MIN_HOLE_SIZE was avoided by re-aligning;
            // back padding < MIN_HOLE_SIZE is leaked (bounded waste, see
            // module docs).

            return NonNull::new(user_start as *mut u8);
        }
    }

    /// Release `[ptr, ptr + need)` (where `need = normalize(layout).0`)
    /// back to the free list, coalescing with neighbors if abutting.
    /// # SAFETY: `ptr` was returned by a prior `alloc(layout)`; the
    /// memory is no longer borrowed.
    /// # C: O(N)
    pub unsafe fn dealloc(&mut self, ptr: NonNull<u8>, layout: Layout) -> Result<(), HoleListError> {
        let (need, _align) = normalize(layout).ok_or(HoleListError::AddressOverflow)?;
        // SAFETY: caller-asserted; we route to add_free_region which
        // re-validates alignment and minimum size.
        unsafe { self.add_free_region(ptr.as_ptr() as usize, need) }
    }
}

/// Normalize a `Layout` to the allocator's internal block geometry.
/// Returns `(size_padded_up_to_min_hole_align, align_at_least_min_hole_align)`.
/// Same fn called on alloc + dealloc to ensure both sides agree.
/// # C: O(1)
#[inline]
pub fn normalize(layout: Layout) -> Option<(usize, usize)> {
    let need = max(align_up(layout.size(), MIN_HOLE_ALIGN)?, MIN_HOLE_SIZE);
    let align = max(layout.align(), MIN_HOLE_ALIGN);
    Some((need, align))
}
