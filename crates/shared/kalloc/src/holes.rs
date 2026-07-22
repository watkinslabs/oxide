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

impl HoleListError {
    /// Stable diagnostic tag for allocator integrity failures. # C: O(1)
    pub const fn tag(self) -> &'static [u8] {
        match self {
            Self::AddressOverflow => b"address-overflow",
            Self::MalformedNode => b"malformed-node",
            Self::OverlappingFree => b"overlapping-free",
            Self::OutsideOwnedRegion => b"outside-owned-region",
        }
    }
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

/// Ring depth for `EvictHistory`. Diagnostic-only (`debug-heappoison`).
#[cfg(feature = "debug-heappoison")]
const EVICT_HISTORY_SLOTS: usize = 4096;

#[cfg(feature = "debug-heappoison")]
#[derive(Clone, Copy)]
struct EvictedSlot { base: usize, size: u32, free_ip: u64 }
#[cfg(feature = "debug-heappoison")]
impl EvictedSlot { const EMPTY: EvictedSlot = EvictedSlot { base: 0, size: 0, free_ip: crate::caller::UNKNOWN_RETURN_IP }; }

/// Records (base, size, free_ip) for blocks that have LEFT the quarantine
/// ring (`poison::Quar`) and rejoined this real hole list. Quarantine's own
/// `lookup`/`scan_window` only see blocks still quarantined; once evicted, a
/// corruption discovered later (a real hole's header found broken, possibly
/// long after the corrupting write) has no provenance at all otherwise.
/// Lives directly on `HoleList` (not `Quar`) so `try_merge`/`alloc`'s own
/// diagnostic prints can consult it without re-locking the allocator they're
/// already running inside of. Diagnostic-only, never in a shipped profile.
#[cfg(feature = "debug-heappoison")]
struct EvictHistory { slots: [EvictedSlot; EVICT_HISTORY_SLOTS], idx: usize }

#[cfg(feature = "debug-heappoison")]
impl EvictHistory {
    const fn new() -> Self { Self { slots: [EvictedSlot::EMPTY; EVICT_HISTORY_SLOTS], idx: 0 } }

    fn record(&mut self, base: usize, size: u32, free_ip: u64) {
        let i = self.idx;
        self.idx = (i + 1) % EVICT_HISTORY_SLOTS;
        self.slots[i] = EvictedSlot { base, size, free_ip };
    }

    /// Most recent evicted block whose original span contained `addr`, if
    /// still within the ring's retention window. # C: O(EVICT_HISTORY_SLOTS)
    fn lookup(&self, addr: usize) -> Option<(usize, u32, u64)> {
        // Newest-first (idx-1 backward) so a re-freed address reports its
        // MOST RECENT owner, not an earlier one still in the ring.
        for k in 0..EVICT_HISTORY_SLOTS {
            let i = (self.idx + EVICT_HISTORY_SLOTS - 1 - k) % EVICT_HISTORY_SLOTS;
            let s = self.slots[i];
            if s.size != 0 && addr >= s.base && addr < s.base + s.size as usize {
                return Some((s.base, s.size, s.free_ip));
            }
        }
        None
    }
}

/// Sorted singly-linked list of free regions. The list is owned by
/// `HoleList`; `KAlloc` wraps it in a `Spinlock`.
pub struct HoleList {
    /// Sentinel header so all "list head" updates go through `next`,
    /// without a separate `head: Option<...>` case.
    first: HoleHdr,
    /// Region descriptors live in reserved prefixes of their backing ranges.
    regions: Option<NonNull<RegionHdr>>,
    /// See `EvictHistory`.
    #[cfg(feature = "debug-heappoison")]
    evict_history: EvictHistory,
}

// SAFETY: `HoleList` mediates exclusive access to the heap region via
// the outer `Spinlock`; the `NonNull<HoleHdr>` chain only points into
// memory owned by the list, which the user reserves once at init.
unsafe impl Send for HoleList {}

impl HoleList {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            first: HoleHdr { size: 0, next: None },
            regions: None,
            #[cfg(feature = "debug-heappoison")]
            evict_history: EvictHistory::new(),
        }
    }

    /// Record that `[base, base+size)` just left quarantine and is about to
    /// be reinserted as a real hole. Call BEFORE the reinsertion so a
    /// corruption discovered on this span later can be traced to its last
    /// known freeing site. # C: O(1)
    #[cfg(feature = "debug-heappoison")]
    pub fn record_evicted(&mut self, base: usize, size: u32, free_ip: u64) {
        self.evict_history.record(base, size, free_ip);
    }

    /// Provenance for `addr`, if it falls within a block this list's owner
    /// evicted from quarantine within the retention window. # C: O(1) amortized
    #[cfg(feature = "debug-heappoison")]
    pub fn lookup_evicted(&self, addr: usize) -> Option<(usize, u32, u64)> {
        self.evict_history.lookup(addr)
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
            if existing_start < end && aligned < existing.end {
                #[cfg(feature = "debug-heappoison")]
                {
                    klog::write_primary_raw(b"[KALLOC] region-collision new=");
                    klog::write_primary_hex_u64(aligned as u64);
                    klog::write_primary_raw(b" new-end=");
                    klog::write_primary_hex_u64(end as u64);
                    klog::write_primary_raw(b" existing=");
                    klog::write_primary_hex_u64(existing_start as u64);
                    klog::write_primary_raw(b" existing-end=");
                    klog::write_primary_hex_u64(existing.end as u64);
                    klog::write_primary_raw(b"\n");
                }
                return Err(HoleListError::OverlappingFree);
            }
            region = existing.next;
        }
        let hdr = aligned as *mut RegionHdr;
        // SAFETY: `aligned` starts the caller-owned range and is never exposed
        // as allocatable storage after this descriptor is installed.
        unsafe { hdr.write(RegionHdr { end, next: self.regions }) };
        // SAFETY: `hdr` is aligned and initialized by the preceding write.
        self.regions = Some(unsafe { NonNull::new_unchecked(hdr) });
        // SAFETY: the usable suffix is contained in the freshly registered range.
        let result = unsafe { self.add_free_region(usable, end - usable) };
        #[cfg(feature = "debug-heappoison")]
        if result.is_err() {
            klog::write_primary_raw(b"[KALLOC] seq=");
            klog::write_primary_dec_u64(crate::next_seq());
            klog::write_primary_raw(b" add-region-failed start=");
            klog::write_primary_hex_u64(aligned as u64);
            klog::write_primary_raw(b" usable=");
            klog::write_primary_hex_u64(usable as u64);
            klog::write_primary_raw(b" end=");
            klog::write_primary_hex_u64(end as u64);
            klog::write_primary_raw(b"\n");
        }
        result
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

    /// Walk the whole free list and reject the first node that violates a
    /// live invariant: owned/aligned header, minimum size, sorted address
    /// order, and non-overlap with its successor. Diagnostic-only bisection
    /// tool (debug-heappoison) for locating WHEN corruption first appears,
    /// as opposed to the reactive asserts in `alloc`/`add_free_region` that
    /// only fire when a corrupted node is finally carved. Returns the
    /// address of the first bad node, or `None` if the list is intact.
    /// # C: O(N)
    #[cfg(feature = "debug-heappoison")]
    pub fn validate(&self) -> Option<usize> {
        let mut prev_end: Option<usize> = None;
        let mut cur = self.first.next;
        while let Some(node) = cur {
            let addr = node.as_ptr() as usize;
            if !self.owns_header(addr) { return Some(addr); }
            // SAFETY: `owns_header` just confirmed `addr` is a readable,
            // allocator-owned, aligned header-sized range.
            let hdr = unsafe { node.as_ref() };
            if hdr.size < MIN_HOLE_SIZE { return Some(addr); }
            let Some(end) = addr.checked_add(hdr.size) else { return Some(addr); };
            if prev_end.is_some_and(|p| addr < p) { return Some(addr); }
            prev_end = Some(end);
            cur = hdr.next;
        }
        None
    }

    /// Visit every free-list node's `(addr, size)` in address order. Stops
    /// at list end or the first node that fails `owns_header` (silently —
    /// callers that need corruption detail should use `validate`/`dump`).
    /// Test-only: lets a hosted fuzz harness cross-check free-list addresses
    /// against the quarantine ring without `alloc` (this crate has none).
    /// # C: O(N)
    #[cfg(any(test, feature = "hosted"))]
    pub(crate) fn for_each_free(&self, mut f: impl FnMut(usize, usize)) {
        let mut cur = self.first.next;
        loop {
            let Some(node) = cur else { break };
            let addr = node.as_ptr() as usize;
            if !self.owns_header(addr) { break; }
            // SAFETY: `owns_header` just confirmed a readable, owned, aligned header.
            let hdr = unsafe { node.as_ref() };
            if hdr.size < MIN_HOLE_SIZE { break; }
            f(addr, hdr.size);
            cur = hdr.next;
        }
    }

    /// Print every free-list node's (addr, size) up to `cap` entries, then
    /// stop (either at list end or the first node that fails `owns_header`,
    /// printed distinctly so the corrupt node's exact neighbors in address
    /// order are visible). Diagnostic-only (debug-heappoison): names the
    /// allocation immediately adjacent to a corrupted node, which a bare
    /// `validate()` bad-address report cannot show. # C: O(min(N, cap))
    #[cfg(feature = "debug-heappoison")]
    pub fn dump(&self, cap: usize) {
        klog::write_primary_raw(b"[KALLOC-DUMP] begin\n");
        let mut cur = self.first.next;
        let mut n = 0usize;
        while let Some(node) = cur {
            if n >= cap { klog::write_primary_raw(b"[KALLOC-DUMP] truncated\n"); break; }
            let addr = node.as_ptr() as usize;
            if !self.owns_header(addr) {
                klog::write_primary_raw(b"[KALLOC-DUMP] BAD addr=");
                klog::write_primary_hex_u64(addr as u64);
                klog::write_primary_raw(b"\n");
                break;
            }
            // SAFETY: `owns_header` just confirmed a readable, owned, aligned header.
            let hdr = unsafe { node.as_ref() };
            klog::write_primary_raw(b"[KALLOC-DUMP] addr=");
            klog::write_primary_hex_u64(addr as u64);
            klog::write_primary_raw(b" size=");
            klog::write_primary_dec_u64(hdr.size as u64);
            klog::write_primary_raw(b"\n");
            if hdr.size < MIN_HOLE_SIZE { break; }
            cur = hdr.next;
            n += 1;
        }
        klog::write_primary_raw(b"[KALLOC-DUMP] end\n");
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
        if !self.owns_range(aligned, end) {
            #[cfg(feature = "debug-heappoison")]
            {
                klog::write_primary_raw(b"[KALLOC] free-outside-owned start=");
                klog::write_primary_hex_u64(aligned as u64);
                klog::write_primary_raw(b" end=");
                klog::write_primary_hex_u64(end as u64);
                let mut region = self.regions;
                while let Some(node) = region {
                    // SAFETY: region links were installed by add_region and
                    // remain in permanently reserved, allocator-owned prefixes.
                    let current = unsafe { node.as_ref() };
                    klog::write_primary_raw(b" region=");
                    klog::write_primary_hex_u64(node.as_ptr() as usize as u64);
                    klog::write_primary_raw(b" region-end=");
                    klog::write_primary_hex_u64(current.end as u64);
                    region = current.next;
                }
                klog::write_primary_raw(b"\n");
            }
            return Err(HoleListError::OutsideOwnedRegion);
        }

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
                        #[cfg(feature = "debug-heappoison")]
                        {
                            klog::write_primary_raw(b"[KALLOC] malformed-free-link prev=");
                            klog::write_primary_hex_u64(prev as usize as u64);
                            klog::write_primary_raw(b" cur=");
                            klog::write_primary_hex_u64(cur as u64);
                            klog::write_primary_raw(b"\n");
                        }
                        return Err(HoleListError::MalformedNode);
                    }
                    // SAFETY: alignment and strict ordering validate the link;
                    // the outer list contract gives this node readable metadata.
                    let cur_size = unsafe { (*n.as_ptr()).size };
                    if cur_size < MIN_HOLE_SIZE || cur_size % MIN_HOLE_ALIGN != 0 {
                        #[cfg(feature = "debug-heappoison")]
                        {
                            klog::write_primary_raw(b"[KALLOC] malformed-free-size addr=");
                            klog::write_primary_hex_u64(cur as u64);
                            klog::write_primary_raw(b" size=");
                            klog::write_primary_hex_u64(cur_size as u64);
                            klog::write_primary_raw(b"\n");
                        }
                        return Err(HoleListError::MalformedNode);
                    }
                    let cur_end = cur.checked_add(cur_size).ok_or(HoleListError::AddressOverflow)?;
                    if !self.owns_range(cur, cur_end) {
                        #[cfg(feature = "debug-heappoison")]
                        {
                            klog::write_primary_raw(b"[KALLOC] listed-free-outside start=");
                            klog::write_primary_hex_u64(cur as u64);
                            klog::write_primary_raw(b" end=");
                            klog::write_primary_hex_u64(cur_end as u64);
                            klog::write_primary_raw(b"\n");
                        }
                        return Err(HoleListError::OutsideOwnedRegion);
                    }
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
        // Diagnostic-only (debug-heappoison): last-K (addr,size) visited by
        // THIS walk, so a corrupt node's immediate predecessors in address
        // order are always available on error — no dump-cap tuning needed,
        // since the corrupt node can be arbitrarily far into the list.
        #[cfg(feature = "debug-heappoison")]
        let mut trail: [(usize, usize); 4] = [(0, 0); 4];
        #[cfg(feature = "debug-heappoison")]
        let mut trail_n: usize = 0;
        loop {
            // SAFETY: caller-asserted; `next` is also a list-owned header
            // by construction.
            let cur = unsafe { &mut *node };
            let Some(nxt_nn) = cur.next else { return Ok(()); };
            let nxt = nxt_nn.as_ptr();
            let nxt_addr = nxt as usize;
            if !self.owns_header(nxt_addr) {
                #[cfg(feature = "debug-heappoison")]
                {
                    klog::write_primary_raw(b"[KALLOC] seq=");
                    klog::write_primary_dec_u64(crate::next_seq());
                    klog::write_primary_raw(b" merge-header-outside node=");
                    klog::write_primary_hex_u64(node as u64);
                    klog::write_primary_raw(b" node_size=");
                    klog::write_primary_dec_u64(cur.size as u64);
                    klog::write_primary_raw(b" bad_next=");
                    klog::write_primary_hex_u64(nxt_addr as u64);
                    klog::write_primary_raw(b"\n");
                    if let Some((base, size, free_ip)) = self.lookup_evicted(node as usize) {
                        klog::write_primary_raw(b"[KALLOC] merge-corrupt-node-provenance base=");
                        klog::write_primary_hex_u64(base as u64);
                        klog::write_primary_raw(b" freed_size=");
                        klog::write_primary_dec_u64(size as u64);
                        klog::write_primary_raw(b" free_ip=0x");
                        klog::write_primary_hex_u64(free_ip);
                        klog::write_primary_raw(b"\n");
                    }
                    let shown = core::cmp::min(trail_n, trail.len());
                    for k in 0..shown {
                        // Oldest-of-the-kept-window first: trail_n - shown
                        // is the ring index of the oldest surviving entry.
                        let i = (trail_n - shown + k) % trail.len();
                        let (a, s) = trail[i];
                        klog::write_primary_raw(b"[KALLOC] merge-trail addr=");
                        klog::write_primary_hex_u64(a as u64);
                        klog::write_primary_raw(b" size=");
                        klog::write_primary_dec_u64(s as u64);
                        klog::write_primary_raw(b"\n");
                    }
                }
                return Err(HoleListError::OutsideOwnedRegion);
            }
            #[cfg(feature = "debug-heappoison")]
            {
                trail[trail_n % trail.len()] = (node as usize, cur.size);
                trail_n += 1;
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
                let Some(merged_end) = (node as usize).checked_add(merged) else { return Err(HoleListError::AddressOverflow); };
                // Backing ranges retain a permanently reserved descriptor at
                // their start. Adjacent PMM growth ranges must therefore stay
                // as separate holes: a merged hole would span two ownership
                // domains and make later provenance validation ambiguous.
                if !self.owns_range(node as usize, merged_end) {
                    node = nxt;
                    continue;
                }
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
                    klog::write_primary_raw(b"[KALLOC] invalid-free-header=");
                    klog::write_primary_hex_u64(cur_ptr as usize as u64);
                    klog::write_primary_raw(b"\n");
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
                    klog::write_primary_raw(b"[KALLOC] invalid-free-span=");
                    klog::write_primary_hex_u64(cur_addr as u64);
                    klog::write_primary_raw(b" size=");
                    klog::write_primary_hex_u64(cur_size as u64);
                    klog::write_primary_raw(b"\n");
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

    /// Check whether releasing this exact allocation would be disjoint from
    /// every free extent, without changing list ownership. Debug quarantine
    /// uses this before touching caller storage, so an invalid second free
    /// cannot overwrite a live in-band hole header.
    /// # C: O(N)
    pub fn can_dealloc(&self, ptr: NonNull<u8>, layout: Layout) -> Result<(), HoleListError> {
        let (size, _) = normalize(layout).ok_or(HoleListError::AddressOverflow)?;
        let start = ptr.as_ptr() as usize;
        let end = start.checked_add(size).ok_or(HoleListError::AddressOverflow)?;
        if !self.owns_range(start, end) { return Err(HoleListError::OutsideOwnedRegion); }
        let mut node = self.first.next;
        while let Some(current) = node {
            let addr = current.as_ptr() as usize;
            if !self.owns_header(addr) { return Err(HoleListError::MalformedNode); }
            // SAFETY: `owns_header` proves the header lies in allocator-owned
            // storage; the list lock prevents concurrent node mutation.
            let free_size = unsafe { current.as_ref().size };
            if free_size < MIN_HOLE_SIZE || free_size % MIN_HOLE_ALIGN != 0 { return Err(HoleListError::MalformedNode); }
            let free_end = addr.checked_add(free_size).ok_or(HoleListError::AddressOverflow)?;
            if !self.owns_range(addr, free_end) { return Err(HoleListError::OutsideOwnedRegion); }
            if addr < end && start < free_end { return Err(HoleListError::OverlappingFree); }
            // SAFETY: same validated list node; its successor is read-only
            // while `KAlloc` holds the enclosing allocator-state lock.
            node = unsafe { current.as_ref().next };
        }
        Ok(())
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
