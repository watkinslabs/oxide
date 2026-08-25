use core::alloc::Layout;
use core::ptr::NonNull;

use super::*;
impl HoleList {
    /// First-fit allocation. Returns `None` on OOM.
    /// # C: O(N)
    pub fn alloc(&mut self, layout: Layout) -> Option<NonNull<u8>> {
        let (need, align) = normalize(layout)?;

        #[cfg(feature = "debug-heapwalk")]
        let mut steps: u64 = 0;
        let mut prev: *mut HoleHdr = &mut self.first;
        loop {
            #[cfg(feature = "debug-heapwalk")]
            { steps += 1; }
            // SAFETY: list invariant — `prev` is always a valid header;
            // `prev.next` is `Some(NonNull)` into our owned heap or `None`.
            let cur_nn = unsafe { (*prev).next };
            let Some(cur_nn) = cur_nn else { return None; };
            let cur_ptr = cur_nn.as_ptr();
            if !self.owns_header(cur_ptr as usize) {
                #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
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
                #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
                {
                    klog::write_primary_raw(b"[KALLOC] invalid-free-span=");
                    klog::write_primary_hex_u64(cur_addr as u64);
                    klog::write_primary_raw(b" size=");
                    klog::write_primary_hex_u64(cur_size as u64);
                    klog::write_primary_raw(b"\n");
                    // B1345 hunt: classify the corrupt node's physical frame
                    // (MANAGED/buddy vs kernel-image-reserved; refcount/mapcount)
                    // to decide device/double-map cross-write vs pure CPU UAF.
                    crate::hooks::probe_corruption(cur_addr);
                    self.print_free_ip(cur_addr); // B1346: name the freer
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
                if let Err(_e) = unsafe { self.add_free_region(cur_addr, front_pad) } {
                    #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
                    {
                        klog::write_primary_raw(b"[KALLOC] front-fragment-failed tag=");
                        klog::write_primary_raw(_e.tag());
                        klog::write_primary_raw(b" cur_addr=");
                        klog::write_primary_hex_u64(cur_addr as u64);
                        klog::write_primary_raw(b" front_pad=");
                        klog::write_primary_dec_u64(front_pad as u64);
                        klog::write_primary_raw(b"\n");
                    }
                    panic!("kalloc front fragment invalid");
                }
            }
            if back_pad >= MIN_HOLE_SIZE {
                // SAFETY: back padding region is also within the former hole.
                if let Err(_e) = unsafe { self.add_free_region(user_end, back_pad) } {
                    #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
                    {
                        klog::write_primary_raw(b"[KALLOC] back-fragment-failed tag=");
                        klog::write_primary_raw(_e.tag());
                        klog::write_primary_raw(b" user_end=");
                        klog::write_primary_hex_u64(user_end as u64);
                        klog::write_primary_raw(b" back_pad=");
                        klog::write_primary_dec_u64(back_pad as u64);
                        klog::write_primary_raw(b"\n");
                    }
                    panic!("kalloc back fragment invalid");
                }
            }
            // Front padding < MIN_HOLE_SIZE was avoided by re-aligning;
            // back padding < MIN_HOLE_SIZE is leaked (bounded waste, see
            // module docs).

            #[cfg(feature = "debug-heapwalk")]
            crate::walkstat::note_alloc(steps);
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

