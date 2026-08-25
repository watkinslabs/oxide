use super::*;
impl HoleList {
    pub unsafe fn add_free_region(&mut self, addr: usize, size: usize) -> Result<(), HoleListError> {
        // Round addr up to header alignment; round size down accordingly.
        let Some(aligned) = align_up(addr, MIN_HOLE_ALIGN) else {
            #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
            {
                klog::write_primary_raw(b"[KALLOC] free-region-align-overflow addr=");
                klog::write_primary_hex_u64(addr as u64);
                klog::write_primary_raw(b" size=");
                klog::write_primary_dec_u64(size as u64);
                klog::write_primary_raw(b"\n");
            }
            return Err(HoleListError::AddressOverflow);
        };
        let drop = aligned - addr;
        if drop >= size {
            #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
            {
                klog::write_primary_raw(b"[KALLOC] free-region-degenerate addr=");
                klog::write_primary_hex_u64(addr as u64);
                klog::write_primary_raw(b" size=");
                klog::write_primary_dec_u64(size as u64);
                klog::write_primary_raw(b" drop=");
                klog::write_primary_dec_u64(drop as u64);
                klog::write_primary_raw(b"\n");
            }
            return Err(HoleListError::MalformedNode);
        }
        let mut size = size - drop;
        size &= !(MIN_HOLE_ALIGN - 1);
        if size < MIN_HOLE_SIZE {
            #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
            {
                klog::write_primary_raw(b"[KALLOC] free-region-too-small addr=");
                klog::write_primary_hex_u64(addr as u64);
                klog::write_primary_raw(b" drop=");
                klog::write_primary_dec_u64(drop as u64);
                klog::write_primary_raw(b" rounded_size=");
                klog::write_primary_dec_u64(size as u64);
                klog::write_primary_raw(b"\n");
            }
            return Err(HoleListError::MalformedNode);
        }
        let Some(end) = aligned.checked_add(size) else {
            #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
            {
                klog::write_primary_raw(b"[KALLOC] free-region-overflow addr=");
                klog::write_primary_hex_u64(addr as u64);
                klog::write_primary_raw(b" aligned=");
                klog::write_primary_hex_u64(aligned as u64);
                klog::write_primary_raw(b" size=");
                klog::write_primary_hex_u64(size as u64);
                klog::write_primary_raw(b"\n");
            }
            return Err(HoleListError::AddressOverflow);
        };
        if !self.owns_range(aligned, end) {
            #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
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
        #[cfg(feature = "debug-heapwalk")]
        let mut steps: u64 = 0;
        let mut prev: *mut HoleHdr = &mut self.first;
        let mut prev_addr = None;
        loop {
            #[cfg(feature = "debug-heapwalk")]
            { steps += 1; }
            // SAFETY: `prev` is initialized to `&mut self.first` and
            // thereafter only advanced through `(*prev).next` pointers
            // that we ourselves inserted; every dereference targets a
            // header we own.
            let next = unsafe { (*prev).next };
            match next {
                Some(n) => {
                    let cur = n.as_ptr() as usize;
                    if !self.owns_header(cur) || prev_addr.is_some_and(|last| cur <= last) {
                        #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
                        {
                            klog::write_primary_raw(b"[KALLOC] malformed-free-link prev=");
                            klog::write_primary_hex_u64(prev as usize as u64);
                            klog::write_primary_raw(b" cur=");
                            klog::write_primary_hex_u64(cur as u64);
                            klog::write_primary_raw(b"\n");
                        }
                        #[cfg(feature = "debug-heappoison")]
                        crate::hooks::probe_corruption(cur);
                        return Err(HoleListError::MalformedNode);
                    }
                    // SAFETY: alignment and strict ordering validate the link;
                    // the outer list contract gives this node readable metadata.
                    let cur_size = unsafe { (*n.as_ptr()).size };
                    if cur_size < MIN_HOLE_SIZE || cur_size % MIN_HOLE_ALIGN != 0 {
                        #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
                        crate::hooks::probe_corruption(cur);
                        #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
                        {
                            klog::write_primary_raw(b"[KALLOC] malformed-free-size addr=");
                            klog::write_primary_hex_u64(cur as u64);
                            klog::write_primary_raw(b" size=");
                            klog::write_primary_hex_u64(cur_size as u64);
                            klog::write_primary_raw(b"\n");
                        }
                        return Err(HoleListError::MalformedNode);
                    }
                    let Some(cur_end) = cur.checked_add(cur_size) else {
                        #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
                        {
                            klog::write_primary_raw(b"[KALLOC] free-list-node-overflow addr=");
                            klog::write_primary_hex_u64(cur as u64);
                            klog::write_primary_raw(b" size=");
                            klog::write_primary_hex_u64(cur_size as u64);
                            klog::write_primary_raw(b"\n");
                            crate::hooks::probe_corruption(cur); // B1345: classify frame
                            self.print_free_ip(cur); // B1346: name the freer
                        }
                        return Err(HoleListError::AddressOverflow);
                    };
                    if !self.owns_range(cur, cur_end) {
                        #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
                        {
                            klog::write_primary_raw(b"[KALLOC] listed-free-outside start=");
                            klog::write_primary_hex_u64(cur as u64);
                            klog::write_primary_raw(b" end=");
                            klog::write_primary_hex_u64(cur_end as u64);
                            klog::write_primary_raw(b"\n");
                            crate::hooks::probe_corruption(cur); // B1345: classify frame
                            self.print_free_ip(cur); // B1346: name the freer
                        }
                        return Err(HoleListError::OutsideOwnedRegion);
                    }
                    if cur_end > aligned && cur < end {
                        #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
                        {
                            klog::write_primary_raw(b"[KALLOC] free-overlap new=");
                            klog::write_primary_hex_u64(aligned as u64);
                            klog::write_primary_raw(b"..");
                            klog::write_primary_hex_u64(end as u64);
                            klog::write_primary_raw(b" listed=");
                            klog::write_primary_hex_u64(cur as u64);
                            klog::write_primary_raw(b"..");
                            klog::write_primary_hex_u64(cur_end as u64);
                            klog::write_primary_raw(b"\n");
                        }
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
        #[cfg(feature = "debug-heapwalk")]
        crate::walkstat::note_free(steps);
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
        #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
        let mut trail: [(usize, usize); 4] = [(0, 0); 4];
        #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
        let mut trail_n: usize = 0;
        loop {
            // SAFETY: caller-asserted; `next` is also a list-owned header
            // by construction.
            let cur = unsafe { &mut *node };
            let Some(nxt_nn) = cur.next else { return Ok(()); };
            let nxt = nxt_nn.as_ptr();
            let nxt_addr = nxt as usize;
            if !self.owns_header(nxt_addr) {
                #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
                {
                    klog::write_primary_raw(b"[KALLOC] seq=");
                    klog::write_primary_dec_u64(crate::hooks::next_seq());
                    klog::write_primary_raw(b" merge-header-outside node=");
                    klog::write_primary_hex_u64(node as u64);
                    klog::write_primary_raw(b" node_size=");
                    klog::write_primary_dec_u64(cur.size as u64);
                    klog::write_primary_raw(b" bad_next=");
                    klog::write_primary_hex_u64(nxt_addr as u64);
                    klog::write_primary_raw(b"\n");
                    // B1345 hunt: classify the corrupt node's physical frame
                    // (MANAGED/buddy vs kernel-image-reserved; refcount/mapcount)
                    // to decide device/double-map cross-write vs pure CPU UAF.
                    crate::hooks::probe_corruption(node as usize);
                    self.print_free_ip(node as usize); // B1346: name the freer
                    #[cfg(feature = "debug-heappoison")]
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
                    #[cfg(feature = "debug-heappoison")]
                    crate::hooks::probe_corruption(node as usize);
                    self.print_free_ip(node as usize); // B1346: name the freer
                }
                return Err(HoleListError::OutsideOwnedRegion);
            }
            #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
            {
                trail[trail_n % trail.len()] = (node as usize, cur.size);
                trail_n += 1;
            }
            let Some(cur_end) = (node as usize).checked_add(cur.size) else {
                #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
                {
                    klog::write_primary_raw(b"[KALLOC] merge-cur-overflow node=");
                    klog::write_primary_hex_u64(node as u64);
                    klog::write_primary_raw(b" size=");
                    klog::write_primary_dec_u64(cur.size as u64);
                    klog::write_primary_raw(b"\n");
                }
                return Err(HoleListError::AddressOverflow);
            };
            // Skip the sentinel: it has size 0 and is at &self.first;
            // can never abut a real region.
            if cur.size == 0 {
                node = nxt;
                continue;
            }
            if nxt_addr <= node as usize {
                #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
                {
                    klog::write_primary_raw(b"[KALLOC] merge-out-of-order node=");
                    klog::write_primary_hex_u64(node as u64);
                    klog::write_primary_raw(b" node_size=");
                    klog::write_primary_dec_u64(cur.size as u64);
                    klog::write_primary_raw(b" nxt=");
                    klog::write_primary_hex_u64(nxt_addr as u64);
                    klog::write_primary_raw(b"\n");
                }
                return Err(HoleListError::MalformedNode);
            }
            if cur_end == nxt as usize {
                // SAFETY: `nxt` came from `cur.next`, a list-owned header
                // pointer that the outer `try_merge` contract guarantees
                // is exclusively reachable through our list mutations.
                let nxt_ref = unsafe { &*nxt };
                let Some(merged) = cur.size.checked_add(nxt_ref.size) else {
                    #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
                    klog::write_primary_raw(b"[KALLOC] merge-size-overflow\n");
                    return Err(HoleListError::AddressOverflow);
                };
                let Some(merged_end) = (node as usize).checked_add(merged) else {
                    #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
                    klog::write_primary_raw(b"[KALLOC] merge-end-overflow\n");
                    return Err(HoleListError::AddressOverflow);
                };
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
}

