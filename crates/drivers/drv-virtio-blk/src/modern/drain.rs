// The used-ring walker, and the decisions it makes, separated so the
// decisions can be exercised without a device.
//
// Two contexts reach a walker: the BlockIo softirq (never the hard IRQ, which
// only raises it) drains the interrupt-driven default queue, and
// `BlockDevice::poll_completions` in process context drains the interrupt-free
// poll queue. They no longer share a queue — that separation is the point of
// the poll queue — but the walker is one function, and the claim-once rule it
// depends on has to hold anyway: `start_deferred_requests` re-enters posting on
// the same queue, and a device could still be given two drainers by a future
// caller. The cursor arithmetic therefore lives below, ungated, with the
// interleaving pinned by tests.

use super::*;

/// `used.idx` sits after `used.flags`, both u16 (Virtio 1.2 §2.7.8).
pub(super) const USED_IDX_OFF: usize = core::mem::size_of::<u16>();
/// `used.ring[]` follows `flags` and `idx`; each element is `id`+`len`, u32 each.
const USED_RING_OFF: usize = core::mem::size_of::<u16>() * 2;
const USED_ELEM_BYTES: usize = core::mem::size_of::<u32>() * 2;

/// Byte offset of `used.ring[slot].id` inside the device area. # C: O(1)
pub(super) const fn used_entry_id_off(slot: usize) -> usize {
    USED_RING_OFF + slot * USED_ELEM_BYTES
}

/// Whether a drain may read this queue's used ring at all. A queue whose rings
/// were never programmed, or a device with no HHDM window, has no ring to walk;
/// `busy` means a SYNCHRONOUS owner holds the engine turn and is watching
/// `used.idx` itself, so its entry must be left where that waiter can see it.
/// # C: O(1)
pub(super) fn drain_admitted(busy: bool, hhdm: u64, device_pa: u64, size: u16) -> bool {
    hhdm != 0 && device_pa != 0 && size != 0 && !busy
}

/// Claim the next used-ring entry for THIS drain, advancing the cursor.
///
/// Called with the queue lock held. Advancing `used_seen` under the same lock
/// that publishes it is what makes the claim exclusive: a second drainer
/// re-reads the advanced cursor, finds it equal to `used.idx`, and stops rather
/// than delivering the same completion twice.
/// # C: O(1)
pub(super) fn claim_next_used(used_seen: &mut u16, used_idx: u16, size: u16) -> Option<usize> {
    if size == 0 || *used_seen == used_idx { return None; }
    let slot = (*used_seen % size) as usize;
    *used_seen = used_seen.wrapping_add(1);
    Some(slot)
}

impl BlkState {
    /// Consume every used-ring entry the device published on `q` and run owned
    /// completions after releasing queue state, returning how many completions
    /// were delivered.
    ///
    /// # Lk: `q.inflight` (`lock_bh`) is taken and released once per entry, and
    /// `used_seen` advances under it, so two concurrent drains never claim the
    /// same entry. Completion continuations run with the lock DROPPED, which is
    /// why this is callable from process context as well as the softirq.
    /// # Ctx: softirq or process; never hard IRQ.
    /// # C: O(completions reaped)
    pub(super) fn drain_owned_completions(&self, q: &BlkQueue) -> usize {
        let mut found = 0usize;
        let h = hhdm();
        if !drain_admitted(q.lock().busy, h, q.res.device_pa, q.res.size) { return found; }
        loop {
            let pending = {
                let mut ring = q.lock();
                let used = h.wrapping_add(q.res.device_pa) as *const u8;
                // SAFETY: `device_pa` is this queue's used frame via HHDM,
                // non-zero per the guard above. Virtio 1.2 §2.7.8 puts `idx` at
                // byte 2 as an aligned u16; the volatile load re-reads the
                // device's publish rather than caching it.
                let used_index = unsafe { core::ptr::read_volatile(used.add(USED_IDX_OFF) as *const u16) };
                let Some(slot) = claim_next_used(&mut ring.used_seen, used_index, q.res.size) else {
                    return found;
                };
                // SAFETY: same used frame; `slot < size` and `size` is capped to
                // one frame, so the entry's `id` is an in-bounds, u32-aligned
                // load. The claim above proves the device already published it.
                let head = unsafe {
                    core::ptr::read_volatile(used.add(used_entry_id_off(slot)) as *const u32) as u16
                };
                let Some(position) = ring.pending.iter().position(|request| request.head == head) else {
                    self.poisoned.store(true, core::sync::atomic::Ordering::Release);
                    continue;
                };
                ring.free_heads.push(head);
                ring.pending.remove(position)
            };
            let mut request = pending.request;
            let bounce = h.wrapping_add(pending.bounce_pa) as *const u8;
            // SAFETY: the per-request `alloc_contig(BOUNCE_ORDER)` block, still
            // owned by this `PendingRequest` (removed from `pending` above, not
            // yet freed). Its descriptor head came back in the used ring, so the
            // device has finished with it. STATUS_OFF is in bounds.
            let status = unsafe { core::ptr::read_volatile(bounce.add(STATUS_OFF)) };
            let result = match blk::decode_status(status) {
                Ok(()) if pending.is_in => {
                    if request.buffer.len() < pending.data_len as usize {
                        Err(BlockError::Eio)
                    } else {
                        // SAFETY: same retired bounce block; the length check
                        // above bounds `data_len` by the caller's buffer, and
                        // `owned_request_plan` bounded it by BOUNCE_DATA_BYTES,
                        // so `DATA_OFF + offset` is inside the block.
                        unsafe {
                            for (offset, byte) in request.buffer[..pending.data_len as usize].iter_mut().enumerate() {
                                *byte = core::ptr::read_volatile(bounce.add(DATA_OFF + offset));
                            }
                        }
                        Ok(())
                    }
                }
                Ok(()) => Ok(()),
                Err(st) => Err(block_error_for_status(st)),
            };
            // SAFETY: the device returned this descriptor head in used.ring;
            // the DMA region is no longer reachable by the device.
            unsafe { pmm::setup::free_contig(pending.bounce_pa, pmm::Order(BOUNCE_ORDER)); }
            // Counted at DELIVERY, not at ring-entry consumption: a used entry
            // whose head matches no pending request poisons the device above
            // and delivers nothing, and reporting it as a completion would tell
            // a poll loop it made progress it did not make.
            found += 1;
            (pending.completion)(request, result);
            self.start_deferred_requests(q);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RING_SIZE: u16 = 8;

    /// The Virtio 1.2 §2.7.8 used-ring layout the walker's volatile loads
    /// assume. An off-by-one here reads a length as a descriptor id and
    /// silently poisons the device on every completion.
    #[test]
    fn used_ring_offsets_match_the_split_ring_layout() {
        assert_eq!(USED_IDX_OFF, 2);
        assert_eq!(used_entry_id_off(0), 4);
        assert_eq!(used_entry_id_off(1), 12);
        assert_eq!(used_entry_id_off(3), 28);
    }

    /// A drain never touches a queue that has no ring, and never consumes the
    /// entry a synchronous turn-holder is parked on.
    #[test]
    fn a_drain_is_refused_without_a_ring_or_against_a_synchronous_owner() {
        assert!(drain_admitted(false, 0xffff_8000_0000_0000, 0x1000, RING_SIZE));
        assert!(!drain_admitted(true, 0xffff_8000_0000_0000, 0x1000, RING_SIZE), "busy owner keeps its entry");
        assert!(!drain_admitted(false, 0, 0x1000, RING_SIZE), "no HHDM, no ring to walk");
        assert!(!drain_admitted(false, 0xffff_8000_0000_0000, 0, RING_SIZE), "unprogrammed used area");
        assert!(!drain_admitted(false, 0xffff_8000_0000_0000, 0x1000, 0), "zero-sized queue");
    }

    /// The claim-once rule, driven the way the bug would arrive: two drainers
    /// alternating over ONE cursor. Every published entry must be claimed by
    /// exactly one of them, and neither may claim past `used.idx`.
    #[test]
    fn two_interleaved_drains_claim_each_used_entry_exactly_once() {
        const PUBLISHED: u16 = 5;
        let mut used_seen = 0u16;
        let mut claimed_by_a = alloc::vec::Vec::new();
        let mut claimed_by_b = alloc::vec::Vec::new();
        loop {
            let a = claim_next_used(&mut used_seen, PUBLISHED, RING_SIZE);
            let b = claim_next_used(&mut used_seen, PUBLISHED, RING_SIZE);
            if a.is_none() && b.is_none() { break; }
            if let Some(slot) = a { claimed_by_a.push(slot); }
            if let Some(slot) = b { claimed_by_b.push(slot); }
            assert!(claimed_by_a.len() + claimed_by_b.len() <= PUBLISHED as usize,
                "a claim past what the device published means the cursor did not advance");
        }
        let mut all: alloc::vec::Vec<usize> =
            claimed_by_a.iter().chain(claimed_by_b.iter()).copied().collect();
        // Counted as a MULTISET: a set would dedupe the double-claim this test
        // exists to catch.
        assert_eq!(all.len(), PUBLISHED as usize, "one claim per published entry, no more");
        all.sort_unstable();
        assert_eq!(all, alloc::vec![0, 1, 2, 3, 4]);
        assert_eq!(used_seen, PUBLISHED, "the cursor stops at what the device published");
    }

    /// A drained ring hands out nothing, however many times it is asked.
    #[test]
    fn a_drained_ring_claims_nothing() {
        let mut used_seen = 7u16;
        assert_eq!(claim_next_used(&mut used_seen, 7, RING_SIZE), None);
        assert_eq!(claim_next_used(&mut used_seen, 7, RING_SIZE), None);
        assert_eq!(used_seen, 7, "a refused claim must not move the cursor");
        let mut used_seen = 0u16;
        assert_eq!(claim_next_used(&mut used_seen, 4, 0), None, "a zero-sized queue has no slot");
    }

    /// The cursor and `used.idx` are free-running u16s: the walk must keep
    /// working across the wrap, and the slot must stay inside the ring.
    #[test]
    fn the_cursor_wraps_with_the_free_running_used_index() {
        let mut used_seen = u16::MAX - 1;
        let used_idx = 1u16;
        let mut slots = alloc::vec::Vec::new();
        while let Some(slot) = claim_next_used(&mut used_seen, used_idx, RING_SIZE) {
            assert!(slot < RING_SIZE as usize);
            slots.push(slot);
            assert!(slots.len() <= 8, "the wrap must terminate");
        }
        assert_eq!(slots.len(), 3, "0xFFFE, 0xFFFF and 0x0000 were published");
        assert_eq!(used_seen, used_idx);
    }
}
