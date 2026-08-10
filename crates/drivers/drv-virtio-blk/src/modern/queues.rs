// Which virtqueues this driver runs, and which one of them carries no
// interrupt. Every decision here is arithmetic over the negotiated feature
// word and the device's advertised queue count, so it is testable without a
// device — the ring access that acts on the decision lives in `drain.rs` and
// `post.rs`.

use super::*;

/// Request queues this driver programs: one interrupt-driven default queue and
/// at most one polling queue. Capped by the queue plan the transport programs.
pub(super) const MAX_REQUEST_QUEUES: u16 = 2;

/// Polling queues taken when the device can spare one. A polled queue is only
/// worth having if something polls it, and every disk this kernel registers is
/// reachable through the polled submission path, so one is taken whenever the
/// device offers a queue to spare.
pub(super) const DEFAULT_POLL_QUEUES: u16 = 1;

/// Request queues actually usable. Without `VIRTIO_BLK_F_MQ` negotiated the
/// device has exactly one request queue no matter what its config space says
/// (§5.2.4 makes `num_queues` meaningful only under that bit), and a device
/// that advertises MQ with zero queues is malformed and gets the same answer.
/// # C: O(1)
pub(super) fn usable_queue_count(drv_features: u64, cfg_num_queues: u16) -> u16 {
    if drv_features & virtio::VIRTIO_BLK_F_MQ == 0 { return 1; }
    if cfg_num_queues == 0 { return 1; }
    core::cmp::min(cfg_num_queues, MAX_REQUEST_QUEUES)
}

/// Index of the dedicated polling virtqueue, or `None` when this device leaves
/// none to spare.
///
/// The split: a poll queue is never taken at the cost of the last default
/// queue, because interrupt-driven I/O still has to work, and poll queues are
/// the TAIL of the queue array. With one of each that tail is index 1.
/// # C: O(1)
pub(super) fn poll_queue_index(
    drv_features: u64, cfg_num_queues: u16, requested_poll_queues: u16,
) -> Option<u16> {
    let usable = usable_queue_count(drv_features, cfg_num_queues);
    let poll = core::cmp::min(requested_poll_queues, usable.saturating_sub(1));
    if poll == 0 { None } else { Some(usable - poll) }
}

/// One request virtqueue and the driver-side shadow of its rings.
///
/// # Lk: `inflight` is taken with `lock_bh` on EVERY path, because the default
/// queue's ring is walked by the block softirq as well as by process context.
/// A poll queue is never touched by the softirq — nothing raises one for it —
/// but it keeps the same discipline so the two queues cannot drift into
/// different locking rules.
pub struct BlkQueue {
    pub(super) res: virtio::VirtQueueResource,
    pub(super) inflight: Spinlock<RingShadow, DriverLockClass>,
    /// Interrupt-free: no MSI-X vector is bound to this queue and its
    /// `avail.flags` carry `VRING_AVAIL_F_NO_INTERRUPT`, so its completions
    /// reach the driver only through `poll_completions`.
    pub(super) polled: bool,
}

impl BlkQueue {
    pub(super) fn new(res: virtio::VirtQueueResource, seed: u16, polled: bool) -> Self {
        Self {
            res,
            inflight: Spinlock::new(RingShadow {
                avail_idx: seed, used_seen: seed, busy: false,
                free_heads: request_heads(res.size), pending: Vec::new(), deferred: Vec::new(),
            }),
            polled,
        }
    }

    /// # Lk: `inflight` under the softirq gate — the single discipline every
    /// caller uses, so a softirq drain and a process-context poll or submit can
    /// never interleave inside one ring update. # C: O(1)
    pub(super) fn lock(&self)
        -> sync::LockBhGuard<'_, RingShadow, DriverLockClass, sched::bh::SchedBh>
    {
        self.inflight.lock_bh::<sched::bh::SchedBh>()
    }
}

/// Whether the completion softirq owns this queue's used ring. It owns every
/// queue whose completions the device signals — the interrupt is what runs it
/// — and no others.
/// # C: O(1)
pub(super) fn softirq_drains(q: &BlkQueue) -> bool { !q.polled }

/// Whether a poll owns this queue's used ring. Exactly the queues the softirq
/// does not: an entry claimed by both contexts is a completion delivered
/// twice, and an entry claimed by neither never completes at all.
/// # C: O(1)
pub(super) fn poll_drains(q: &BlkQueue) -> bool { q.polled }

/// Tell the device to stop raising interrupts for this queue's completions by
/// setting `VRING_AVAIL_F_NO_INTERRUPT` in its driver area (Virtio 1.2
/// §2.7.6). Called once, before any buffer is made available on the queue, so
/// the device cannot be mid-completion on it.
/// # C: O(1)
pub(super) fn suppress_queue_interrupts(hhdm: u64, res: &virtio::VirtQueueResource) {
    if hhdm == 0 || res.driver_pa == 0 { return; }
    let avail = hhdm.wrapping_add(res.driver_pa + virtio::VRING_AVAIL_FLAGS_OFF) as *mut u16;
    // SAFETY: `driver_pa` is this queue's own avail frame, allocated and zeroed
    // by the transport and reachable through the HHDM; Virtio 1.2 §2.7.6 puts
    // `flags` at its first, u16-aligned, byte. No descriptor has been published
    // on this queue yet, so no other agent is reading the field.
    unsafe { core::ptr::write_volatile(avail, virtio::VRING_AVAIL_F_NO_INTERRUPT); }
}

#[cfg(test)]
pub(super) fn unprogrammed_queue(index: u16) -> virtio::VirtQueueResource {
    virtio::VirtQueueResource::new(index, 0, 0, 0, 0, 0, 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MQ: u64 = virtio::VIRTIO_BLK_F_MQ;

    /// `num_queues` is meaningless without the multiqueue bit negotiated: a
    /// device that advertises four queues in a config space the driver did not
    /// unlock still has exactly one usable request queue, and using a second
    /// would be a spec violation with no ring behind it.
    #[test]
    fn a_device_without_the_multiqueue_bit_has_exactly_one_request_queue() {
        assert_eq!(usable_queue_count(0, 4), 1);
        assert_eq!(usable_queue_count(virtio::VIRTIO_BLK_F_FLUSH, 8), 1);
        assert_eq!(poll_queue_index(0, 4, 1), None, "no MQ, no queue to poll");
    }

    /// A device that claims multiqueue and then reports zero queues is
    /// malformed; treat it as the single-queue device it actually is rather
    /// than computing a queue index from nonsense.
    #[test]
    fn a_multiqueue_device_reporting_zero_queues_falls_back_to_one() {
        assert_eq!(usable_queue_count(MQ, 0), 1);
        assert_eq!(poll_queue_index(MQ, 0, 1), None);
    }

    /// One spare queue becomes the poll queue, at the tail of the queue array.
    /// The default queue keeps index 0 so interrupt-driven I/O is unaffected.
    #[test]
    fn a_spare_queue_becomes_the_polling_queue_at_the_tail() {
        assert_eq!(usable_queue_count(MQ, 2), 2);
        assert_eq!(poll_queue_index(MQ, 2, 1), Some(1));
        assert_eq!(poll_queue_index(MQ, 8, 1), Some(1), "only two queues are programmed");
    }

    /// A poll queue is never taken at the cost of the LAST default queue:
    /// interrupt-driven submission has to keep working, and a device with one
    /// queue has none to spare.
    #[test]
    fn a_single_queue_device_keeps_it_for_interrupt_driven_io() {
        assert_eq!(poll_queue_index(MQ, 1, 1), None);
        assert_eq!(poll_queue_index(MQ, 1, 4), None, "asking for more cannot take the only queue");
    }

    /// Asking for no poll queues yields none even on a device that could
    /// spare one — the count is the input, not the device's generosity.
    #[test]
    fn requesting_no_poll_queues_leaves_every_queue_interrupt_driven() {
        assert_eq!(poll_queue_index(MQ, 2, 0), None);
        assert_eq!(DEFAULT_POLL_QUEUES, 1, "this driver asks for one");
    }

    /// The whole safety argument for two drain contexts: they PARTITION the
    /// queues. A queue both would drain is a completion delivered twice, with
    /// the request's DMA buffer freed twice behind it; a queue neither drains
    /// never completes. Asserted as a partition, not as two separate rules,
    /// because it is the overlap and the gap that are the bugs.
    #[test]
    fn the_softirq_and_a_poll_partition_the_queues_between_them() {
        let interrupt_driven = BlkQueue::new(unprogrammed_queue(0), 0, false);
        let interrupt_free = BlkQueue::new(unprogrammed_queue(1), 0, true);
        for q in [&interrupt_driven, &interrupt_free] {
            assert_ne!(softirq_drains(q), poll_drains(q),
                "each queue is drained by exactly one context");
        }
        assert!(softirq_drains(&interrupt_driven), "a signalled queue belongs to the softirq");
        assert!(poll_drains(&interrupt_free), "an interrupt-free queue belongs to the poller");
    }
}

/// # C: O(1)
#[cfg(test)]
pub fn suppress_queue_interrupts_for_tests(hhdm: u64, res: &virtio::VirtQueueResource) {
    suppress_queue_interrupts(hhdm, res);
}
