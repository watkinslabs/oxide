// Completion polling: which disks offer it, which queue a polled request goes
// to, and what a poll is allowed to consume.
//
// The decision logic these tests exercise is ungated by construction — queue
// selection lives in `modern/queues.rs` and the used-ring cursor in
// `modern/drain.rs`, both of which carry their own unit tests. What is
// exercised HERE is the device surface a caller keys on.

use super::*;
use crate::modern::BlkState;

fn state() -> std::sync::Arc<BlkState> {
    let mut cfg = [0u8; 64];
    std::sync::Arc::new(BlkState::for_test_cfg(cfg.as_mut_ptr() as u64))
}

fn state_with_poll_queue() -> std::sync::Arc<BlkState> {
    let mut cfg = [0u8; 64];
    std::sync::Arc::new(BlkState::for_test_cfg_with_poll_queue(cfg.as_mut_ptr() as u64, true))
}

/// A disk is pollable exactly when the device gave it an interrupt-free queue.
/// Polling a queue the device still interrupts saves the wait but not the
/// interrupt, so it must not be offered as a polled disk: a caller admitted on
/// that promise would pay the interrupt anyway.
#[test]
fn only_a_device_with_an_interrupt_free_queue_is_pollable() {
    assert!(!state().can_poll(), "one interrupt-driven queue is not a poll capability");
    assert!(state_with_poll_queue().can_poll(), "a dedicated interrupt-free queue is");
}

/// The capability is a property of the DEVICE, not of what a poll just found:
/// an idle poll queue reaps nothing and stays pollable. Deriving the
/// capability from "did this poll find work" would refuse a device the moment
/// it went quiet.
#[test]
fn an_idle_poll_queue_reaps_nothing_and_stays_pollable() {
    let s = state_with_poll_queue();
    assert!(s.can_poll());
    assert_eq!(s.poll_completions(), 0, "unprogrammed queue reaps nothing");
    assert!(s.can_poll(), "reaping nothing does not revoke the capability");
}

/// A device with no poll queue answers zero rather than reaching for the
/// interrupt-driven queue. Draining that queue here would take completions the
/// block softirq owns, and would report a saving that was never made.
#[test]
fn a_device_without_a_poll_queue_reaps_nothing_at_all() {
    let s = state();
    assert_eq!(s.poll_completions(), 0);
}

/// A synchronous request owns its descriptor and observes `used.idx` itself,
/// so no drain may consume its entry. A poll that ignored it would eat the
/// completion the synchronous waiter is parked on.
#[test]
fn a_poll_does_not_consume_a_synchronous_owners_completion() {
    let s = state_with_poll_queue();
    s.hold_inflight_for_tests();
    assert_eq!(s.poll_completions(), 0, "the turn holder's entry is left in the ring");
    s.release_inflight_for_tests();
}

/// The routing rule, at the device surface: a request that says a poller will
/// reap it goes to the interrupt-free queue, everything else to the queue the
/// device signals. On a device with no poll queue every request goes to the
/// one queue there is — a polled request must never be posted to a queue
/// nobody will drain.
#[test]
fn a_polled_request_is_issued_on_the_interrupt_free_queue() {
    let s = state_with_poll_queue();
    assert!(s.queue_is_polled_for_tests(true), "polled request takes the interrupt-free queue");
    assert!(!s.queue_is_polled_for_tests(false), "ordinary request keeps the interrupt");

    let s = state();
    assert!(!s.queue_is_polled_for_tests(true),
        "with no poll queue a polled request still goes somewhere that completes it");
    assert!(!s.queue_is_polled_for_tests(false));
}

/// The interrupt-driven queue and the interrupt-free one are DISTINCT rings.
/// One ring reached by both the softirq and a poller is the shared-queue shape
/// this separation exists to remove.
#[test]
fn the_poll_queue_is_a_second_ring_beside_the_interrupt_driven_one() {
    let s = state_with_poll_queue();
    assert_eq!(s.queue_count_for_tests(), 2);
    assert_eq!(s.poll_queue_index_for_tests(), Some(virtio::POLL_QUEUE_INDEX));
    assert_eq!(state().queue_count_for_tests(), 1);
    assert_eq!(state().poll_queue_index_for_tests(), None);
}

/// The interrupt-free queue is only interrupt-free because the device is told
/// so in its driver area. Programming the ring and forgetting this store gives
/// back a queue that interrupts on every completion while every other signal
/// says it does not.
#[test]
fn the_poll_queue_avail_flags_suppress_device_notifications() {
    const DRIVER_PA: u64 = 0x1000;
    let mut driver_area = [0u16; 8];
    // The driver addresses a ring area as `hhdm + driver_pa`; place the fake
    // window so that sum lands on this array.
    let window = (driver_area.as_mut_ptr() as u64).wrapping_sub(DRIVER_PA);
    let programmed =
        virtio::VirtQueueResource::new(virtio::POLL_QUEUE_INDEX, 8, 0x2000, DRIVER_PA, 0x3000, 0x4000, 1);
    let unprogrammed =
        virtio::VirtQueueResource::new(virtio::POLL_QUEUE_INDEX, 8, 0x2000, 0, 0x3000, 0x4000, 1);

    crate::modern::suppress_queue_interrupts_for_tests(0, &programmed);
    assert_eq!(driver_area[0], 0, "with no HHDM window there is no driver area to write");
    crate::modern::suppress_queue_interrupts_for_tests(window, &unprogrammed);
    assert_eq!(driver_area[0], 0, "an unprogrammed driver area is never written");

    crate::modern::suppress_queue_interrupts_for_tests(window, &programmed);
    assert_eq!(driver_area[0], virtio::VRING_AVAIL_F_NO_INTERRUPT,
        "the device is told not to signal this queue's completions");
    assert_eq!(driver_area[1], 0, "only the flags field is written; avail.idx is the device's");
}

/// The IRQ entry point is the only producer of the completion-interrupt
/// counter. A poll of the interrupt-free ring leaves it unchanged, while the
/// production entry-point helper advances it exactly once.
#[test]
fn interrupt_accounting_distinguishes_irq_from_polling() {
    let before = crate::modern::completion_interrupt_count();
    assert_eq!(state_with_poll_queue().poll_completions(), 0);
    assert_eq!(crate::modern::completion_interrupt_count(), before);

    crate::modern::note_completion_interrupt_for_tests();
    assert_eq!(crate::modern::completion_interrupt_count(), before + 1);
}
