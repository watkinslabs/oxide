// Behaviour contract for the RX bottom half. These encode what was verified
// against the reference implementation's receive path — admission arithmetic,
// what a drop is accounted against, the two-queue splice, the budget/weight
// loop, and the positional `/proc/net/softnet_stat` columns — so a later change
// can re-check the contract without the repository citing anything external.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::limits::{NETDEV_BUDGET, NETDEV_MAX_BACKLOG, SOFTNET_COLUMNS};
use super::queue::{BacklogItem, RxVerdict, SoftnetData, SoftnetRow};
use super::softnet::render_softnet_stat;
use crate::addr::NetIfaceId;
use crate::loopback::LoopbackDev;
use crate::netdev::NetDev;
use crate::pkt::Pkt;

const IFACE: NetIfaceId = NetIfaceId::from_raw(1);

fn item(byte: u8) -> BacklogItem {
    let mut pkt = Pkt::with_capacity(0, 1);
    pkt.put(1).unwrap()[0] = byte;
    BacklogItem { iface: IFACE, pkt }
}

/// One packet that reaches protocol delivery and is rejected there: a
/// truncated IPv4 frame. Delivery failure is the observable that proves the
/// frame travelled the whole poll-list → backlog → delivery route.
fn malformed_ipv4() -> Pkt {
    let mut pkt = Pkt::with_capacity(0, 1);
    pkt.put(1).unwrap()[0] = 0;
    pkt.proto = crate::addr::eth_p::IPV4;
    pkt
}

// ---- admission -----------------------------------------------------------

#[test]
fn admission_holds_one_more_than_the_cap_then_drops() {
    let mut sd = SoftnetData::new();
    // The cap is compared against the length BEFORE the push, so the queue
    // reaches NETDEV_MAX_BACKLOG + 1 entries. Encoded exactly; "tidying" this
    // to a strict cap silently changes the depth every tuning assumes.
    for i in 0..=NETDEV_MAX_BACKLOG {
        assert_eq!(sd.enqueue(item(i as u8)), RxVerdict::Success, "entry {i}");
    }
    assert_eq!(sd.len(), NETDEV_MAX_BACKLOG + 1);
    assert_eq!(sd.enqueue(item(0)), RxVerdict::Drop);
    assert_eq!(sd.len(), NETDEV_MAX_BACKLOG + 1, "a refused frame is not queued");
    assert_eq!(sd.row().dropped, 1);
}

#[test]
fn a_refused_frame_is_dropped_not_deferred() {
    let mut sd = SoftnetData::new();
    for _ in 0..=NETDEV_MAX_BACKLOG { sd.enqueue(item(1)); }
    for _ in 0..5 { assert_eq!(sd.enqueue(item(2)), RxVerdict::Drop); }
    assert_eq!(sd.row().dropped, 5);
    // Draining does not resurrect them: exactly the admitted frames come back.
    let mut seen = 0;
    while sd.dequeue().is_some() { seen += 1; }
    assert_eq!(seen, NETDEV_MAX_BACKLOG + 1);
}

// ---- the two queues ------------------------------------------------------

#[test]
fn dequeue_splices_input_into_process_and_preserves_order() {
    let mut sd = SoftnetData::new();
    for i in 0..4u8 { sd.enqueue(item(i)); }
    assert_eq!(sd.row().input_qlen, 4);
    assert_eq!(sd.row().process_qlen, 0);

    let first = sd.dequeue().expect("frame");
    assert_eq!(first.pkt.data(), &[0]);
    // The whole input queue moved across in one splice, as the reference does,
    // so producers append behind the drain rather than in front of it.
    assert_eq!(sd.row().input_qlen, 0);
    assert_eq!(sd.row().process_qlen, 3);

    for expect in 1..4u8 {
        assert_eq!(sd.dequeue().expect("frame").pkt.data(), &[expect]);
    }
    assert!(sd.dequeue().is_none());
    assert!(sd.is_empty());
}

#[test]
fn frames_enqueued_during_a_drain_are_taken_on_the_next_splice() {
    let mut sd = SoftnetData::new();
    sd.enqueue(item(1));
    assert_eq!(sd.dequeue().expect("frame").pkt.data(), &[1]);
    // Process queue now empty, input queue empty. A frame produced by receive
    // processing itself (an ACK looped straight back) must still be picked up.
    sd.enqueue(item(2));
    assert_eq!(sd.dequeue().expect("frame").pkt.data(), &[2]);
}

#[test]
fn processed_counts_frames_handed_to_delivery() {
    let mut sd = SoftnetData::new();
    for i in 0..3u8 { sd.enqueue(item(i)); }
    assert_eq!(sd.row().processed, 0);
    sd.dequeue();
    sd.dequeue();
    assert_eq!(sd.row().processed, 2);
}

#[test]
fn purge_accounts_every_queued_frame_as_a_drop() {
    let mut sd = SoftnetData::new();
    for i in 0..3u8 { sd.enqueue(item(i)); }
    sd.dequeue();
    sd.purge();
    assert!(sd.is_empty());
    assert_eq!(sd.row().dropped, 2, "the two still queued, not the delivered one");
}

// ---- /proc/net/softnet_stat ---------------------------------------------

#[test]
fn softnet_stat_row_is_fifteen_hex_columns_per_cpu() {
    let rows = [SoftnetRow::default(); 3];
    let text = render_softnet_stat(&rows);
    let text = core::str::from_utf8(&text).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3, "one row per CPU, no header line");
    for line in &lines {
        let cols: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(cols.len(), SOFTNET_COLUMNS);
        for c in &cols { assert_eq!(c.len(), 8, "fixed-width 8-digit hex: {c}"); }
    }
}

#[test]
fn softnet_stat_columns_are_positional() {
    let rows = [
        SoftnetRow::default(),
        SoftnetRow { processed: 0x11, dropped: 0x22, time_squeeze: 0x33,
                     input_qlen: 4, process_qlen: 5 },
    ];
    let text = render_softnet_stat(&rows);
    let text = core::str::from_utf8(&text).unwrap();
    let cols: Vec<u32> = text.lines().nth(1).unwrap().split_whitespace()
        .map(|c| u32::from_str_radix(c, 16).unwrap()).collect();
    assert_eq!(cols[0], 0x11, "processed");
    assert_eq!(cols[1], 0x22, "dropped");
    assert_eq!(cols[2], 0x33, "time_squeeze");
    // Columns 3..=10 are retired upstream but still emitted so positional
    // parsers keep working.
    for i in 3..=10 { assert_eq!(cols[i], 0, "retired column {i} must stay zero"); }
    assert_eq!(cols[11], 9, "total backlog length");
    assert_eq!(cols[12], 1, "CPU index is the row index");
    assert_eq!(cols[13], 4, "input_pkt_queue length");
    assert_eq!(cols[14], 5, "process_queue length");
}

// ---- poll list -----------------------------------------------------------

static POLLED: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
fn probe_poll() { POLLED.fetch_add(1, core::sync::atomic::Ordering::Relaxed); }

#[test]
fn poll_list_registration_is_idempotent_and_reversible() {
    use core::sync::atomic::Ordering;
    super::napi::unregister_poll(probe_poll);
    POLLED.store(0, Ordering::Relaxed);
    assert!(super::napi::register_poll(probe_poll));
    assert!(super::napi::register_poll(probe_poll), "second register is a no-op");
    let before = super::napi::registered();
    super::napi::poll_all();
    assert_eq!(POLLED.load(Ordering::Relaxed), 1, "one entry, polled once");
    super::napi::unregister_poll(probe_poll);
    assert_eq!(super::napi::registered(), before - 1);
    super::napi::poll_all();
    assert_eq!(POLLED.load(Ordering::Relaxed), 1, "unregistered entry is not polled");
}

#[test]
fn registering_a_poll_claims_the_net_rx_slot() {
    // A driver poll registered before anything raises NET_RX must still find a
    // handler installed, or its frames would be queued with nothing to drain
    // them. Registration installs; the observable is that the slot's handler
    // pointer is non-null afterwards.
    super::napi::unregister_poll(probe_poll);
    assert!(super::napi::register_poll(probe_poll));
    super::napi::unregister_poll(probe_poll);
    assert!(super::action::installed());
    let previous = softirq::set_handler(softirq::Slot::NetRx, super::action::net_rx_action);
    assert!(!previous.is_null(), "NET_RX slot was already claimed by the drain");
}

// ---- the drain pass ------------------------------------------------------

#[test]
fn a_pass_moves_frames_from_the_poll_list_through_delivery() {
    let stack = crate::NetStack::new();
    let lo = Arc::new(LoopbackDev::new());
    let iface = stack.ifaces.register(lo.clone());
    stack.register_rx_poll(iface, &lo);
    lo.xmit(malformed_ipv4()).unwrap();

    assert!(!stack.do_net_rx(), "one pass suffices for one frame");
    assert_eq!(lo.rx_len(), 0, "the device queue was drained into the backlog");
    assert_eq!(lo.stats().rx_packets, 1);
    assert_eq!(lo.stats().rx_errors, 1, "delivery rejected it — it reached delivery");
}

#[test]
fn a_pass_stops_at_its_budget_and_reports_work_remaining() {
    let stack = crate::NetStack::new();
    let lo = Arc::new(LoopbackDev::new());
    let iface = stack.ifaces.register(lo.clone());
    stack.register_rx_poll(iface, &lo);
    // One more than the budget: the pass must deliver exactly the budget and
    // tell its caller to come back rather than run the queue to completion.
    for _ in 0..=NETDEV_BUDGET { lo.xmit(malformed_ipv4()).unwrap(); }

    assert!(stack.do_net_rx(), "budget exhausted with work left");
    assert_eq!(lo.stats().rx_errors as usize, NETDEV_BUDGET);
    let squeezed: u64 = stack.softnet_rows().iter().map(|r| r.time_squeeze).sum();
    assert_eq!(squeezed, 1, "a truncated pass is accounted as a time squeeze");

    assert!(!stack.do_net_rx(), "the remainder finishes on the next pass");
    assert_eq!(lo.stats().rx_errors as usize, NETDEV_BUDGET + 1);
}

#[test]
fn a_retired_poll_entry_leaves_the_list_with_its_device() {
    let stack = crate::NetStack::new();
    let lo = Arc::new(LoopbackDev::new());
    // Poll list only: the interface registry retains its own strong reference,
    // so the last owner going away is what this covers.
    stack.register_rx_poll(IFACE, &lo);
    drop(lo);
    // The list holds a weak reference, so nothing has to unregister: a pass
    // over a list whose only device is gone is a no-op, not a dangling poll.
    assert!(!stack.do_net_rx());
    assert!(stack.rx_poll.lock().is_empty());
}

#[test]
fn frames_queued_for_a_down_interface_are_dropped_at_delivery() {
    let stack = crate::NetStack::new();
    let lo = Arc::new(LoopbackDev::new());
    // Never registered in the interface table: the delivery-time ingress
    // acquire fails, which is the same observable a device going down between
    // enqueue and drain produces.
    assert_eq!(stack.netif_rx(NetIfaceId::from_raw(4242), malformed_ipv4()),
               RxVerdict::Success);
    assert!(!stack.do_net_rx());
    let dropped: u64 = stack.softnet_rows().iter().map(|r| r.dropped).sum();
    assert_eq!(dropped, 1);
    assert_eq!(lo.stats().rx_errors, 0);
}
