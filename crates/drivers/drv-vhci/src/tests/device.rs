use super::*;
use bluetooth::uapi::hci::{HCI_COMMAND_PKT, HCI_VENDOR_PKT};
use crate::protocol::{parse_create_opcode, CREATE_ACK_MARK};

fn frame(n: u8) -> Vec<u8> { alloc::vec![HCI_COMMAND_PKT, n] }

#[test]
fn a_fresh_description_owns_no_controller() {
    let d = VhciDevice::new();
    assert!(!d.has_device());
    assert_eq!(d.index(), None);
    assert!(!d.readable());
}

// Sending before a controller exists has nowhere to go, and must not silently
// queue a frame that would later be handed to an unrelated controller.
#[test]
fn the_transport_refuses_to_send_before_a_controller_exists() {
    let d = VhciDevice::new();
    assert_eq!(d.send(&frame(1)), Err(Errno::Enodev));
    assert_eq!(d.open(), Err(Errno::Enodev));
    assert!(!d.readable());
}

#[test]
fn attaching_records_the_index_and_queues_the_acknowledgement_first() {
    let d = VhciDevice::new();
    d.send(&frame(1)).ok();
    let flags = parse_create_opcode(0x00).unwrap();
    d.attach(flags, 7);
    assert!(d.has_device());
    assert_eq!(d.index(), Some(7));
    let first = d.read_frame().unwrap();
    assert_eq!(first[0], HCI_VENDOR_PKT);
    assert_eq!(first[1], CREATE_ACK_MARK);
    assert_eq!(&first[3..5], &[7, 0]);
}

#[test]
fn a_sent_frame_reaches_the_reader_unchanged_and_in_order() {
    let d = VhciDevice::new();
    d.attach(parse_create_opcode(0).unwrap(), 0);
    d.read_frame();
    for n in 0..4u8 { d.send(&frame(n)).unwrap(); }
    for n in 0..4u8 { assert_eq!(d.read_frame().unwrap(), frame(n)); }
    assert!(d.read_frame().is_none());
}

// A process that stops reading must not grow kernel memory without bound.
// Dropping the OLDEST is what a transport does: refusing new frames would
// instead stall the stack producing them.
#[test]
fn a_reader_that_falls_behind_loses_the_oldest_frames_not_the_newest() {
    let mut q = ReadQueue::new();
    for n in 0..(READ_QUEUE_LIMIT + 3) { q.push(alloc::vec![n as u8]); }
    assert_eq!(q.len(), READ_QUEUE_LIMIT);
    assert_eq!(q.dropped(), 3);
    // The three oldest went; the newest survived.
    assert_eq!(q.pop().unwrap(), alloc::vec![3u8]);
    let mut last = alloc::vec![];
    while let Some(f) = q.pop() { last = f; }
    assert_eq!(last, alloc::vec![(READ_QUEUE_LIMIT + 2) as u8]);
}

#[test]
fn a_queue_at_the_limit_reports_every_further_drop() {
    let mut q = ReadQueue::new();
    for _ in 0..READ_QUEUE_LIMIT { q.push(alloc::vec![0]); }
    assert_eq!(q.dropped(), 0);
    q.push(alloc::vec![1]);
    assert_eq!(q.dropped(), 1);
}

#[test]
fn detaching_forgets_the_controller_and_discards_what_was_queued() {
    let d = VhciDevice::new();
    d.attach(parse_create_opcode(0).unwrap(), 2);
    d.send(&frame(9)).unwrap();
    assert!(d.readable());
    d.detach();
    assert!(!d.has_device());
    assert!(!d.readable());
    assert_eq!(d.send(&frame(9)), Err(Errno::Enodev));
}

#[test]
fn closing_the_transport_discards_what_was_queued_but_keeps_the_controller() {
    let d = VhciDevice::new();
    d.attach(parse_create_opcode(0).unwrap(), 1);
    d.send(&frame(1)).unwrap();
    d.close();
    assert!(!d.readable());
    assert!(d.has_device());
    assert_eq!(d.open(), Ok(()));
}

#[test]
fn the_transport_reports_the_virtual_bus_and_its_driver_name() {
    let d = VhciDevice::new();
    assert_eq!(d.bus(), bluetooth::uapi::hci::HCI_VIRTUAL);
    assert_eq!(d.driver_name().as_str(), "vhci");
}

#[test]
fn the_requested_properties_are_kept_for_the_acknowledgement_to_echo() {
    let d = VhciDevice::new();
    let flags = parse_create_opcode(crate::protocol::CREATE_RAW_DEVICE).unwrap();
    d.attach(flags, 0);
    assert!(d.flags().raw_device);
    assert_eq!(d.read_frame().unwrap()[2], crate::protocol::CREATE_RAW_DEVICE);
}
