use super::*;
use crate::hci::filter::Filter;
use crate::hci::mon::parse_header;
use crate::hci::packet::build_frame;
use crate::uapi::hci::HCI_EVENT_PKT;
use crate::uapi::hci_mon::{HCI_MON_EVENT_PKT, HCI_MON_HDR_SIZE};
use crate::uapi::hci_sock::HCI_DEV_NONE;
use super::super::hci_sock::plan_bind;

fn exists(_d: u16) -> bool { true }

fn bound(channel: u16, dev: u16, pass_all: bool) -> Arc<HciSocketFile> {
    let f = Arc::new(HciSocketFile::new());
    {
        let mut st = f.state.lock();
        st.bind(plan_bind(channel, dev, true, exists).unwrap()).unwrap();
        if pass_all { st.filter = Filter::pass_all(); }
    }
    register(&f);
    f
}

fn ev() -> alloc::vec::Vec<u8> { build_frame(HCI_EVENT_PKT, 0x0e, &[0x01, 0x03, 0x0c, 0x00]).unwrap() }

// Each test registers into one global list, so every one withdraws what it
// registered; a leaked socket would silently receive another test's frames.
struct Cleanup(alloc::vec::Vec<Arc<HciSocketFile>>);
impl Drop for Cleanup {
    fn drop(&mut self) { for s in &self.0 { unregister(s); } }
}

#[test]
fn a_raw_socket_receives_the_frame_itself() {
    let s = bound(HCI_CHANNEL_RAW, 0, true);
    let _c = Cleanup(alloc::vec![Arc::clone(&s)]);
    assert_eq!(deliver(0, &ev(), Dir::Rx), 1);
    assert_eq!(s.state.lock().pop().unwrap(), ev());
}

// A monitor socket receives the frame wrapped in a record, because that is the
// format a trace is made of; handing it the bare frame would produce a trace
// one header short.
#[test]
fn a_monitor_socket_receives_a_record_rather_than_the_bare_frame() {
    let s = bound(HCI_CHANNEL_MONITOR, HCI_DEV_NONE, false);
    let _c = Cleanup(alloc::vec![Arc::clone(&s)]);
    assert_eq!(deliver(2, &ev(), Dir::Rx), 1);
    let got = s.state.lock().pop().unwrap();
    assert_ne!(got, ev());
    let (opcode, index, len) = parse_header(&got).unwrap();
    assert_eq!((opcode, index), (HCI_MON_EVENT_PKT, 2));
    assert_eq!(len as usize, ev().len() - 1);
    assert_eq!(&got[HCI_MON_HDR_SIZE..], &ev()[1..]);
}

// A socket attached to one controller must never receive another's traffic.
#[test]
fn a_frame_reaches_only_the_sockets_bound_to_its_controller() {
    let a = bound(HCI_CHANNEL_RAW, 0, true);
    let b = bound(HCI_CHANNEL_RAW, 1, true);
    let _c = Cleanup(alloc::vec![Arc::clone(&a), Arc::clone(&b)]);
    assert_eq!(deliver(0, &ev(), Dir::Rx), 1);
    assert!(a.state.lock().readable());
    assert!(!b.state.lock().readable());
}

// A monitor sees every controller, which is the whole point of the channel.
#[test]
fn a_monitor_socket_sees_every_controller() {
    let m = bound(HCI_CHANNEL_MONITOR, HCI_DEV_NONE, false);
    let _c = Cleanup(alloc::vec![Arc::clone(&m)]);
    for dev in 0..3u16 { deliver(dev, &ev(), Dir::Rx); }
    let mut st = m.state.lock();
    let mut indexes = alloc::vec::Vec::new();
    while let Some(r) = st.pop() { indexes.push(parse_header(&r).unwrap().1); }
    assert_eq!(indexes, alloc::vec![0u16, 1, 2]);
}

#[test]
fn a_raw_socket_whose_filter_passes_nothing_receives_nothing() {
    let s = bound(HCI_CHANNEL_RAW, 0, false);
    let _c = Cleanup(alloc::vec![Arc::clone(&s)]);
    assert_eq!(deliver(0, &ev(), Dir::Rx), 0);
    assert!(!s.state.lock().readable());
}

// The direction selects the record opcode for data frames, so a transmitted
// frame and a received one are distinguishable in the trace.
#[test]
fn the_direction_reaches_the_monitor_record_for_data_frames() {
    use crate::uapi::hci::{acl_pack, ACL_START, HCI_ACLDATA_PKT};
    use crate::uapi::hci_mon::{HCI_MON_ACL_RX_PKT, HCI_MON_ACL_TX_PKT};
    let m = bound(HCI_CHANNEL_MONITOR, HCI_DEV_NONE, false);
    let _c = Cleanup(alloc::vec![Arc::clone(&m)]);
    let acl = build_frame(HCI_ACLDATA_PKT, acl_pack(1, ACL_START), &[0xaa]).unwrap();
    deliver(0, &acl, Dir::Tx);
    deliver(0, &acl, Dir::Rx);
    let mut st = m.state.lock();
    assert_eq!(parse_header(&st.pop().unwrap()).unwrap().0, HCI_MON_ACL_TX_PKT);
    assert_eq!(parse_header(&st.pop().unwrap()).unwrap().0, HCI_MON_ACL_RX_PKT);
}

#[test]
fn an_unregistered_socket_receives_nothing_further() {
    let s = bound(HCI_CHANNEL_RAW, 0, true);
    assert!(unregister(&s));
    assert!(!unregister(&s));
    assert_eq!(deliver(0, &ev(), Dir::Rx), 0);
}

#[test]
fn an_unbound_socket_receives_nothing() {
    let f = Arc::new(HciSocketFile::new());
    register(&f);
    let _c = Cleanup(alloc::vec![Arc::clone(&f)]);
    assert_eq!(deliver(0, &ev(), Dir::Rx), 0);
}

#[test]
fn an_empty_frame_delivers_to_nobody_rather_than_panicking() {
    let s = bound(HCI_CHANNEL_RAW, 0, true);
    let _c = Cleanup(alloc::vec![Arc::clone(&s)]);
    assert_eq!(deliver(0, &[], Dir::Rx), 0);
}
