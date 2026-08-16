use super::*;
extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::cell::RefCell;

/// A transport that records what it was asked to do, which is what every
/// higher-level test drives the core against.
struct Recorder {
    sent: RefCell<Vec<Vec<u8>>>,
    opened: RefCell<u32>,
    closed: RefCell<u32>,
    fail: bool,
}

// SAFETY: the recorder is only ever used from one test thread at a time; the
// trait demands the marker and no test shares an instance across threads.
unsafe impl Sync for Recorder {}
// SAFETY: same single-threaded test ownership as the Sync impl above.
unsafe impl Send for Recorder {}

impl Recorder {
    fn new(fail: bool) -> Recorder {
        Recorder { sent: RefCell::new(Vec::new()), opened: RefCell::new(0),
            closed: RefCell::new(0), fail }
    }
}

impl HciTransport for Recorder {
    fn open(&self) -> Result<(), Errno> {
        *self.opened.borrow_mut() += 1;
        if self.fail { Err(Errno::Eio) } else { Ok(()) }
    }
    fn close(&self) { *self.closed.borrow_mut() += 1; }
    fn send(&self, frame: &[u8]) -> Result<(), Errno> {
        if self.fail { return Err(Errno::Eio); }
        self.sent.borrow_mut().push(frame.to_vec());
        Ok(())
    }
    fn bus(&self) -> u8 { crate::uapi::hci::HCI_UART }
    fn driver_name(&self) -> String { "recorder".to_string() }
}

// The contract carries whole frames unchanged: a transport that reordered or
// rewrote bytes would corrupt every protocol above it.
#[test]
fn a_transport_carries_whole_frames_unchanged_and_in_order() {
    let t = Recorder::new(false);
    for n in 0..3u8 { t.send(&[0x01, n]).unwrap(); }
    assert_eq!(*t.sent.borrow(), alloc::vec![alloc::vec![0x01, 0], alloc::vec![0x01, 1],
        alloc::vec![0x01, 2]]);
}

// A failed send must report rather than silently drop, so the caller can give
// back the command slot instead of waiting out a deadline.
#[test]
fn a_failing_transport_reports_rather_than_dropping() {
    let t = Recorder::new(true);
    assert_eq!(t.send(&[0x01, 0]), Err(Errno::Eio));
    assert!(t.sent.borrow().is_empty());
    assert_eq!(t.open(), Err(Errno::Eio));
}

#[test]
fn open_and_close_bracket_the_transports_usable_life() {
    let t = Recorder::new(false);
    assert_eq!(t.open(), Ok(()));
    t.close();
    assert_eq!((*t.opened.borrow(), *t.closed.borrow()), (1, 1));
}

#[test]
fn a_transport_reports_the_bus_it_attaches_by_and_names_itself() {
    let t = Recorder::new(false);
    assert_eq!(t.bus(), crate::uapi::hci::HCI_UART);
    assert_eq!(t.driver_name().as_str(), "recorder");
}

// The event type is what a transport hands upward; a frame and a failure are
// distinguishable so a caller cannot mistake an empty frame for a failure.
#[test]
fn a_frame_and_a_failure_are_distinguishable_events() {
    assert_ne!(TransportEvent::Frame(alloc::vec![]), TransportEvent::Failed);
    assert_eq!(TransportEvent::Frame(alloc::vec![1, 2]),
        TransportEvent::Frame(alloc::vec![1, 2]));
}
