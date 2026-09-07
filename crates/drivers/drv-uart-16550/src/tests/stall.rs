// Transmit-stall reproduction against a modelled 8250.
//
// The model implements the part's documented transmit-interrupt rules: the
// transmit-empty source is RETIRED by an IIR read, and is produced only by a
// holding-register-empty TRANSITION. `latches_while_masked` selects between a
// part that keeps a transition it made while the enable bit was clear (so
// arming later still delivers it) and one that does not — the split the
// reference probes for at startup, and the half that turns a consumed edge into
// a permanently silent console.

use crate::regs::{IER, IIR, IIR_NO_INTERRUPT, LSR, LSR_THR_EMPTY, RBR};
use crate::seq::{self, PortIo};
use crate::tx::{TxEngine, IER_TX_EMPTY, TX_FIFO_DEPTH};
use core::cell::RefCell;

/// IIR encoding for a pending transmit-empty source.
const IIR_THR_EMPTY: u8 = 0x02;

struct Model {
    st: RefCell<State>,
}

struct State {
    ier: u8,
    /// Latched transmit-empty source, cleared by an IIR read.
    thr_pending: bool,
    /// Bytes in the hardware transmit FIFO.
    fifo: usize,
    /// Bytes the part has put on the wire.
    wire: alloc::vec::Vec<u8>,
    latches_while_masked: bool,
}

impl Model {
    fn new(latches_while_masked: bool) -> Self {
        Model { st: RefCell::new(State {
            ier: 0, thr_pending: true, fifo: 0,
            wire: alloc::vec::Vec::new(), latches_while_masked,
        }) }
    }

    /// Whether the part is asserting its interrupt line.
    fn irq(&self) -> bool {
        let st = self.st.borrow();
        st.thr_pending && st.ier & IER_TX_EMPTY != 0
    }

    /// Shift the whole transmit FIFO onto the wire. Emptying it is the
    /// transition that produces a transmit-empty source.
    fn transmit(&self) {
        let mut st = self.st.borrow_mut();
        if st.fifo == 0 { return; }
        st.fifo = 0;
        if st.latches_while_masked || st.ier & IER_TX_EMPTY != 0 { st.thr_pending = true; }
    }

    fn wire(&self) -> alloc::vec::Vec<u8> { self.st.borrow().wire.clone() }
}

impl PortIo for Model {
    fn read(&self, off: u16) -> u8 {
        let mut st = self.st.borrow_mut();
        match off {
            IIR => {
                if st.thr_pending && st.ier & IER_TX_EMPTY != 0 {
                    // The read retires the source; only a later empty
                    // transition produces another one.
                    st.thr_pending = false;
                    IIR_THR_EMPTY
                } else {
                    IIR_NO_INTERRUPT
                }
            }
            LSR => if st.fifo == 0 { LSR_THR_EMPTY } else { 0 },
            _ => 0,
        }
    }

    fn write(&self, off: u16, v: u8) {
        let mut st = self.st.borrow_mut();
        match off {
            RBR => {
                assert!(st.fifo < TX_FIFO_DEPTH, "model: transmit FIFO overrun");
                st.fifo += 1;
                st.wire.push(v);
            }
            IER => {
                let armed = v & IER_TX_EMPTY != 0 && st.ier & IER_TX_EMPTY == 0;
                st.ier = v;
                if armed && st.latches_while_masked && st.fifo == 0 { st.thr_pending = true; }
            }
            _ => {}
        }
    }
}

fn engine() -> TxEngine<64> {
    let mut eng = TxEngine::<64>::new();
    eng.start_runtime();
    eng
}

/// Drive the interrupt handler until the part stops asserting its line.
fn service(eng: &mut TxEngine<64>, io: &Model) {
    let mut passes = 0;
    while io.irq() {
        let iir = io.read(IIR);
        assert_eq!(iir & IIR_NO_INTERRUPT, 0);
        let lsr = io.read(LSR);
        seq::irq_tx(eng, io, lsr);
        io.transmit();
        passes += 1;
        assert!(passes < 1000, "interrupt service did not converge");
    }
}

// ---------------------------------------------------------------- positive control

#[test]
fn model_wedges_when_a_retired_transmit_edge_is_never_reasserted() {
    // The failure the reproduction depends on: read the source out of IIR
    // without writing the holding register, and the part never offers it again.
    let io = Model::new(false);
    io.write(IER, IER_TX_EMPTY);
    assert!(io.irq(), "a register empty since reset owes an armed port a source");
    assert_eq!(io.read(IIR) & IIR_NO_INTERRUPT, 0);
    assert!(!io.irq(), "the IIR read retires the source");
    for _ in 0..1000 { io.transmit(); }
    assert!(!io.irq(), "no empty transition, so no replacement source");
}

#[test]
fn a_part_that_latches_while_masked_recovers_without_help() {
    let io = Model::new(true);
    io.write(IER, IER_TX_EMPTY);
    assert_eq!(io.read(IIR) & IIR_NO_INTERRUPT, 0);
    io.write(RBR, b'x');
    io.write(IER, 0);
    io.transmit();
    assert!(!io.irq(), "masked, so the line stays low");
    io.write(IER, IER_TX_EMPTY);
    assert!(io.irq(), "the transition survived the mask and arming delivers it");
}

// ---------------------------------------------------------------- the defect

#[test]
fn queue_wedges_when_the_arming_edge_is_lost_without_the_inline_transmit() {
    // What the driver did before: queue, arm, and wait for an interrupt.
    let io = Model::new(false);
    let mut eng = engine();
    io.write(IER, eng.ier());

    let t = eng.enqueue(b"first");
    assert!(t.ier_changed);
    io.write(IER, eng.ier());
    service(&mut eng, &io);
    assert_eq!(io.wire(), b"first".to_vec());
    assert!(!eng.queued(), "the burst drained and the queue disarmed");

    // Ring empty => the handler cleared the enable. The next write re-arms it,
    // and on this part that produces nothing.
    let t = eng.enqueue(b"second");
    assert!(t.ier_changed);
    io.write(IER, eng.ier());
    for _ in 0..1000 { io.transmit(); }
    assert!(!io.irq(), "no interrupt: the arming edge was lost");
    assert_eq!(io.wire(), b"first".to_vec(), "the console is silent while the queue holds bytes");
    assert!(eng.queued());
}

#[test]
fn start_tx_transmits_inline_when_the_arming_edge_is_lost() {
    let io = Model::new(false);
    let mut eng = engine();
    io.write(IER, eng.ier());

    seq::start_tx(&mut eng, &io, b"first");
    service(&mut eng, &io);
    assert!(!eng.queued());

    seq::start_tx(&mut eng, &io, b"second");
    service(&mut eng, &io);
    assert_eq!(io.wire(), b"firstsecond".to_vec());
    assert!(!eng.queued(), "nothing is left waiting on an interrupt that never comes");
}

#[test]
fn a_burst_longer_than_the_hardware_fifo_drains_completely() {
    let io = Model::new(false);
    let mut eng = engine();
    io.write(IER, eng.ier());
    let burst: alloc::vec::Vec<u8> = (0..60u8).collect();
    seq::start_tx(&mut eng, &io, &burst);
    service(&mut eng, &io);
    assert_eq!(io.wire(), burst);
}

// ---------------------------------------------------------------- recovery poll

#[test]
fn poll_lost_tx_recovers_a_queue_wedged_by_a_retired_edge() {
    let io = Model::new(false);
    let mut eng = engine();
    io.write(IER, eng.ier());

    // Wedge it exactly as a service pass that declines to transmit would:
    // armed and loaded, with the source read out of IIR and dropped.
    eng.enqueue(b"stuck");
    io.write(IER, eng.ier());
    assert_eq!(io.read(IIR) & IIR_NO_INTERRUPT, 0);
    assert!(!io.irq());

    assert!(seq::poll_lost_tx(&mut eng, &io), "the poll reports a recovered edge");
    io.transmit();
    service(&mut eng, &io);
    assert_eq!(io.wire(), b"stuck".to_vec());
    assert!(!eng.queued());
}

#[test]
fn poll_lost_tx_is_inert_on_an_idle_or_busy_port() {
    let io = Model::new(false);
    let mut eng = engine();
    io.write(IER, eng.ier());
    assert!(!seq::poll_lost_tx(&mut eng, &io), "an empty queue owes nothing");

    seq::start_tx(&mut eng, &io, &(0..40u8).collect::<alloc::vec::Vec<u8>>());
    // The FIFO is loaded and still transmitting: the completion transition is
    // still owed, so the poll must not claim a lost edge.
    assert!(!seq::poll_lost_tx(&mut eng, &io));
    assert!(eng.queued());
    io.transmit();
    service(&mut eng, &io);
    assert_eq!(io.wire().len(), 40);
}
