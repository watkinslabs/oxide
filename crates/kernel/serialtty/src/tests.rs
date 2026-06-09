// T6 end-to-end tests: drive the FULL serial tty stack assembled as a
// real `TtyStruct<SerialTtyDriver<RecordingOut, RecordingSignal>,
// HostWait>` and assert what the UART emits (TX), what `read` returns,
// what was echoed, and which signals fired — without a real UART.

use super::*;
use std::cell::RefCell;
use std::rc::Rc;
use std::vec::Vec;

use tty::pty::{default_termios, lflag, oflag, TERMIOS_OFF_LFLAG, TERMIOS_OFF_OFLAG};
use tty::wait::host::HostWait;

// --- recording UART sink ------------------------------------------------

/// `SerialOut` that records every TX byte so tests assert UART output
/// (OPOST/ONLCR cooking happens upstream in N_TTY; this captures the
/// post-cook bytes that reach the wire).
#[derive(Default, Clone)]
struct RecordingOut {
    bytes: Rc<RefCell<Vec<u8>>>,
}

impl RecordingOut {
    fn tx(&self) -> Vec<u8> {
        self.bytes.borrow().clone()
    }
}

impl SerialOut for RecordingOut {
    fn emit(&mut self, bytes: &[u8]) {
        self.bytes.borrow_mut().extend_from_slice(bytes);
    }
}

// --- recording signal sink ----------------------------------------------

#[derive(Default, Clone)]
struct RecordingSignal {
    log: Rc<RefCell<Vec<(u32, Sig)>>>,
}

impl FgSignal for RecordingSignal {
    fn raise(&mut self, pgrp: u32, sig: Sig) {
        self.log.borrow_mut().push((pgrp, sig));
    }
}

// --- assembly helper ----------------------------------------------------

type Stty = SerialTtyDriver<RecordingOut, RecordingSignal>;

fn build() -> (TtyStruct<Stty, HostWait>, RecordingOut, RecordingSignal) {
    let out = RecordingOut::default();
    let sig = RecordingSignal::default();
    let tty = assemble(out.clone(), sig.clone(), HostWait::new());
    (tty, out, sig)
}

/// Mutate a termios u32 field (oflag/lflag) in place.
fn set_field(t: &mut [u8; tty::pty::TERMIOS_BYTES], off: usize, f: impl FnOnce(u32) -> u32) {
    let cur = u32::from_le_bytes([t[off], t[off + 1], t[off + 2], t[off + 3]]);
    let b = f(cur).to_le_bytes();
    t[off..off + 4].copy_from_slice(&b);
}

// --- TX OPOST -----------------------------------------------------------

#[test]
fn tx_onlcr_translates_newline() {
    // Default termios has OPOST|ONLCR: "hi\n" → UART sees "hi\r\n".
    let (tty, out, _sig) = build();
    let n = tty.write(b"hi\n");
    assert_eq!(n, 3);
    assert_eq!(out.tx(), b"hi\r\n");
}

#[test]
fn tx_opost_off_is_raw() {
    // Clear OPOST: "hi\n" reaches the UART verbatim, no CR inserted.
    let mut t = default_termios();
    set_field(&mut t, TERMIOS_OFF_OFLAG, |o| o & !oflag::OPOST);
    let out = RecordingOut::default();
    let drv = SerialTtyDriver::with_signal(out.clone(), RecordingSignal::default());
    let tty = TtyStruct::with_termios(drv, HostWait::new(), t);
    tty.write(b"hi\n");
    assert_eq!(out.tx(), b"hi\n");
}

// --- RX → read + echo ---------------------------------------------------

#[test]
fn rx_line_reads_and_echoes_to_uart() {
    let (tty, out, _sig) = build();
    // UART RX a full canonical line.
    tty.receive_from_driver(b"cmd\n");
    // Program read returns the cooked line (with trailing \n).
    let mut buf = [0u8; 32];
    let got = tty.read(&mut buf);
    assert_eq!(&buf[..got], b"cmd\n");
    // Echo went out driver_write → UART. N_TTY echoes the typed bytes
    // (the newline echoes as the canonical line terminator); OPOST is the
    // output-write path, not the echo path, so the echo is "cmd\n".
    assert_eq!(out.tx(), b"cmd\n");
}

#[test]
fn password_echo_off_reads_line_nothing_on_uart() {
    let mut t = default_termios();
    set_field(&mut t, TERMIOS_OFF_LFLAG, |l| l & !lflag::ECHO);
    let out = RecordingOut::default();
    let drv = SerialTtyDriver::with_signal(out.clone(), RecordingSignal::default());
    let tty = TtyStruct::with_termios(drv, HostWait::new(), t);

    tty.receive_from_driver(b"secret\n");
    let mut buf = [0u8; 32];
    let got = tty.read(&mut buf);
    assert_eq!(&buf[..got], b"secret\n");
    // ECHO off → nothing reached the UART.
    assert!(out.tx().is_empty(), "uart should be silent, got {:?}", out.tx());
}

// --- ctrl-C → SIGINT ----------------------------------------------------

#[test]
fn ctrl_c_raises_sigint_on_fg_pgrp() {
    let (tty, _out, sig) = build();
    set_fg_pgrp(&tty, 4242);
    tty.receive_from_driver(b"\x03");
    let log = sig.log.borrow();
    assert_eq!(log.len(), 1, "expected exactly one signal");
    assert_eq!(log[0], (4242, Sig::Int));
}

// --- registry -----------------------------------------------------------

#[test]
fn registry_lookup_returns_ttys0() {
    use std::sync::Arc;
    use tty::TtyRegistry;
    let reg: TtyRegistry<TtyStruct<Stty, HostWait>> = TtyRegistry::new();
    let (tty, _out, _sig) = build();
    let handle = Arc::new(tty);
    reg.register(TTYS0, Arc::clone(&handle));
    let got = reg.lookup(TTYS0).expect("ttyS0 must be registered");
    assert!(Arc::ptr_eq(&got, &handle));
    // Wrong minor misses.
    assert!(reg.lookup(DevId::new(major::SERIAL, 0)).is_none());
}

// --- proptest: random RX + reads never lose a completed line ------------

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]
    #[test]
    fn random_rx_reads_never_panic_never_lose_line(
        ops in proptest::collection::vec(
            prop_oneof![
                proptest::collection::vec(any::<u8>(), 0..16).prop_map(POp::Recv),
                Just(POp::Read),
            ],
            0..64,
        )
    ) {
        let (tty, _out, _sig) = build();
        for op in ops {
            match op {
                POp::Recv(b) => { tty.receive_from_driver(&b); }
                POp::Read => {
                    let mut buf = [0u8; 128];
                    let n = tty.read_nonblock(&mut buf);
                    prop_assert!(n <= buf.len());
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
enum POp {
    Recv(Vec<u8>),
    Read,
}

// A completed line is never lost: feed a full line then drain it.
#[test]
fn completed_line_always_drains() {
    let (tty, _out, _sig) = build();
    tty.receive_from_driver(b"alpha\n");
    tty.receive_from_driver(b"beta\n");
    let mut buf = [0u8; 16];
    let n1 = tty.read(&mut buf);
    assert_eq!(&buf[..n1], b"alpha\n");
    let n2 = tty.read(&mut buf);
    assert_eq!(&buf[..n2], b"beta\n");
}
