// TTY core tests. Headline: the lost-wakeup-free blocking read.
use std::sync::atomic::Ordering;
use std::sync::{Arc, Barrier};
use std::vec::Vec;

use super::{TtyDriver, TtyStruct};
use crate::ldisc::Sig;
use crate::pty::{
    cc, default_termios, lflag, oflag, read_lflag, read_oflag, Winsize, TERMIOS_BYTES,
    TERMIOS_OFF_CC, TERMIOS_OFF_LFLAG,
};
use crate::wait::host::HostWait;
use crate::wait::TtyWait;

/// Driver that records everything written + signals raised.
#[derive(Default)]
struct RecordingDriver {
    out: Vec<u8>,
    signals: Vec<Sig>,
    opens: u32,
    closes: u32,
}

impl TtyDriver for RecordingDriver {
    fn write(&mut self, bytes: &[u8]) {
        self.out.extend_from_slice(bytes);
    }
    fn signal_fg_pgrp(&mut self, sig: Sig) {
        self.signals.push(sig);
    }
    fn open(&mut self) {
        self.opens += 1;
    }
    fn close(&mut self) {
        self.closes += 1;
    }
}

fn raw_termios() -> [u8; TERMIOS_BYTES] {
    let mut t = default_termios();
    // Clear ICANON + ECHO + ISIG → raw passthrough.
    let lf = read_lflag(&t) & !(lflag::ICANON | lflag::ECHO | lflag::ISIG);
    t[TERMIOS_OFF_LFLAG..TERMIOS_OFF_LFLAG + 4].copy_from_slice(&lf.to_le_bytes());
    // VMIN=1 so a single byte satisfies a raw read.
    t[TERMIOS_OFF_CC + cc::VMIN] = 1;
    t[TERMIOS_OFF_CC + cc::VTIME] = 0;
    t
}

// ---------------------------------------------------------------------
// Headline: lost-wakeup-free blocking read.
// ---------------------------------------------------------------------

/// A byte delivered by a second thread while a reader is parked must be
/// returned — the reader must NOT sleep forever. Looped many times to
/// exercise the window between the reader's empty-check and its park. If
/// the read loop ever reverted to check-then-park (no recheck after
/// enqueue), one iteration would deadlock and the test would hang/fail.
#[test]
fn lost_wakeup_free_concurrent_delivery() {
    for _ in 0..2000 {
        let tty = Arc::new(TtyStruct::with_termios(
            RecordingDriver::default(),
            HostWait::new(),
            raw_termios(),
        ));
        let tty2 = Arc::clone(&tty);
        let barrier = Arc::new(Barrier::new(2));
        let b2 = Arc::clone(&barrier);

        let producer = std::thread::spawn(move || {
            // Release both threads as close together as possible so the
            // byte can land anywhere in the reader's fast-path→park window.
            b2.wait();
            tty2.receive_from_driver(b"X");
        });

        barrier.wait();
        let mut buf = [0u8; 8];
        let n = tty.read(&mut buf); // MUST return, never hang.
        producer.join().unwrap();
        assert_eq!(n, 1, "reader must get the concurrently-delivered byte");
        assert_eq!(buf[0], b'X');
    }
}

/// Deterministic half of the proof: a wake that arrives BEFORE the reader
/// commits to sleep is not lost — `park_commit` consumes the pending wake
/// and returns instead of blocking. (Mirrors the kernel WaitList: a
/// wake_all between park_prepare and schedule still rouses the task.)
#[test]
fn wake_before_commit_not_lost() {
    let w = HostWait::new();
    w.park_prepare();
    w.wake_all(); // wake races ahead of the sleep
    w.park_commit(); // must return immediately, not block forever
    assert_eq!(w.counters.commits.load(Ordering::SeqCst), 1);
}

/// The fast path: input already queued → read returns without ever
/// parking (no prepare/commit).
#[test]
fn fast_path_no_park() {
    let tty = TtyStruct::with_termios(RecordingDriver::default(), HostWait::new(), raw_termios());
    tty.receive_from_driver(b"hi");
    let mut buf = [0u8; 8];
    let n = tty.read(&mut buf);
    assert_eq!(&buf[..n], b"hi");
    assert_eq!(tty.wait_counters().commits.load(Ordering::SeqCst), 0);
}

// Helper so tests can reach the counters through the opaque wait.
impl<D: TtyDriver> TtyStruct<D, HostWait> {
    fn wait_counters(&self) -> Arc<crate::wait::host::Counters> {
        Arc::clone(&self.wait_handle().counters)
    }
}

// ---------------------------------------------------------------------
// RX → flip → ldisc → cooked read + echo.
// ---------------------------------------------------------------------

#[test]
fn canonical_line_cooked_and_echoed() {
    let tty = TtyStruct::new(RecordingDriver::default(), HostWait::new());
    // Default termios = ICANON|ECHO. Type "hi\n".
    tty.receive_from_driver(b"hi\n");
    // Echo went out the driver.
    tty.with_driver(|d| {
        assert_eq!(d.out, b"hi\n");
    });
    // read returns the whole cooked line.
    let mut buf = [0u8; 16];
    let n = tty.read(&mut buf);
    assert_eq!(&buf[..n], b"hi\n");
}

#[test]
fn ctrl_c_signals_fg_pgrp() {
    let tty = TtyStruct::new(RecordingDriver::default(), HostWait::new());
    tty.receive_from_driver(&[0x03]); // ^C
    tty.with_driver(|d| {
        assert_eq!(d.signals, std::vec![Sig::Int]);
    });
}

// ---------------------------------------------------------------------
// termios / winsize / pgrp / sid via ioctl.
// ---------------------------------------------------------------------

#[test]
fn tcgets_tcsets_roundtrip_and_rawmode() {
    use crate::ioctl::{core_ioctl_decoded, req, IoctlOut};
    let tty = TtyStruct::new(RecordingDriver::default(), HostWait::new());

    // TCGETS returns the default image.
    let got = core_ioctl_decoded(&tty, req::TCGETS, 0, None, None).unwrap().0;
    assert!(matches!(got, IoctlOut::Termios(t) if t == default_termios()));

    // TCSETS to raw mode.
    let raw = raw_termios();
    let (out, _) = core_ioctl_decoded(&tty, req::TCSETS, 0, Some(&raw), None).unwrap();
    assert_eq!(out, IoctlOut::Ok);
    assert_eq!(tty.termios(), raw);
    // Raw mode: bytes pass through one at a time, no cooking.
    tty.receive_from_driver(b"ab");
    let mut buf = [0u8; 8];
    let n = tty.read(&mut buf);
    assert_eq!(&buf[..n], b"ab");
}

#[test]
fn winsize_get_set() {
    use crate::ioctl::{core_ioctl_decoded, req, IoctlOut};
    let tty = TtyStruct::new(RecordingDriver::default(), HostWait::new());
    let got = core_ioctl_decoded(&tty, req::TIOCGWINSZ, 0, None, None).unwrap().0;
    assert_eq!(got, IoctlOut::Winsize(Winsize::default_pty()));

    let ws = Winsize { rows: 50, cols: 132, xpixel: 0, ypixel: 0 };
    let (out, changed) = core_ioctl_decoded(&tty, req::TIOCSWINSZ, 0, None, Some(ws)).unwrap();
    assert_eq!(out, IoctlOut::Ok);
    assert!(changed);
    assert_eq!(tty.winsize(), ws);
    // Setting the same size again is not a change (no SIGWINCH).
    let (_, changed2) = core_ioctl_decoded(&tty, req::TIOCSWINSZ, 0, None, Some(ws)).unwrap();
    assert!(!changed2);
}

#[test]
fn pgrp_get_set() {
    use crate::ioctl::{core_ioctl_decoded, req, IoctlOut};
    let tty = TtyStruct::new(RecordingDriver::default(), HostWait::new());
    assert_eq!(
        core_ioctl_decoded(&tty, req::TIOCGPGRP, 0, None, None).unwrap().0,
        IoctlOut::U32(0)
    );
    core_ioctl_decoded(&tty, req::TIOCSPGRP, 4242, None, None).unwrap();
    assert_eq!(tty.fg_pgrp(), 4242);
    assert_eq!(
        core_ioctl_decoded(&tty, req::TIOCGPGRP, 0, None, None).unwrap().0,
        IoctlOut::U32(4242)
    );
}

#[test]
fn ctty_sid_set_get_notty() {
    use crate::ioctl::{core_ioctl_decoded, req, IoctlOut};
    let tty = TtyStruct::new(RecordingDriver::default(), HostWait::new());
    core_ioctl_decoded(&tty, req::TIOCSCTTY, 99, None, None).unwrap();
    core_ioctl_decoded(&tty, req::TIOCSPGRP, 99, None, None).unwrap();
    assert_eq!(
        core_ioctl_decoded(&tty, req::TIOCGSID, 0, None, None).unwrap().0,
        IoctlOut::U32(99)
    );
    // TIOCNOTTY clears both sid and fg pgrp.
    core_ioctl_decoded(&tty, req::TIOCNOTTY, 0, None, None).unwrap();
    assert_eq!(tty.sid(), 0);
    assert_eq!(tty.fg_pgrp(), 0);
}

#[test]
fn unknown_ioctl_is_none() {
    use crate::ioctl::core_ioctl_decoded;
    let tty = TtyStruct::new(RecordingDriver::default(), HostWait::new());
    assert!(core_ioctl_decoded(&tty, 0xDEAD, 0, None, None).is_none());
}

// ---------------------------------------------------------------------
// poll / write (OPOST) / readable.
// ---------------------------------------------------------------------

#[test]
fn poll_reflects_readability() {
    use crate::ldisc::pollmask;
    let tty = TtyStruct::new(RecordingDriver::default(), HostWait::new());
    assert_eq!(tty.poll() & pollmask::POLLIN, 0);
    assert!(!tty.readable());
    tty.receive_from_driver(b"x\n");
    assert_ne!(tty.poll() & pollmask::POLLIN, 0);
    assert!(tty.readable());
}

#[test]
fn write_applies_opost_onlcr() {
    let tty = TtyStruct::new(RecordingDriver::default(), HostWait::new());
    // Default termios has OPOST|ONLCR.
    assert!(read_oflag(&tty.termios()) & oflag::ONLCR != 0);
    tty.write(b"a\nb");
    tty.with_driver(|d| assert_eq!(d.out, b"a\r\nb"));
}

#[test]
fn read_nonblock_drains_or_empty() {
    let tty = TtyStruct::with_termios(RecordingDriver::default(), HostWait::new(), raw_termios());
    let mut buf = [0u8; 8];
    assert_eq!(tty.read_nonblock(&mut buf), 0); // empty, no park
    tty.receive_from_driver(b"z");
    assert_eq!(tty.read_nonblock(&mut buf), 1);
    assert_eq!(buf[0], b'z');
}

// ---------------------------------------------------------------------
// registry.
// ---------------------------------------------------------------------

#[test]
fn registry_register_lookup() {
    use crate::registry::{major, DevId, TtyRegistry};
    let reg: TtyRegistry<TtyStruct<RecordingDriver, HostWait>> = TtyRegistry::new();
    assert!(reg.is_empty());
    let tty = Arc::new(TtyStruct::new(RecordingDriver::default(), HostWait::new()));
    let id = DevId::new(major::VC, 1);
    reg.register(id, Arc::clone(&tty));
    assert_eq!(reg.len(), 1);
    let got = reg.lookup(id).expect("registered tty resolves");
    assert!(Arc::ptr_eq(&got, &tty));
    assert!(reg.lookup(DevId::new(major::VC, 2)).is_none());
    reg.unregister(id);
    assert!(reg.is_empty());
}

// ---------------------------------------------------------------------
// proptest: random RX streams never panic / never lose a completed line /
// never deadlock the (fast-path) model.
// ---------------------------------------------------------------------

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    #[test]
    fn random_rx_never_panics_and_drains(stream in proptest::collection::vec(any::<u8>(), 0..512)) {
        let tty = TtyStruct::with_termios(
            RecordingDriver::default(), HostWait::new(), raw_termios());
        tty.receive_from_driver(&stream);
        // Raw mode: every non-signal byte is queued; ISIG is off so all
        // bytes pass through. Drain via nonblocking reads until empty;
        // must terminate (no deadlock) and never panic.
        let mut total = 0usize;
        let mut buf = [0u8; 64];
        loop {
            let n = tty.read_nonblock(&mut buf);
            if n == 0 { break; }
            total += n;
            prop_assert!(total <= stream.len());
        }
        prop_assert_eq!(total, stream.len());
    }

    #[test]
    fn canonical_completed_lines_never_lost(
        lines in proptest::collection::vec("[a-z]{0,8}", 1..16)
    ) {
        let tty = TtyStruct::new(RecordingDriver::default(), HostWait::new());
        // Feed each line terminated by \n.
        let mut expect = std::string::String::new();
        for l in &lines {
            tty.receive_from_driver(l.as_bytes());
            tty.receive_from_driver(b"\n");
            expect.push_str(l);
            expect.push('\n');
        }
        // Read back all cooked lines; must reassemble exactly.
        let mut got = std::vec::Vec::new();
        let mut buf = [0u8; 32];
        loop {
            let n = tty.read_nonblock(&mut buf);
            if n == 0 { break; }
            got.extend_from_slice(&buf[..n]);
        }
        prop_assert_eq!(got, expect.into_bytes());
    }
}
