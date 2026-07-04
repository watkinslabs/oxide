use super::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    #[test]
    fn fuzz_receive_read_invariants(input in proptest::collection::vec(any::<u8>(), 0..512),
                                    bufcap in 1usize..64,
                                    canon in any::<bool>()) {
        let mut t = default_termios();
        if !canon {
            let mut lf = crate::pty::read_lflag(&t);
            lf &= !lflag::ICANON;
            set_u32(&mut t, TERMIOS_OFF_LFLAG, lf);
            t[TERMIOS_OFF_CC + cc::VMIN] = 1;
        }
        let mut n = NTty::with_termios(t);
        let mut d = RecordingDriver::default();
        n.receive_buf(&mut d, &input);

        let mut total = 0usize;
        for _ in 0..1000 {
            let mut buf = vec![0u8; bufcap];
            let got = n.read(&mut buf);
            prop_assert!(got <= bufcap);
            if got == 0 { break; }
            total += got;
            if canon {
                // Canonical never merges lines: a \n (the only delimiter
                // here — VEOL/VEOL2 are 0 in default_termios) may appear
                // only at the final returned position, never in the
                // middle (that would mean the read crossed into the next
                // line). VEOF-terminated lines have no delimiter at all,
                // which is also fine.
                for (i, &c) in buf[..got].iter().enumerate() {
                    if c == b'\n' {
                        prop_assert_eq!(i, got - 1);
                    }
                }
            }
        }
        prop_assert!(total <= input.len() + 8);
    }

    #[test]
    fn fuzz_write_never_panics(input in proptest::collection::vec(any::<u8>(), 0..512)) {
        let mut n = NTty::new();
        let mut d = RecordingDriver::default();
        let w = n.write(&mut d, &input);
        prop_assert_eq!(w, input.len());
    }
}

// ---------------------------------------------------------------------
// VMIN/VTIME noncanonical read-decision state machine (the 4 Linux
// cases). Pure fn — no clock, no lock — so every case + boundary is a
// direct unit test. The signal-interrupt path is kernel-only (it reads
// the running task's sigpending&!sigmask via KernelWait::should_interrupt)
// and is exercised by the boot smoke, not here.
// ---------------------------------------------------------------------
use crate::ldisc::{vmin_vtime_decision, VmtDecision, VTIME_TENTH_NS};

/// MIN==0,TIME==0: polling read — return immediately with whatever is
/// available (0 if none), never block.
#[test]
fn vmt_poll_min0_time0() {
    assert_eq!(vmin_vtime_decision(0, 0, 0, 8, 0, 0, false), VmtDecision::ReturnNow(0));
    assert_eq!(vmin_vtime_decision(0, 0, 3, 8, 0, 0, true), VmtDecision::ReturnNow(3));
    // Available exceeds buf → clamp to buf_len.
    assert_eq!(vmin_vtime_decision(0, 0, 9, 8, 0, 0, true), VmtDecision::ReturnNow(8));
}

/// MIN>0,TIME==0: block until ≥MIN bytes (no timer); return up to buf.len().
#[test]
fn vmt_block_min_no_timer() {
    // Below MIN → block, no deadline.
    assert_eq!(vmin_vtime_decision(3, 0, 2, 8, 0, 0, true), VmtDecision::BlockNoDeadline);
    assert_eq!(vmin_vtime_decision(3, 0, 0, 8, 0, 0, false), VmtDecision::BlockNoDeadline);
    // MIN reached → return.
    assert_eq!(vmin_vtime_decision(3, 0, 3, 8, 0, 0, true), VmtDecision::ReturnNow(3));
    // More than MIN → take min(avail, buf).
    assert_eq!(vmin_vtime_decision(3, 0, 5, 8, 0, 0, true), VmtDecision::ReturnNow(5));
    // Buf full before MIN (buf_len < MIN) still returns.
    assert_eq!(vmin_vtime_decision(8, 0, 2, 2, 0, 0, true), VmtDecision::ReturnNow(2));
}

/// MIN==0,TIME>0: read timer — block up to TIME*100ms for the FIRST byte;
/// return what arrived (0 on timeout). Timer is start-relative.
#[test]
fn vmt_read_timer_min0_time() {
    // Nothing yet, timer not expired → BlockUntil TIME*tenth.
    assert_eq!(
        vmin_vtime_decision(0, 2, 0, 8, 0, 0, false),
        VmtDecision::BlockUntil(2 * VTIME_TENTH_NS)
    );
    // First byte arrived → return it (timer ends on first byte).
    assert_eq!(vmin_vtime_decision(0, 2, 1, 8, 50_000_000, 0, true), VmtDecision::ReturnNow(1));
    // Timer expired with nothing → ReturnNow(0).
    assert_eq!(
        vmin_vtime_decision(0, 2, 0, 8, 2 * VTIME_TENTH_NS, 0, false),
        VmtDecision::ReturnNow(0)
    );
}

/// MIN>0,TIME>0: interbyte timer — wait for the first byte with no overall
/// timeout; after a byte, return at MIN/buf-full or when the interbyte gap
/// exceeds TIME.
#[test]
fn vmt_interbyte_min_time() {
    // No byte yet → block with NO deadline (wait for first byte).
    assert_eq!(vmin_vtime_decision(3, 2, 0, 8, 0, 0, false), VmtDecision::BlockNoDeadline);
    // First byte arrived, below MIN, gap not exceeded → BlockUntil interbyte.
    assert_eq!(
        vmin_vtime_decision(3, 2, 1, 8, 10_000_000, 10_000_000, true),
        VmtDecision::BlockUntil(2 * VTIME_TENTH_NS)
    );
    // MIN reached → return regardless of timers.
    assert_eq!(vmin_vtime_decision(3, 2, 3, 8, 0, 0, true), VmtDecision::ReturnNow(3));
    // Buf full before MIN → return.
    assert_eq!(vmin_vtime_decision(8, 2, 2, 2, 0, 0, true), VmtDecision::ReturnNow(2));
    // Interbyte gap exceeded with partial data → return what's there.
    assert_eq!(
        vmin_vtime_decision(3, 2, 2, 8, 999_000_000, 2 * VTIME_TENTH_NS, true),
        VmtDecision::ReturnNow(2)
    );
}
