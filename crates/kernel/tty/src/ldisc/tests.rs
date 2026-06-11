// N_TTY hosted tests: drive bytes through the discipline with a
// recording driver; assert cooked lines, echo bytes, signals, raw
// passthrough, edit keys, EOF, iflag/oflag mapping, poll. Plus a
// proptest fuzz: random streams never panic / never over-read / never
// return an unterminated canonical line.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;
use proptest::prelude::*;

use super::{pollmask, LdiscOps, NTty, Sig, TtyDriverHooks};
use crate::pty::{
    cc, default_termios, iflag, lflag, oflag, TERMIOS_BYTES, TERMIOS_OFF_CC,
    TERMIOS_OFF_IFLAG, TERMIOS_OFF_LFLAG, TERMIOS_OFF_OFLAG,
};

/// Captures driver_write bytes + raised signals.
#[derive(Default)]
struct RecordingDriver {
    out: Vec<u8>,
    sigs: Vec<Sig>,
}

impl TtyDriverHooks for RecordingDriver {
    fn driver_write(&mut self, bytes: &[u8]) {
        self.out.extend_from_slice(bytes);
    }
    fn signal_fg_pgrp(&mut self, sig: Sig) {
        self.sigs.push(sig);
    }
}

fn set_u32(t: &mut [u8; TERMIOS_BYTES], off: usize, v: u32) {
    t[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

/// Read all currently-available bytes via repeated `read` (canonical
/// returns one line per call).
fn drain(n: &mut NTty) -> Vec<u8> {
    let mut all = Vec::new();
    loop {
        let mut buf = [0u8; 256];
        let got = n.read(&mut buf);
        if got == 0 {
            break;
        }
        all.extend_from_slice(&buf[..got]);
    }
    all
}

// ---- canonical line read ----

#[test]
fn canon_full_line() {
    let mut n = NTty::new();
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, b"ls -l\n");
    let mut buf = [0u8; 64];
    let got = n.read(&mut buf);
    assert_eq!(&buf[..got], b"ls -l\n");
}

#[test]
fn canon_partial_no_newline_returns_nothing() {
    let mut n = NTty::new();
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, b"ab");
    let mut buf = [0u8; 64];
    assert_eq!(n.read(&mut buf), 0);
    assert!(!n.has_input());
    // Now terminate.
    n.receive_buf(&mut d, b"c\n");
    let got = n.read(&mut buf);
    assert_eq!(&buf[..got], b"abc\n");
}

#[test]
fn canon_two_lines_read_one_at_a_time() {
    let mut n = NTty::new();
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, b"one\ntwo\n");
    let mut buf = [0u8; 64];
    let g1 = n.read(&mut buf);
    assert_eq!(&buf[..g1], b"one\n");
    let g2 = n.read(&mut buf);
    assert_eq!(&buf[..g2], b"two\n");
}

#[test]
fn canon_line_longer_than_buf_not_split_below_newline() {
    // buf smaller than the line: read stops at buf.len, the rest stays.
    let mut n = NTty::new();
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, b"abcdef\n");
    let mut buf = [0u8; 3];
    let g = n.read(&mut buf);
    assert_eq!(&buf[..g], b"abc");
    assert_eq!(drain(&mut n), b"def\n");
}

// ---- echo ----

#[test]
fn echo_printable() {
    let mut n = NTty::new();
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, b"hi\n");
    assert_eq!(d.out, b"hi\n");
}

#[test]
fn echo_control_as_caret_with_echoctl() {
    let mut n = NTty::new();
    let mut d = RecordingDriver::default();
    // 0x01 = ^A. ECHOCTL on by default.
    n.receive_buf(&mut d, &[0x01, b'\n']);
    assert_eq!(d.out, b"^A\n");
}

#[test]
fn echo_off_password_mode() {
    let mut t = default_termios();
    let mut lf = crate::pty::read_lflag(&t);
    lf &= !lflag::ECHO;
    set_u32(&mut t, TERMIOS_OFF_LFLAG, lf);
    let mut n = NTty::with_termios(t);
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, b"secret\n");
    // ECHONL is not set here, so nothing echoes — not even the NL.
    assert!(d.out.is_empty());
    // The line is still readable.
    assert_eq!(drain(&mut n), b"secret\n");
}

// ---- VERASE / VKILL / VWERASE ----

#[test]
fn verase_del_erases_last_char() {
    let mut n = NTty::new();
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, b"abc");
    n.receive_buf(&mut d, &[0x7f]); // DEL
    n.receive_buf(&mut d, b"\n");
    assert_eq!(drain(&mut n), b"ab\n");
    // ECHOE emits "\b \b" once for the erase.
    assert_eq!(d.out, b"abc\x08 \x08\n");
}

#[test]
fn verase_at_line_start_is_noop() {
    let mut n = NTty::new();
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, &[0x7f]); // nothing to erase
    n.receive_buf(&mut d, b"x\n");
    assert_eq!(drain(&mut n), b"x\n");
}

#[test]
fn vkill_clears_line() {
    let mut n = NTty::new();
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, b"garbage");
    n.receive_buf(&mut d, &[0x15]); // ^U
    n.receive_buf(&mut d, b"ok\n");
    assert_eq!(drain(&mut n), b"ok\n");
}

#[test]
fn vwerase_erases_word() {
    let mut n = NTty::new();
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, b"foo bar");
    n.receive_buf(&mut d, &[0x17]); // ^W
    n.receive_buf(&mut d, b"\n");
    assert_eq!(drain(&mut n), b"foo \n");
}

#[test]
fn vwerase_skips_trailing_space() {
    let mut n = NTty::new();
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, b"foo bar   ");
    n.receive_buf(&mut d, &[0x17]); // ^W: skip blanks then erase "bar"
    n.receive_buf(&mut d, b"\n");
    assert_eq!(drain(&mut n), b"foo \n");
}

// ---- VEOF (^D) ----

#[test]
fn veof_at_line_start_is_eof() {
    let mut n = NTty::new();
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, &[0x04]); // ^D, line empty
    let mut buf = [0u8; 8];
    assert_eq!(n.read(&mut buf), 0); // EOF
}

#[test]
fn veof_midline_delivers_line_without_ctrl_d() {
    let mut n = NTty::new();
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, b"ab");
    n.receive_buf(&mut d, &[0x04]); // ^D mid-line
    let mut buf = [0u8; 8];
    let got = n.read(&mut buf);
    assert_eq!(&buf[..got], b"ab"); // no \n, no \x04
}

// ---- ISIG ----

#[test]
fn isig_intr_raises_sigint() {
    let mut n = NTty::new();
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, &[0x03]); // ^C
    assert_eq!(d.sigs, vec![Sig::Int]);
}

#[test]
fn isig_quit_susp() {
    let mut n = NTty::new();
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, &[0x1c]); // ^\
    n.receive_buf(&mut d, &[0x1a]); // ^Z
    assert_eq!(d.sigs, vec![Sig::Quit, Sig::Tstp]);
}

#[test]
fn isig_drops_pending_line() {
    let mut n = NTty::new();
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, b"half");
    n.receive_buf(&mut d, &[0x03]); // ^C drops the half line
    n.receive_buf(&mut d, b"done\n");
    assert_eq!(drain(&mut n), b"done\n");
}

#[test]
fn isig_cleared_no_signal() {
    let mut t = default_termios();
    let mut lf = crate::pty::read_lflag(&t);
    lf &= !lflag::ISIG;
    set_u32(&mut t, TERMIOS_OFF_LFLAG, lf);
    let mut n = NTty::with_termios(t);
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, &[0x03, b'\n']); // ^C now a literal byte
    assert!(d.sigs.is_empty());
    let got = drain(&mut n);
    assert_eq!(got, &[0x03, b'\n']);
}

// ---- iflag mapping ----

#[test]
fn icrnl_cr_becomes_nl() {
    // Default termios has ICRNL set.
    let mut n = NTty::new();
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, b"x\r"); // \r → \n completes line
    assert_eq!(drain(&mut n), b"x\n");
}

#[test]
fn igncr_drops_cr() {
    let mut t = default_termios();
    set_u32(&mut t, TERMIOS_OFF_IFLAG, iflag::IGNCR);
    let mut n = NTty::with_termios(t);
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, b"a\rb\n");
    assert_eq!(drain(&mut n), b"ab\n");
}

#[test]
fn inlcr_nl_becomes_cr() {
    // INLCR maps \n→\r. With ICANON the \r is not a terminator, so no
    // line completes; switch to raw to observe the byte.
    let mut t = default_termios();
    set_u32(&mut t, TERMIOS_OFF_IFLAG, iflag::INLCR);
    let mut lf = crate::pty::read_lflag(&t);
    lf &= !lflag::ICANON;
    set_u32(&mut t, TERMIOS_OFF_LFLAG, lf);
    let mut n = NTty::with_termios(t);
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, b"\n");
    assert_eq!(drain(&mut n), b"\r");
}

// ---- raw mode ----

fn raw_termios() -> [u8; TERMIOS_BYTES] {
    let mut t = default_termios();
    set_u32(&mut t, TERMIOS_OFF_LFLAG, 0); // no ICANON/ECHO/ISIG
    set_u32(&mut t, TERMIOS_OFF_IFLAG, 0); // no CR/NL mapping
    set_u32(&mut t, TERMIOS_OFF_OFLAG, 0); // no OPOST
    t[TERMIOS_OFF_CC + cc::VMIN] = 1;
    t[TERMIOS_OFF_CC + cc::VTIME] = 0;
    t
}

#[test]
fn raw_each_byte_immediately_readable() {
    let mut n = NTty::with_termios(raw_termios());
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, b"a");
    let mut buf = [0u8; 8];
    assert_eq!(n.read(&mut buf), 1);
    assert_eq!(buf[0], b'a');
    // No echo (ECHO off).
    assert!(d.out.is_empty());
}

#[test]
fn raw_no_line_buffering() {
    let mut n = NTty::with_termios(raw_termios());
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, b"abc"); // no newline needed
    assert_eq!(drain(&mut n), b"abc");
}

#[test]
fn raw_vmin_holds_until_threshold() {
    let mut t = raw_termios();
    t[TERMIOS_OFF_CC + cc::VMIN] = 3;
    let mut n = NTty::with_termios(t);
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, b"ab");
    let mut buf = [0u8; 8];
    assert_eq!(n.read(&mut buf), 0); // fewer than VMIN=3
    n.receive_buf(&mut d, b"c");
    let got = n.read(&mut buf);
    assert_eq!(&buf[..got], b"abc");
}

#[test]
fn raw_echo_on_when_echo_set() {
    let mut t = raw_termios();
    set_u32(&mut t, TERMIOS_OFF_LFLAG, lflag::ECHO);
    let mut n = NTty::with_termios(t);
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, b"z");
    assert_eq!(d.out, b"z");
}

// ---- output OPOST ----

#[test]
fn opost_onlcr_expands_newline() {
    let mut n = NTty::new(); // OPOST|ONLCR default
    let mut d = RecordingDriver::default();
    let w = n.write(&mut d, b"hi\n");
    assert_eq!(w, 3);
    assert_eq!(d.out, b"hi\r\n");
}

#[test]
fn opost_off_passthrough() {
    let mut t = default_termios();
    set_u32(&mut t, TERMIOS_OFF_OFLAG, 0);
    let mut n = NTty::with_termios(t);
    let mut d = RecordingDriver::default();
    n.write(&mut d, b"hi\n");
    assert_eq!(d.out, b"hi\n");
}

#[test]
fn opost_tab_expansion_col_tracking() {
    // Tab from col 0 → 8 spaces is NOT what Linux does by default
    // (TAB3 expansion only with XTABS); our model expands tabs to the
    // next stop unconditionally under OPOST. Assert the stop math.
    let mut n = NTty::new();
    let mut d = RecordingDriver::default();
    n.write(&mut d, b"ab\tc");
    // "ab" → col 2; tab → 6 spaces to col 8; "c" → col 9.
    assert_eq!(d.out, b"ab      c");
}

#[test]
fn opost_ocrnl() {
    let mut t = default_termios();
    set_u32(&mut t, TERMIOS_OFF_OFLAG, oflag::OPOST | oflag::OCRNL);
    let mut n = NTty::with_termios(t);
    let mut d = RecordingDriver::default();
    n.write(&mut d, b"a\rb");
    assert_eq!(d.out, b"a\nb");
}

// ---- poll ----

#[test]
fn poll_reflects_input_and_eof() {
    let mut n = NTty::new();
    let mut d = RecordingDriver::default();
    assert_eq!(n.poll() & pollmask::POLLIN, 0);
    assert_eq!(n.poll() & pollmask::POLLOUT, pollmask::POLLOUT);
    n.receive_buf(&mut d, b"x\n");
    assert_eq!(n.poll() & pollmask::POLLIN, pollmask::POLLIN);
    let _ = drain(&mut n);
    assert_eq!(n.poll() & pollmask::POLLIN, 0);
    // EOF also flags POLLIN.
    n.receive_buf(&mut d, &[0x04]);
    assert_eq!(n.poll() & pollmask::POLLIN, pollmask::POLLIN);
}

// ---- termios switch flushes canon to raw ----

#[test]
fn set_termios_to_raw_flushes_pending_line() {
    let mut n = NTty::new();
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, b"partial");
    n.set_termios(&raw_termios());
    assert_eq!(drain(&mut n), b"partial");
}

// ---- fuzz: never panic, never over-read, never split a line ----

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
use super::{vmin_vtime_decision, VmtDecision, n_tty::VTIME_TENTH_NS};

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
