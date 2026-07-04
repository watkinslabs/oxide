use super::*;

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

// ---- IXON flow control (d) ----

/// A raw-mode (ICANON off) NTty with IXON enabled, so ^S/^Q are flow
/// control and output is the simple raw passthrough we can observe.
fn ixon_raw() -> NTty {
    let mut t = default_termios();
    // raw: clear ICANON|ECHO so input goes straight to readq, output raw.
    set_u32(&mut t, TERMIOS_OFF_LFLAG, 0);
    let il = crate::pty::read_iflag(&t) | iflag::IXON;
    set_u32(&mut t, TERMIOS_OFF_IFLAG, il);
    // VMIN=0 so a read with nothing queued returns 0 (no min-bytes wait).
    t[TERMIOS_OFF_CC + cc::VMIN] = 0;
    NTty::with_termios(t)
}

#[test]
fn flow_action_classifies_stop_start_normal() {
    use crate::ldisc::{flow_action, FlowAction};
    let on = iflag::IXON;
    assert_eq!(flow_action(on, 0x13, 0x11, 0x13, false), FlowAction::Stop);
    assert_eq!(flow_action(on, 0x13, 0x11, 0x11, true),  FlowAction::Start);
    assert_eq!(flow_action(on, 0x13, 0x11, b'a',  false), FlowAction::Normal);
    // IXON off → never flow control.
    assert_eq!(flow_action(0, 0x13, 0x11, 0x13, false), FlowAction::Normal);
    // IXANY: any byte while stopped restarts.
    assert_eq!(flow_action(on | iflag::IXANY, 0x13, 0x11, b'z', true), FlowAction::Start);
    // IXANY but not stopped → normal.
    assert_eq!(flow_action(on | iflag::IXANY, 0x13, 0x11, b'z', false), FlowAction::Normal);
}

#[test]
fn ixon_vstop_sets_stopped_and_consumes_byte() {
    let mut n = ixon_raw();
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, b"\x13"); // ^S
    assert!(n.stopped(), "VSTOP set the stop flag");
    let mut buf = [0u8; 8];
    assert_eq!(n.read(&mut buf), 0, "^S byte was consumed, not queued");
}

#[test]
fn ixon_vstart_clears_stopped_and_consumes_byte() {
    let mut n = ixon_raw();
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, b"\x13"); // ^S
    n.receive_buf(&mut d, b"\x11"); // ^Q
    assert!(!n.stopped(), "VSTART cleared the stop flag");
    let mut buf = [0u8; 8];
    assert_eq!(n.read(&mut buf), 0, "^S/^Q both consumed");
}

#[test]
fn ixon_output_withheld_while_stopped_then_flushed_on_start() {
    let mut n = ixon_raw();
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, b"\x13"); // ^S — stop output
    // Writes are withheld, NOT sent to the driver.
    let w = n.write(&mut d, b"hello");
    assert_eq!(w, 5, "write reports full consumption (buffered)");
    assert!(d.out.is_empty(), "nothing reached the driver while stopped");
    // ^Q flushes the held output in order.
    n.receive_buf(&mut d, b"\x11");
    assert_eq!(&d.out, b"hello", "withheld output flushed on VSTART");
}

#[test]
fn ixon_ixany_resumes_and_keeps_the_restart_byte() {
    let mut t = default_termios();
    set_u32(&mut t, TERMIOS_OFF_LFLAG, 0);
    let il = crate::pty::read_iflag(&t) | iflag::IXON | iflag::IXANY;
    set_u32(&mut t, TERMIOS_OFF_IFLAG, il);
    t[TERMIOS_OFF_CC + cc::VMIN] = 0;
    let mut n = NTty::with_termios(t);
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, b"\x13");          // ^S
    n.write(&mut d, b"out");                  // withheld
    n.receive_buf(&mut d, b"x");              // IXANY: any byte resumes
    assert!(!n.stopped());
    assert_eq!(&d.out, b"out", "held output flushed by IXANY restart");
    // The restart byte itself is still input (raw → readq).
    let mut buf = [0u8; 8];
    let got = n.read(&mut buf);
    assert_eq!(&buf[..got], b"x", "IXANY restart byte is still processed");
}

// ---- hangup (c): ldisc hung-up state ----

#[test]
fn hangup_flushes_queues_and_reports_eof() {
    let mut n = NTty::new();
    let mut d = RecordingDriver::default();
    n.receive_buf(&mut d, b"queued\n"); // a full cooked line waiting
    assert!(n.has_input());
    n.hangup();
    assert!(n.is_hung_up());
    // Queues flushed; read reports EOF (0) with eof_consumed set.
    let mut buf = [0u8; 64];
    assert_eq!(n.read(&mut buf), 0, "hung-up read → EOF");
    assert!(n.eof_consumed(), "EOF, not empty-park");
    // has_input stays true so the core never parks forever on a hung tty.
    assert!(n.has_input());
}

#[test]
fn hangup_drops_writes_and_ignores_input() {
    let mut n = NTty::new();
    let mut d = RecordingDriver::default();
    n.hangup();
    // Writes are dropped (Linux: EIO at the syscall layer).
    let w = n.write(&mut d, b"output");
    assert_eq!(w, 6, "write reports consumed");
    assert!(d.out.is_empty(), "hung-up write reaches nothing");
    // Input after hangup is ignored.
    n.receive_buf(&mut d, b"typed\n");
    let mut buf = [0u8; 8];
    assert_eq!(n.read(&mut buf), 0, "no input accepted after hangup");
}

// ---- fuzz: never panic, never over-read, never split a line ----
