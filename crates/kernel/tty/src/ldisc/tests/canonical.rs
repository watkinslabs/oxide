use super::*;

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
