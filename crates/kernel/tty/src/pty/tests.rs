// Hosted tests for the PTY pair core per `28§5`.

use super::*;

#[test]
fn ring_starts_empty_with_full_space() {
    let r = Ring::new();
    assert_eq!(r.len(), 0);
    assert!(r.is_empty());
    assert_eq!(r.space(), PTY_BUF_BYTES);
}

#[test]
fn ring_write_then_read_round_trip() {
    let mut r = Ring::new();
    assert_eq!(r.write(b"hello"), 5);
    let mut buf = [0u8; 8];
    assert_eq!(r.read(&mut buf), 5);
    assert_eq!(&buf[..5], b"hello");
    assert!(r.is_empty());
}

#[test]
fn ring_write_caps_at_capacity_drops_excess() {
    let mut r = Ring::new();
    let big = alloc::vec![b'x'; PTY_BUF_BYTES + 100];
    let n = r.write(&big);
    assert_eq!(n, PTY_BUF_BYTES);
    assert_eq!(r.space(), 0);
    // A second write returns 0 — caller's job to retry / EAGAIN.
    assert_eq!(r.write(b"more"), 0);
}

#[test]
fn ring_read_into_short_buf_leaves_remainder() {
    let mut r = Ring::new();
    r.write(b"abcdef");
    let mut buf = [0u8; 3];
    assert_eq!(r.read(&mut buf), 3);
    assert_eq!(&buf, b"abc");
    let mut buf2 = [0u8; 8];
    assert_eq!(r.read(&mut buf2), 3);
    assert_eq!(&buf2[..3], b"def");
}

#[test]
fn ring_read_empty_returns_zero() {
    let mut r = Ring::new();
    let mut buf = [0u8; 4];
    assert_eq!(r.read(&mut buf), 0);
}

#[test]
fn pair_master_writes_appear_on_slave_reads() {
    let mut p = Pair::new(0);
    assert_eq!(p.master_write(b"keystrokes"), 10);
    let mut buf = [0u8; 16];
    assert_eq!(p.slave_read(&mut buf), 10);
    assert_eq!(&buf[..10], b"keystrokes");
}

#[test]
fn pair_slave_writes_appear_on_master_reads() {
    let mut p = Pair::new(1);
    assert_eq!(p.slave_write(b"program output"), 14);
    let mut buf = [0u8; 32];
    assert_eq!(p.master_read(&mut buf), 14);
    assert_eq!(&buf[..14], b"program output");
}

#[test]
fn pair_directions_are_independent() {
    let mut p = Pair::new(2);
    p.master_write(b"in");
    p.slave_write(b"out");
    let mut mbuf = [0u8; 8];
    let mut sbuf = [0u8; 8];
    // Master read returns slave-written bytes; slave read returns master-written.
    assert_eq!(p.master_read(&mut mbuf), 3);
    assert_eq!(&mbuf[..3], b"out");
    assert_eq!(p.slave_read(&mut sbuf), 2);
    assert_eq!(&sbuf[..2], b"in");
}

#[test]
fn pair_pts_num_preserved() {
    let p = Pair::new(7);
    assert_eq!(p.pts_num, 7);
}

#[test]
fn pair_hangup_flag_set() {
    let mut p = Pair::new(0);
    assert!(!p.hung_up);
    p.hangup();
    assert!(p.hung_up);
}

#[test]
fn pair_foreground_pgid_defaults_zero() {
    let p = Pair::new(0);
    assert_eq!(p.foreground_pgid, 0);
}

#[test]
fn pair_foreground_pgid_round_trip() {
    // Mirrors TIOCSPGRP then TIOCGPGRP from userspace.
    let mut p = Pair::new(0);
    p.foreground_pgid = 4099;
    assert_eq!(p.foreground_pgid, 4099);
}

#[test]
fn pair_buffered_data_survives_hangup() {
    // Linux: hangup makes *empty* reads return EOF, but already-buffered
    // bytes can still be drained.
    let mut p = Pair::new(0);
    p.slave_write(b"final output");
    p.hangup();
    let mut buf = [0u8; 32];
    assert_eq!(p.master_read(&mut buf), 12);
    assert_eq!(&buf[..12], b"final output");
}

// ---------------------------------------------------------------------------
// Cooked mode (ICANON | ECHO | ISIG) — `28§5` line discipline
// ---------------------------------------------------------------------------

fn cooked(pts: u32) -> Pair {
    let mut p = Pair::new(pts);
    p.termios = default_termios();
    p
}

#[test]
fn cooked_master_write_echoes_back_to_master_read() {
    let mut p = cooked(0);
    p.master_write(b"abc\n");
    let mut buf = [0u8; 16];
    // Echo bytes appear immediately on master read (no line-buffer on master).
    let n = p.master_read(&mut buf);
    assert_eq!(n, 4);
    assert_eq!(&buf[..4], b"abc\n");
}

#[test]
fn cooked_slave_read_blocks_until_newline() {
    let mut p = cooked(0);
    p.master_write(b"hi");
    let mut buf = [0u8; 16];
    // ICANON: no newline yet → slave reads 0.
    assert_eq!(p.slave_read(&mut buf), 0);
    p.master_write(b" there\n");
    // Newline now present — drains exactly the line up to and including \n.
    let n = p.slave_read(&mut buf);
    assert_eq!(n, 9);
    assert_eq!(&buf[..9], b"hi there\n");
}

#[test]
fn cooked_slave_read_drains_one_line_at_a_time() {
    let mut p = cooked(0);
    p.master_write(b"one\ntwo\n");
    let mut buf = [0u8; 32];
    let n1 = p.slave_read(&mut buf);
    assert_eq!(n1, 4);
    assert_eq!(&buf[..4], b"one\n");
    let n2 = p.slave_read(&mut buf);
    assert_eq!(n2, 4);
    assert_eq!(&buf[..4], b"two\n");
    assert_eq!(p.slave_read(&mut buf), 0);
}

#[test]
fn cooked_vintr_records_pending_sigint_and_drops_byte() {
    let mut p = cooked(0);
    p.foreground_pgid = 7;
    p.master_write(b"a\x03b\n");
    assert!(p.pending_sigint, "VINTR must set pending_sigint under ISIG");
    let mut buf = [0u8; 16];
    let n = p.slave_read(&mut buf);
    // The ^C is dropped from the input stream; "ab\n" reaches the slave.
    assert_eq!(n, 3);
    assert_eq!(&buf[..3], b"ab\n");
}

#[test]
fn cooked_vintr_echoes_caret_c_on_master() {
    let mut p = cooked(0);
    p.master_write(b"\x03");
    let mut buf = [0u8; 16];
    let n = p.master_read(&mut buf);
    // Echo of ^C is the literal two bytes "^C" (Linux ldisc behaviour).
    assert_eq!(n, 2);
    assert_eq!(&buf[..2], b"^C");
}

#[test]
fn raw_mode_passes_vintr_through() {
    // lflag == 0 (raw) → ^C is just data.
    let mut p = Pair::new(0);
    p.master_write(b"a\x03b");
    assert!(!p.pending_sigint);
    let mut buf = [0u8; 16];
    let n = p.slave_read(&mut buf);
    assert_eq!(n, 3);
    assert_eq!(&buf[..3], b"a\x03b");
}

#[test]
fn raw_mode_no_echo_on_master_write() {
    let mut p = Pair::new(0);
    p.master_write(b"hi");
    let mut buf = [0u8; 8];
    // No echo — master_read drains s_to_m which is empty.
    assert_eq!(p.master_read(&mut buf), 0);
}

// ---------------------------------------------------------------------------
// Termios byte image — Linux struct termios layout
// ---------------------------------------------------------------------------

#[test]
fn default_termios_has_canonical_flags_and_vintr() {
    let t = default_termios();
    assert_eq!(read_lflag(&t), DEFAULT_LFLAG);
    assert_eq!(read_iflag(&t), DEFAULT_IFLAG);
    assert_eq!(read_oflag(&t), DEFAULT_OFLAG);
    assert_eq!(read_vintr(&t), DEFAULT_VINTR);
    // c_cflag defaults zero in v1 (no baud / parity tracking yet).
    assert_eq!(read_termios_u32(&t, TERMIOS_OFF_CFLAG), 0);
    assert_eq!(t[TERMIOS_OFF_LINE], 0);
}

#[test]
fn pair_lflag_accessor_reads_termios_bytes() {
    let mut p = Pair::new(0);
    assert_eq!(p.lflag(), 0);
    p.termios = default_termios();
    assert_eq!(p.lflag(), DEFAULT_LFLAG);
}

#[test]
fn pair_vintr_accessor_reads_c_cc() {
    let mut p = Pair::new(0);
    p.termios = default_termios();
    assert_eq!(p.vintr(), DEFAULT_VINTR);
    // Custom VINTR via c_cc[0] — Linux supports `stty intr ^X`.
    p.termios[TERMIOS_OFF_CC] = 0x18; // ^X
    assert_eq!(p.vintr(), 0x18);
}

#[test]
fn cooked_vintr_honours_termios_c_cc() {
    // Re-bind VINTR to ^X and feed it through master_write.
    let mut p = cooked(0);
    p.termios[TERMIOS_OFF_CC] = 0x18;
    p.master_write(b"\x18");
    assert!(p.pending_sigint, "remapped VINTR must trigger pending_sigint");
}

#[test]
fn cooked_vintr_zero_disables_isig_path() {
    // c_cc[VINTR]==0 disables the dispatch — the byte passes as data.
    let mut p = cooked(0);
    p.termios[TERMIOS_OFF_CC] = 0;
    p.master_write(b"\x03ok\n");
    assert!(!p.pending_sigint);
    let mut buf = [0u8; 8];
    let n = p.slave_read(&mut buf);
    // ^C reaches the slave as an ordinary byte under VINTR=0.
    assert_eq!(n, 4);
    assert_eq!(&buf[..4], b"\x03ok\n");
}

#[test]
fn termios_round_trip_through_byte_image() {
    // TCSETS writes the whole image; TCGETS reads it back.
    let mut p = Pair::new(0);
    let mut img = default_termios();
    img[TERMIOS_OFF_IFLAG] = 0xAA;
    img[TERMIOS_OFF_OFLAG + 2] = 0x55;
    img[TERMIOS_OFF_CC + 5] = 0xCC;
    p.termios = img;
    assert_eq!(p.termios, img);
    assert_eq!(p.lflag(), DEFAULT_LFLAG);
}

// ---------------------------------------------------------------------------
// Winsize — TIOCGWINSZ / TIOCSWINSZ + SIGWINCH dispatch flag
// ---------------------------------------------------------------------------

#[test]
fn winsize_default_pty_is_24x80() {
    let ws = Winsize::default_pty();
    assert_eq!(ws.rows, 24);
    assert_eq!(ws.cols, 80);
    assert_eq!(ws.xpixel, 0);
    assert_eq!(ws.ypixel, 0);
}

#[test]
fn winsize_le_bytes_round_trip() {
    let ws = Winsize { rows: 50, cols: 132, xpixel: 1024, ypixel: 768 };
    let b = ws.to_le_bytes();
    // little-endian: rows.lo, rows.hi, cols.lo, cols.hi, ...
    assert_eq!(b, [50, 0, 132, 0, 0x00, 0x04, 0x00, 0x03]);
    let back = Winsize::from_le_bytes(&b);
    assert_eq!(back, ws);
}

#[test]
fn pair_winsize_default_pty() {
    let p = Pair::new(0);
    assert_eq!(p.winsize, Winsize::default_pty());
    assert!(!p.pending_sigwinch);
}

#[test]
fn pair_set_winsize_flags_pending_on_change() {
    let mut p = Pair::new(0);
    p.set_winsize(Winsize { rows: 30, cols: 100, xpixel: 0, ypixel: 0 });
    assert!(p.pending_sigwinch);
    assert_eq!(p.winsize.rows, 30);
    assert_eq!(p.winsize.cols, 100);
}

#[test]
fn pair_set_winsize_no_op_when_unchanged() {
    let mut p = Pair::new(0);
    p.set_winsize(Winsize::default_pty());
    assert!(!p.pending_sigwinch, "no-op set must not fire SIGWINCH");
}

// ---------------------------------------------------------------------------
// iflag / oflag — line-discipline byte translation
// ---------------------------------------------------------------------------

#[test]
fn cooked_icrnl_translates_carriage_return_to_newline() {
    // Default iflag has ICRNL. Terminal Enter sends \r; ldisc converts
    // it to \n so cooked-mode slave_read can complete a line.
    let mut p = cooked(0);
    p.master_write(b"hello\r");
    let mut buf = [0u8; 16];
    // ICRNL turned \r into \n → line is complete.
    let n = p.slave_read(&mut buf);
    assert_eq!(n, 6);
    assert_eq!(&buf[..6], b"hello\n");
}

#[test]
fn cooked_igncr_drops_carriage_return() {
    let mut p = cooked(0);
    let iflag = read_iflag(&p.termios);
    let new_iflag = (iflag & !iflag::ICRNL) | iflag::IGNCR;
    p.termios[TERMIOS_OFF_IFLAG..TERMIOS_OFF_IFLAG + 4]
        .copy_from_slice(&new_iflag.to_le_bytes());
    p.master_write(b"a\rb\n");
    let mut buf = [0u8; 16];
    let n = p.slave_read(&mut buf);
    assert_eq!(n, 3);
    assert_eq!(&buf[..3], b"ab\n");
}

#[test]
fn cooked_inlcr_translates_newline_to_cr() {
    let mut p = cooked(0);
    let iflag = read_iflag(&p.termios);
    let new_iflag = (iflag & !iflag::ICRNL) | iflag::INLCR;
    p.termios[TERMIOS_OFF_IFLAG..TERMIOS_OFF_IFLAG + 4]
        .copy_from_slice(&new_iflag.to_le_bytes());
    // \n becomes \r — no longer a line terminator under ICANON.
    p.master_write(b"hi\n");
    let mut buf = [0u8; 16];
    // No newline in m_to_s after INLCR translation → slave_read = 0.
    assert_eq!(p.slave_read(&mut buf), 0);
}

#[test]
fn cooked_onlcr_expands_newline_on_slave_write() {
    // Default oflag = OPOST | ONLCR. Slave writes "ok\n" → master sees "ok\r\n".
    let mut p = cooked(0);
    p.slave_write(b"ok\n");
    let mut buf = [0u8; 16];
    let n = p.master_read(&mut buf);
    assert_eq!(n, 4);
    assert_eq!(&buf[..4], b"ok\r\n");
}

#[test]
fn raw_slave_write_skips_oflag_transformations() {
    // Pair::new starts raw (oflag = 0); slave_write is verbatim.
    let mut p = Pair::new(0);
    p.slave_write(b"raw\n");
    let mut buf = [0u8; 16];
    let n = p.master_read(&mut buf);
    assert_eq!(n, 4);
    assert_eq!(&buf[..4], b"raw\n");
}

#[test]
fn cooked_opost_off_disables_onlcr() {
    let mut p = cooked(0);
    let oflag = read_oflag(&p.termios);
    let new_oflag = oflag & !oflag::OPOST;
    p.termios[TERMIOS_OFF_OFLAG..TERMIOS_OFF_OFLAG + 4]
        .copy_from_slice(&new_oflag.to_le_bytes());
    p.slave_write(b"x\n");
    let mut buf = [0u8; 16];
    let n = p.master_read(&mut buf);
    assert_eq!(n, 2, "OPOST off → no expansion");
    assert_eq!(&buf[..2], b"x\n");
}

#[test]
fn master_readable_tracks_s_to_m() {
    let mut p = Pair::new(0);
    assert!(!p.master_readable());
    p.slave_write(b"x");
    assert!(p.master_readable());
    let mut buf = [0u8; 4];
    p.master_read(&mut buf);
    assert!(!p.master_readable());
}

#[test]
fn slave_readable_raw_mode_any_byte() {
    let mut p = Pair::new(0); // raw
    assert!(!p.slave_readable());
    p.master_write(b"x");
    assert!(p.slave_readable());
}

#[test]
fn slave_readable_cooked_requires_newline() {
    let mut p = cooked(0);
    p.master_write(b"hi");
    assert!(!p.slave_readable(), "ICANON needs \\n");
    p.master_write(b"\n");
    assert!(p.slave_readable());
    let mut buf = [0u8; 8];
    p.slave_read(&mut buf);
    assert!(!p.slave_readable());
}

#[test]
fn default_termios_populates_full_c_cc_set() {
    let t = default_termios();
    assert_eq!(t[TERMIOS_OFF_CC + cc::VINTR],  DEFAULT_VINTR);
    assert_eq!(t[TERMIOS_OFF_CC + cc::VQUIT],  DEFAULT_VQUIT);
    assert_eq!(t[TERMIOS_OFF_CC + cc::VERASE], DEFAULT_VERASE);
    assert_eq!(t[TERMIOS_OFF_CC + cc::VKILL],  DEFAULT_VKILL);
    assert_eq!(t[TERMIOS_OFF_CC + cc::VEOF],   DEFAULT_VEOF);
    assert_eq!(t[TERMIOS_OFF_CC + cc::VSUSP],  DEFAULT_VSUSP);
    // Remaining slots stay zero.
    assert_eq!(t[TERMIOS_OFF_CC + cc::VTIME],  0);
    assert_eq!(t[TERMIOS_OFF_CC + cc::VMIN],   0);
    assert_eq!(t[TERMIOS_OFF_CC + cc::VEOL],   0);
}

#[test]
fn cooked_veof_on_empty_line_terminates_with_zero_bytes() {
    let mut p = cooked(0);
    p.master_write(b"\x04"); // ^D on empty line
    assert!(p.pending_eof);
    let mut buf = [0u8; 16];
    // slave_read returns 0 (EOF), clears the flag.
    assert_eq!(p.slave_read(&mut buf), 0);
    assert!(!p.pending_eof, "EOF flag cleared after delivery");
}

#[test]
fn cooked_veof_after_partial_line_drains_buffer() {
    let mut p = cooked(0);
    p.master_write(b"hi");        // partial line, no \n yet
    p.master_write(b"\x04");      // ^D — terminates without \n
    assert!(p.pending_eof);
    let mut buf = [0u8; 16];
    let n = p.slave_read(&mut buf);
    assert_eq!(n, 2);
    assert_eq!(&buf[..2], b"hi");
    // Next read sees the empty queue + cleared flag → 0 (EOF still).
    assert!(!p.pending_eof);
}

#[test]
fn cooked_veof_zero_disables_eof_path() {
    let mut p = cooked(0);
    p.termios[TERMIOS_OFF_CC + cc::VEOF] = 0;
    p.master_write(b"\x04");
    assert!(!p.pending_eof, "VEOF=0 disables");
    // Byte passes through as data.
    let mut buf = [0u8; 4];
    p.master_write(b"\n");
    let n = p.slave_read(&mut buf);
    assert_eq!(n, 2);
    assert_eq!(&buf[..2], b"\x04\n");
}

#[test]
fn cooked_veof_does_not_fire_in_raw_mode() {
    let mut p = Pair::new(0); // raw
    p.termios[TERMIOS_OFF_CC + cc::VEOF] = 0x04;
    p.master_write(b"\x04");
    assert!(!p.pending_eof, "raw mode skips ICANON-only EOF path");
}

#[test]
fn cooked_verase_backspaces_unfinished_line() {
    let mut p = cooked(0);
    p.master_write(b"abc");
    p.master_write(b"\x7f");  // DEL = default VERASE
    p.master_write(b"\n");
    let mut buf = [0u8; 16];
    let n = p.slave_read(&mut buf);
    assert_eq!(n, 3);
    assert_eq!(&buf[..3], b"ab\n");
}

#[test]
fn cooked_verase_does_not_eat_past_newline() {
    let mut p = cooked(0);
    p.master_write(b"first\n");
    p.master_write(b"\x7f"); // backspace: should NOT touch "first\n"
    p.master_write(b"x\n");
    let mut buf = [0u8; 32];
    let n1 = p.slave_read(&mut buf);
    assert_eq!(n1, 6);
    assert_eq!(&buf[..6], b"first\n");
    let n2 = p.slave_read(&mut buf);
    assert_eq!(n2, 2);
    assert_eq!(&buf[..2], b"x\n");
}

#[test]
fn cooked_vkill_clears_unfinished_line() {
    let mut p = cooked(0);
    p.master_write(b"oops");
    p.master_write(b"\x15"); // ^U = default VKILL
    p.master_write(b"ok\n");
    let mut buf = [0u8; 16];
    let n = p.slave_read(&mut buf);
    assert_eq!(n, 3);
    assert_eq!(&buf[..3], b"ok\n");
}

#[test]
fn cooked_verase_echoes_destructive_backspace() {
    let mut p = cooked(0);
    p.master_write(b"x");
    let mut echo = [0u8; 8];
    let _ = p.master_read(&mut echo); // drain echo of 'x'
    p.master_write(b"\x7f");
    let n = p.master_read(&mut echo);
    // Linux ldisc echoes "\b \b" — destructive backspace.
    assert_eq!(n, 3);
    assert_eq!(&echo[..3], b"\x08 \x08");
}

#[test]
fn ixon_vstop_pauses_slave_writes() {
    let mut p = cooked(0);
    let iflag = read_iflag(&p.termios);
    p.termios[TERMIOS_OFF_IFLAG..TERMIOS_OFF_IFLAG + 4]
        .copy_from_slice(&(iflag | iflag::IXON).to_le_bytes());
    // ^S on master pauses output.
    p.master_write(b"\x13");
    assert!(p.output_stopped);
    // slave_write under output_stopped is silently consumed.
    let n = p.slave_write(b"hello");
    assert_eq!(n, 5);
    let mut buf = [0u8; 16];
    assert_eq!(p.master_read(&mut buf), 0, "no bytes reach master");
}

#[test]
fn ixon_vstart_resumes_slave_writes() {
    let mut p = cooked(0);
    let iflag = read_iflag(&p.termios);
    p.termios[TERMIOS_OFF_IFLAG..TERMIOS_OFF_IFLAG + 4]
        .copy_from_slice(&(iflag | iflag::IXON).to_le_bytes());
    p.master_write(b"\x13");                  // ^S
    p.slave_write(b"dropped");                // dropped while paused
    p.master_write(b"\x11");                  // ^Q
    assert!(!p.output_stopped);
    p.slave_write(b"ok\n");
    let mut buf = [0u8; 16];
    let n = p.master_read(&mut buf);
    // ONLCR expands \n → \r\n
    assert_eq!(n, 4);
    assert_eq!(&buf[..4], b"ok\r\n");
}

#[test]
fn ixon_off_passes_ctrl_chars_through() {
    // IXON is OFF in cooked default — the master_write should let ^S/^Q
    // through to the slave as data.
    let mut p = cooked(0);
    p.master_write(b"\x13\n");
    let mut buf = [0u8; 8];
    let n = p.slave_read(&mut buf);
    assert_eq!(n, 2);
    assert_eq!(&buf[..2], b"\x13\n");
    assert!(!p.output_stopped, "no IXON → no flow control");
}

#[test]
fn cooked_vsusp_records_pending_sigtstp() {
    let mut p = cooked(0);
    p.master_write(b"a\x1ab\n"); // ^Z mid-line
    assert!(p.pending_sigtstp);
    let mut buf = [0u8; 16];
    let n = p.slave_read(&mut buf);
    assert_eq!(n, 3);
    assert_eq!(&buf[..3], b"ab\n");
}

#[test]
fn cooked_vquit_records_pending_sigquit() {
    let mut p = cooked(0);
    p.master_write(b"\x1c"); // ^\ alone
    assert!(p.pending_sigquit);
}

#[test]
fn cooked_vsusp_echoes_caret_z() {
    let mut p = cooked(0);
    p.master_write(b"\x1a");
    let mut buf = [0u8; 16];
    let n = p.master_read(&mut buf);
    assert_eq!(n, 2);
    assert_eq!(&buf[..2], b"^Z");
}

#[test]
fn cooked_vquit_echoes_caret_backslash() {
    let mut p = cooked(0);
    p.master_write(b"\x1c");
    let mut buf = [0u8; 16];
    let n = p.master_read(&mut buf);
    assert_eq!(n, 2);
    assert_eq!(&buf[..2], b"^\\");
}

#[test]
fn raw_mode_passes_vsusp_through() {
    let mut p = Pair::new(0); // raw
    p.termios[TERMIOS_OFF_CC + cc::VSUSP] = 0x1A;
    p.master_write(b"\x1a");
    assert!(!p.pending_sigtstp, "raw mode skips ISIG");
}
