use super::*;

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
