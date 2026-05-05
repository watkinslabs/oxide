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
    p.lflag = DEFAULT_LFLAG;
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
