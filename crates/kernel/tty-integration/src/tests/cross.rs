// Cross-stack equivalence (tty-rebuild-plan §3-T9 surface 3). The N_TTY
// line discipline is SHARED by the VT and serial tty drivers; feeding the
// SAME RX byte sequence through both assembled stacks must yield the SAME
// cooked read() stream. A divergence means the ldisc behaviour leaked
// into a driver — exactly the bug class this net guards against.

use super::harness::*;
use std::vec::Vec;

/// Drain a VT stack's cooked output for one RX sequence.
fn vt_cooked(seq: &[u8]) -> Vec<u8> {
    let (tty, _consw, _sig) = build_vt(40, 5);
    tty.receive_from_driver(seq);
    let mut buf = [0u8; 256];
    let n = tty.read_nonblock(&mut buf);
    buf[..n].to_vec()
}

/// Drain a serial stack's cooked output for one RX sequence.
fn ser_cooked(seq: &[u8]) -> Vec<u8> {
    let (tty, _out, _sig) = build_serial();
    tty.receive_from_driver(seq);
    let mut buf = [0u8; 256];
    let n = tty.read_nonblock(&mut buf);
    buf[..n].to_vec()
}

/// The two stacks agree on the cooked stream for a plain line.
#[test]
fn cross_plain_line_agrees() {
    let seq = b"hello\n";
    let v = vt_cooked(seq);
    let s = ser_cooked(seq);
    assert_eq!(v, s, "VT={:?} serial={:?}", v, s);
    assert_eq!(v, b"hello\n");
}

/// The two stacks agree on a line that uses backspace editing.
#[test]
fn cross_line_editing_agrees() {
    let seq = b"ls -l\x7f\x7fxy\n";
    let v = vt_cooked(seq);
    let s = ser_cooked(seq);
    assert_eq!(v, s, "VT={:?} serial={:?}", v, s);
    assert_eq!(v, b"ls xy\n", "edited line on both stacks");
}

/// The two stacks agree on WERASE (^W deletes the last word).
#[test]
fn cross_werase_agrees() {
    let seq = b"foo bar\x17\n"; // ^W erases "bar"
    let v = vt_cooked(seq);
    let s = ser_cooked(seq);
    assert_eq!(v, s, "VT={:?} serial={:?}", v, s);
    assert_eq!(v, b"foo \n", "WERASE drops the last word on both");
}

/// The two stacks agree on KILL (^U erases the whole line).
#[test]
fn cross_kill_agrees() {
    let seq = b"garbage\x15kept\n"; // ^U erases "garbage"
    let v = vt_cooked(seq);
    let s = ser_cooked(seq);
    assert_eq!(v, s, "VT={:?} serial={:?}", v, s);
    assert_eq!(v, b"kept\n", "KILL clears the line on both");
}
