// Serial-stack full-stack integration (tty-rebuild-plan §3-T9 surface 2).
// Drive the assembled `serialtty` stack and assert the UART TX bytes AND
// the program-visible read() stream together.

use super::harness::*;
use tty::ldisc::Sig;

/// TX OPOST: write "hi\n" → UART sees "hi\r\n" (ONLCR).
#[test]
fn ser_tx_opost_onlcr() {
    let (tty, out, _sig) = build_serial();
    let n = tty.write(b"hi\n");
    assert_eq!(n, 3, "byte count is the input length");
    assert_eq!(out.tx(), b"hi\r\n", "ONLCR inserts CR before LF on the wire");
}

/// TX OPOST off: write "hi\n" → UART sees "hi\n" verbatim.
#[test]
fn ser_tx_opost_off_raw() {
    let (tty, out, _sig) = build_serial_termios(opost_off_termios());
    tty.write(b"hi\n");
    assert_eq!(out.tx(), b"hi\n", "no CR when OPOST cleared");
}

/// RX → read + echo: type "cmd\n" → read() == "cmd\n" AND the echo
/// reaches the UART.
#[test]
fn ser_rx_reads_and_echoes_to_uart() {
    let (tty, out, _sig) = build_serial();
    tty.receive_from_driver(b"cmd\n");

    let mut buf = [0u8; 32];
    let got = tty.read(&mut buf);
    assert_eq!(&buf[..got], b"cmd\n", "cooked line to program");
    // Echo (the typed bytes) reaches the wire.
    assert_eq!(out.tx(), b"cmd\n", "echo on the UART");
}

/// Password ECHO off: type "secret\n" → read() == "secret\n" but the
/// UART stays silent.
#[test]
fn ser_password_echo_off_uart_silent() {
    let (tty, out, _sig) = build_serial_termios(echo_off_termios());
    tty.receive_from_driver(b"secret\n");

    let mut buf = [0u8; 32];
    let got = tty.read(&mut buf);
    assert_eq!(&buf[..got], b"secret\n", "program still sees the line");
    assert!(out.tx().is_empty(), "UART must be silent, got {:?}", out.tx());
}

/// Ctrl-C raises SIGINT on the fg pgrp (serial line).
#[test]
fn ser_ctrl_c_raises_sigint() {
    let (tty, _out, sig) = build_serial();
    ser_set_pgrp(&tty, 4242);
    tty.receive_from_driver(b"\x03");

    let sigs = sig.sigs();
    assert_eq!(sigs.len(), 1, "exactly one signal");
    assert_eq!(sigs[0], (4242, Sig::Int), "SIGINT to fg pgrp");
}

/// Ctrl-D at line start → read() returns 0 (EOF) on the serial line too.
#[test]
fn ser_ctrl_d_at_line_start_is_eof() {
    let (tty, _out, _sig) = build_serial();
    tty.receive_from_driver(b"\x04");

    let mut buf = [0u8; 32];
    let got = tty.read(&mut buf);
    assert_eq!(got, 0, "^D → EOF over serial");
}
