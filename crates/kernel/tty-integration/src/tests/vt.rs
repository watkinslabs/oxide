// VT-stack full-stack integration (tty-rebuild-plan §3-T9 surface 1).
// Each test drives the assembled `vtconsole` stack and asserts MULTIPLE
// surfaces — the program-visible read() stream, the `Vc` cell grid (what
// the screen shows), and the consw render ops — so a regression in any
// layer (ldisc, emulator, Vc, consw) is caught.

use super::harness::*;
use tty::ldisc::Sig;

/// Login flow: user types `root\n`; read() returns the cooked line AND
/// the echo renders to the Vc cells AND the renderer was driven.
#[test]
fn vt_login_line_reads_echoes_and_renders() {
    let (tty, consw, _sig) = build_vt(20, 5);
    tty.receive_from_driver(b"root\n");

    // (a) read() stream.
    let mut buf = [0u8; 32];
    let got = tty.read(&mut buf);
    assert_eq!(&buf[..got], b"root\n", "cooked login line");

    // (b) Vc cell grid: echo rendered "root" on row 0.
    assert!(vt_row(&tty, 0).starts_with("root"), "row0 = {:?}", vt_row(&tty, 0));

    // (c) consw was asked to paint.
    assert!(!consw.log().putcs.is_empty(), "renderer got no putcs");
}

/// Password flow: ECHO off; read() returns the line but NOTHING renders
/// to the Vc (screen stays blank).
#[test]
fn vt_password_echo_off_reads_but_screen_blank() {
    let (tty, _consw, _sig) = build_vt_termios(20, 3, echo_off_termios());
    tty.receive_from_driver(b"secret\n");

    let mut buf = [0u8; 32];
    let got = tty.read(&mut buf);
    assert_eq!(&buf[..got], b"secret\n", "cooked password line");

    // Nothing echoed → row 0 all blanks.
    assert_eq!(vt_row(&tty, 0).trim_end(), "", "screen must stay blank");
}

/// Shell line with editing: `ls -l\x7f\x7fxy\n` (two backspaces erase
/// "-l") → read() == "ls xy\n" AND the Vc shows the edited line.
#[test]
fn vt_line_editing_two_backspaces() {
    let (tty, _consw, _sig) = build_vt(20, 3);
    tty.receive_from_driver(b"ls -l\x7f\x7fxy\n");

    let mut buf = [0u8; 32];
    let got = tty.read(&mut buf);
    assert_eq!(&buf[..got], b"ls xy\n", "two backspaces should drop -l");

    // Screen shows the edited line (ECHOE \b \b erased the two cells).
    assert_eq!(vt_row(&tty, 0).trim_end(), "ls xy", "row0 = {:?}", vt_row(&tty, 0));
}

/// Program output with CSI/SGR: write red "ERR" + reset + newline →
/// Vc cell attrs show red fg AND ONLCR put the newline (cursor row 1).
#[test]
fn vt_program_output_csi_red_and_onlcr() {
    let (tty, consw, _sig) = build_vt(20, 5);
    let n = tty.write(b"\x1b[31mERR\x1b[0m\n");
    assert_eq!(n, 13, "all 13 input bytes accepted (ESC[31m + ERR + ESC[0m + \\n)");

    // Cells E,R,R carry red fg (resolved to VGA-red RGB).
    let red = vtdata::xterm_256_rgb(1);
    let a0 = tty.with_driver(|d| d.active().attr_at(0, 0)).unwrap();
    let a2 = tty.with_driver(|d| d.active().attr_at(2, 0)).unwrap();
    assert_eq!(a0.fg, red, "first cell red: {:?}", a0);
    assert_eq!(a2.fg, red, "third cell red: {:?}", a2);
    assert_eq!(vt_row(&tty, 0).trim_end(), "ERR");

    // ONLCR: the "\n" became CR+LF → cursor home col, advanced to row 1.
    assert_eq!(tty.with_driver(|d| (d.active().x, d.active().y)), (0, 1));
    assert!(!consw.log().putcs.is_empty());
}

/// Ctrl-C raises SIGINT on the fg pgrp.
#[test]
fn vt_ctrl_c_raises_sigint() {
    let (tty, _consw, sig) = build_vt(20, 3);
    vt_set_pgrp(&tty, 4242);
    tty.receive_from_driver(b"\x03");

    let sigs = sig.sigs();
    assert_eq!(sigs.len(), 1, "exactly one signal");
    assert_eq!(sigs[0], (4242, Sig::Int), "SIGINT to fg pgrp");
}

/// Ctrl-D at line start → read() returns 0 (EOF), and nothing renders.
#[test]
fn vt_ctrl_d_at_line_start_is_eof() {
    let (tty, _consw, _sig) = build_vt(20, 3);
    tty.receive_from_driver(b"\x04");

    let mut buf = [0u8; 32];
    let got = tty.read(&mut buf);
    assert_eq!(got, 0, "^D at line start → 0-length read (EOF)");
    assert_eq!(vt_row(&tty, 0).trim_end(), "", "EOF renders nothing");
}

/// Prompt write then typed line share the active VT (program + user on
/// the same screen row, same read stream).
#[test]
fn vt_prompt_then_input_share_active_vc() {
    let (tty, _consw, _sig) = build_vt(20, 4);
    tty.write(b"$ ");
    tty.receive_from_driver(b"echo hi\n");

    let mut buf = [0u8; 32];
    let got = tty.read(&mut buf);
    assert_eq!(&buf[..got], b"echo hi\n");
    assert!(vt_row(&tty, 0).starts_with("$ echo hi"), "row0 = {:?}", vt_row(&tty, 0));
}
