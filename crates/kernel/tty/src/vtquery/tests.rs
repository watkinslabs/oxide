// Hosted tests for the pure output-side terminal query responder.
// Drives `TermState::step` byte-by-byte against a capture buffer that
// stands in for the VT input ring — the verify-left gate before QEMU.

use super::{TermState, ROWS, COLS};
extern crate alloc;
use alloc::vec::Vec;

/// Feed every byte of `input` through `st`, collecting all reply bytes
/// (as a real responder would inject into the input ring).
fn feed(st: &mut TermState, input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for &b in input {
        if let Some(r) = st.step(b) {
            out.extend_from_slice(r.as_bytes());
        }
    }
    out
}

const ESC: u8 = 0x1b;

#[test]
fn dsr_cpr_from_home() {
    let mut st = TermState::new();
    let reply = feed(&mut st, &[ESC, b'[', b'6', b'n']);
    assert_eq!(reply, b"\x1b[1;1R");
}

#[test]
fn dsr_cpr_after_printing() {
    let mut st = TermState::new();
    let reply = feed(&mut st, b"hello\x1b[6n");
    // 5 printable chars from col 1 → col 6.
    assert_eq!(reply, b"\x1b[1;6R");
    assert_eq!(st.cursor_row, 1);
    assert_eq!(st.cursor_col, 6);
}

#[test]
fn size_probe_clamps() {
    // crossterm size probe: move to 999;999 (clamps to 24;80), then DSR.
    let mut st = TermState::new();
    let reply = feed(&mut st, b"\x1b[999;999H\x1b[6n");
    assert_eq!(reply, b"\x1b[24;80R");
    assert_eq!(st.cursor_row, ROWS);
    assert_eq!(st.cursor_col, COLS);
}

#[test]
fn newline_advances_row() {
    let mut st = TermState::new();
    let reply = feed(&mut st, b"\n\n\x1b[6n");
    assert_eq!(reply, b"\x1b[3;1R");
}

#[test]
fn carriage_return_resets_col() {
    let mut st = TermState::new();
    let reply = feed(&mut st, b"abc\r\x1b[6n");
    assert_eq!(reply, b"\x1b[1;1R");
}

#[test]
fn backspace_decrements_col() {
    let mut st = TermState::new();
    let reply = feed(&mut st, b"abc\x08\x08\x1b[6n");
    // col: 1→4 after "abc", then two BS → 2.
    assert_eq!(reply, b"\x1b[1;2R");
}

#[test]
fn da1_reply() {
    let mut st = TermState::new();
    assert_eq!(feed(&mut st, &[ESC, b'[', b'c']), b"\x1b[?1;2c");
    let mut st2 = TermState::new();
    assert_eq!(feed(&mut st2, b"\x1b[0c"), b"\x1b[?1;2c");
}

#[test]
fn dsr_ok_reply() {
    let mut st = TermState::new();
    assert_eq!(feed(&mut st, &[ESC, b'[', b'5', b'n']), b"\x1b[0n");
}

#[test]
fn escape_split_across_calls() {
    // State persists across process_output calls: ESC[6 then n still replies.
    let mut st = TermState::new();
    let _ = feed(&mut st, b"hello");
    assert!(feed(&mut st, b"\x1b[6").is_empty());
    assert_eq!(feed(&mut st, b"n"), b"\x1b[1;6R");
}

#[test]
fn private_dsr_no_reply() {
    // ESC[?6n (DECRQM-ish private) must NOT produce a CPR.
    let mut st = TermState::new();
    assert!(feed(&mut st, b"\x1b[?6n").is_empty());
}

#[test]
fn cursor_movement_csi() {
    let mut st = TermState::new();
    // home then down 5, right 10.
    let _ = feed(&mut st, b"\x1b[H\x1b[5B\x1b[10C");
    assert_eq!(st.cursor_row, 6);
    assert_eq!(st.cursor_col, 11);
    let reply = feed(&mut st, b"\x1b[6n");
    assert_eq!(reply, b"\x1b[6;11R");
}

#[test]
fn cursor_up_left_clamp() {
    let mut st = TermState::new();
    // From home, up/left clamp at 1.
    let _ = feed(&mut st, b"\x1b[9A\x1b[9D");
    assert_eq!(st.cursor_row, 1);
    assert_eq!(st.cursor_col, 1);
}

#[test]
fn line_wrap_advances_row() {
    let mut st = TermState::new();
    // Print 80 chars: col fills to 80; the 81st wraps to row 2 col 1.
    let line = [b'x'; 81];
    let _ = feed(&mut st, &line);
    let reply = feed(&mut st, b"\x1b[6n");
    assert_eq!(reply, b"\x1b[2;2R");
}

#[test]
fn ignored_csi_finals_no_reply() {
    let mut st = TermState::new();
    // SGR color, erase, scroll-region — consumed, no reply, cursor intact.
    let r = feed(&mut st, b"\x1b[2J\x1b[0m\x1b[1;24r\x1b[?25h");
    assert!(r.is_empty());
    assert_eq!(st.cursor_row, 1);
    assert_eq!(st.cursor_col, 1);
}

#[test]
fn semicolon_omitted_row_defaults() {
    // ESC[;5H → row defaults to 1, col 5.
    let mut st = TermState::new();
    let _ = feed(&mut st, b"\x1b[;5H");
    assert_eq!(st.cursor_row, 1);
    assert_eq!(st.cursor_col, 5);
}

#[test]
fn osc11_bg_query_bel_terminated() {
    let mut st = TermState::new();
    // ESC]11;? BEL  → background-color query, BEL-terminated
    let reply = feed(&mut st, &[ESC, b']', b'1', b'1', b';', b'?', 0x07]);
    assert_eq!(reply, b"\x1b]11;rgb:0000/0000/0000\x1b\\");
}

#[test]
fn osc11_bg_query_st_terminated() {
    let mut st = TermState::new();
    // ESC]11;? ESC\  → ST-terminated form
    let reply = feed(&mut st, &[ESC, b']', b'1', b'1', b';', b'?', ESC, b'\\']);
    assert_eq!(reply, b"\x1b]11;rgb:0000/0000/0000\x1b\\");
}

#[test]
fn osc10_fg_query() {
    let mut st = TermState::new();
    let reply = feed(&mut st, &[ESC, b']', b'1', b'0', b';', b'?', 0x07]);
    assert_eq!(reply, b"\x1b]10;rgb:ffff/ffff/ffff\x1b\\");
}

#[test]
fn osc_title_set_no_reply() {
    let mut st = TermState::new();
    // ESC]0;sometitle BEL  → window-title set, not a query → no reply
    let reply = feed(&mut st, b"\x1b]0;mytitle\x07");
    assert!(reply.is_empty());
}

#[test]
fn osc_then_cursor_query_both_answered() {
    let mut st = TermState::new();
    // bg query (OSC) followed by CPR (CSI) — both must be answered
    let reply = feed(&mut st, &[ESC, b']', b'1', b'1', b';', b'?', 0x07, ESC, b'[', b'6', b'n']);
    assert_eq!(reply, b"\x1b]11;rgb:0000/0000/0000\x1b\\\x1b[1;1R");
    assert_eq!((st.cursor_row, st.cursor_col), (1, 1));
}

#[test]
fn osc_query_then_dsr_no_osc_terminator() {
    // termenv pattern: bg query immediately followed by DSR as the
    // fail-fast terminator, with NO BEL/ST on the OSC:  ESC]11;? ESC[6n
    // Both must be answered (OSC reply, then CPR).
    let mut st = TermState::new();
    let reply = feed(&mut st, &[ESC, b']', b'1', b'1', b';', b'?', ESC, b'[', b'6', b'n']);
    assert_eq!(reply, b"\x1b]11;rgb:0000/0000/0000\x1b\\\x1b[1;1R");
}
