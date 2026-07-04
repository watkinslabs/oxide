use crate::*;

#[test]
fn psf2_header_layout() {
    assert_eq!(core::mem::size_of::<font::Psf2Header>(), 32);
}

#[test]
fn step_emits_putchar_for_ascii() {
    let mut s = ParserState::default();
    assert_eq!(step(&mut s, b'A'), Action::PutChar('A' as u32));
}

#[test]
fn step_csi_cup_decodes_pos() {
    let mut s = ParserState::default();
    for &b in b"\x1b[10;20H" {
        step(&mut s, b);
    }
    let mut s2 = ParserState::default();
    let mut last = Action::None;
    for &b in b"\x1b[10;20H" {
        last = step(&mut s2, b);
    }
    assert_eq!(last, Action::CursorPosition(10, 20));
}

#[test]
fn step_csi_sgr_collects_params() {
    let mut s = ParserState::default();
    let mut last = Action::None;
    for &b in b"\x1b[1;31;47m" {
        last = step(&mut s, b);
    }
    if let Action::SetGraphicRendition(p, n) = last {
        assert_eq!(n, 3);
        assert_eq!(&p[..3], &[1, 31, 47]);
    } else {
        panic!("expected SetGraphicRendition");
    }
}

#[test]
fn step_decset_25_show_cursor() {
    let mut s = ParserState::default();
    let mut last = Action::None;
    for &b in b"\x1b[?25h" {
        last = step(&mut s, b);
    }
    assert_eq!(last, Action::SetMode(25, true));
}

#[test]
fn step_utf8_decode_two_byte() {
    let mut s = ParserState::default();
    step(&mut s, 0xc3);
    let act = step(&mut s, 0xa9);
    assert_eq!(act, Action::PutChar(0xe9));
}

#[test]
fn xterm_256_cube_mid() {
    assert_eq!(xterm_256(124), [175, 0, 0]);
}

#[test]
fn xterm_256_grayscale() {
    assert_eq!(xterm_256(232), [8, 8, 8]);
}

#[test]
fn vga_palette_size() {
    assert_eq!(VGA_PALETTE.len(), 16);
}

#[test]
fn console_new_dims() {
    let c = Console::new(640, 480);
    assert_eq!(c.cols, 80);
    assert_eq!(c.rows, 30);
    assert_eq!(c.fb.len(), 640 * 480 * 4);
}

#[test]
fn put_advances_cursor() {
    let mut c = Console::new(640, 480);
    c.put(b"abc");
    assert_eq!((c.cur_col, c.cur_row), (3, 0));
}

#[test]
fn newline_advances_row_only() {
    let mut c = Console::new(640, 480);
    c.put(b"abc\nx");
    assert_eq!(c.cur_col, 4);
    assert_eq!(c.cur_row, 1);
}

#[test]
fn carriage_return_resets_column() {
    let mut c = Console::new(640, 480);
    c.put(b"abc\rx");
    assert_eq!((c.cur_col, c.cur_row), (1, 0));
}

#[test]
fn ansi_csi_h_positions_cursor() {
    let mut c = Console::new(640, 480);
    c.put(b"\x1b[10;20H");
    assert_eq!((c.cur_row, c.cur_col), (9, 19));
}

#[test]
fn sgr_red_changes_fg() {
    let mut c = Console::new(640, 480);
    c.put(b"\x1b[31m");
    assert_eq!(c.fg, VGA_PALETTE[1]);
}
