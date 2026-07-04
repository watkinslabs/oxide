use crate::emulator::Emulator;
use crate::palette::{rgb, xterm_256_rgb};
use crate::vc::{Attr, Vc, DEFAULT_BG, DEFAULT_BG_RGB, DEFAULT_FG, DEFAULT_FG_RGB};

use super::run;

#[test]
fn sgr_sets_color_attr() {
    let vc = run(20, 2, b"\x1b[31mA\x1b[0mB");
    let a = vc.attr_at(0, 0).unwrap();
    assert_eq!(a.fg, xterm_256_rgb(1));
    let b = vc.attr_at(1, 0).unwrap();
    assert_eq!(b.fg, DEFAULT_FG_RGB);
}

#[test]
fn sgr_bright_and_bg() {
    let mut vc = Vc::new(20, 2);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[91;42mX");
    let a = vc.attr_at(0, 0).unwrap();
    assert_eq!(a.fg, xterm_256_rgb(9));
    assert_eq!(a.bg, xterm_256_rgb(2));
    em.feed_bytes(&mut vc, b"\x1b[1mY");
    assert!(vc.attr.bold);
}

#[test]
fn sgr_256_color() {
    let mut vc = Vc::new(20, 2);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[38;5;200mZ");
    assert_eq!(vc.attr_at(0, 0).unwrap().fg, xterm_256_rgb(200));
}

#[test]
fn sgr_truecolor_stored_verbatim() {
    let mut vc = Vc::new(20, 2);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[38;2;12;34;56;48;2;200;100;50mT");
    let a = vc.attr_at(0, 0).unwrap();
    assert_eq!(a.fg, rgb([12, 34, 56]));
    assert_eq!(a.bg, rgb([200, 100, 50]));
}

#[test]
fn sgr_bold_brightens_basic_color_at_resolve() {
    let vc = run(20, 2, b"\x1b[1;31mA");
    let a = vc.attr_at(0, 0).unwrap();
    assert!(a.bold);
    assert_eq!(a.fg, xterm_256_rgb(9));
    let vc2 = run(20, 2, b"\x1b[1;38;2;5;6;7mB");
    assert_eq!(vc2.attr_at(0, 0).unwrap().fg, rgb([5, 6, 7]));
}

#[test]
fn decsc_decrc_save_restore() {
    let vc = run(20, 5, b"\x1b[3;5H\x1b7\x1b[1;1H\x1b8*");
    assert_eq!(vc.glyph_at(4, 2), '*' as u32);
}

#[test]
fn csi_s_u_save_restore() {
    let vc = run(20, 5, b"\x1b[3;5H\x1b[s\x1b[1;1H\x1b[u*");
    assert_eq!(vc.glyph_at(4, 2), '*' as u32);
}

#[test]
fn decsc_restores_attr() {
    let mut vc = Vc::new(20, 2);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[31m\x1b7\x1b[0m\x1b8X");
    assert_eq!(vc.attr_at(0, 0).unwrap().fg, xterm_256_rgb(1));
    let _ = DEFAULT_BG;
}

#[test]
fn per_cell_flags_survive_bold_underline_reverse() {
    let vc = run(20, 2, b"\x1b[1;4;7;33;44mA\x1b[0mB");
    let a = vc.attr_at(0, 0).unwrap();
    assert!(a.bold);
    assert!(a.underline);
    assert!(a.reverse);
    assert_eq!(a.fg, xterm_256_rgb(11));
    assert_eq!(a.bg, xterm_256_rgb(4));
    let b = vc.attr_at(1, 0).unwrap();
    assert!(!b.bold && !b.underline && !b.reverse);
    assert_eq!(b.fg, DEFAULT_FG_RGB);
    assert_eq!(b.bg, DEFAULT_BG_RGB);
}

#[test]
fn per_cell_flags_toggle_off_midline() {
    let vc = run(20, 2, b"\x1b[4mX\x1b[24mY");
    let x = vc.attr_at(0, 0).unwrap();
    let y = vc.attr_at(1, 0).unwrap();
    assert!(x.underline && !x.reverse);
    assert!(!y.underline && !y.reverse);
}

#[test]
fn dsr_device_status_replies_ok() {
    let mut vc = Vc::new(80, 24);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[5n");
    let r = em.take_reply();
    assert_eq!(r.as_slice(), b"\x1b[0n");
    assert!(em.take_reply().is_empty());
}

#[test]
fn cpr_cursor_position_report_is_one_based() {
    let mut vc = Vc::new(80, 24);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[10;20H");
    assert_eq!((vc.y, vc.x), (9, 19));
    em.feed_bytes(&mut vc, b"\x1b[6n");
    let r = em.take_reply();
    assert_eq!(r.as_slice(), b"\x1b[10;20R");
}

#[test]
fn cpr_after_clamp_reports_real_geometry() {
    let mut vc = Vc::new(80, 24);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[999;999H\x1b[6n");
    let r = em.take_reply();
    assert_eq!(r.as_slice(), b"\x1b[24;80R");
}

#[test]
fn private_dsr_produces_no_reply() {
    let mut vc = Vc::new(80, 24);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[?6n");
    assert!(em.take_reply().is_empty());
}

#[test]
fn sgr0_resets_to_defaults() {
    let vc = run(20, 2, b"\x1b[1;4;7;31;44mA\x1b[0mB");
    let b = vc.attr_at(1, 0).unwrap();
    assert_eq!(b.fg, DEFAULT_FG_RGB);
    assert_eq!(b.bg, crate::vc::DEFAULT_BG_RGB);
    assert!(!b.bold && !b.underline && !b.reverse);
}
