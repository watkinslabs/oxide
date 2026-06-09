// Mock-consw drive tests: feed a byte stream through `Emulator` into a
// `Vc`, run `render`, and assert the `Consw` received the expected
// putcs/cursor/scroll/switch calls for the dirtied regions.

use crate::consw::{render, switch, Consw, ScrollDir};
use crate::emulator::Emulator;
use crate::vc::Vc;
use alloc::vec::Vec;

/// Records every op call for assertion.
#[derive(Default)]
struct RecordingConsw {
    init: Vec<(u32, u32)>,
    clear: Vec<(u32, u32, u32, u32)>,
    putcs: Vec<(u32, u32, u32)>,
    cursor: Vec<bool>,
    scroll: Vec<(u32, u32, ScrollDir, u32)>,
    switch_calls: u32,
}

impl Consw for RecordingConsw {
    fn con_init(&mut self, cols: u32, rows: u32) {
        self.init.push((cols, rows));
    }
    fn con_clear(&mut self, _vc: &Vc, x: u32, y: u32, w: u32, h: u32) {
        self.clear.push((x, y, w, h));
    }
    fn con_putcs(&mut self, _vc: &Vc, row: u32, col: u32, n: u32) {
        self.putcs.push((row, col, n));
    }
    fn con_cursor(&mut self, _vc: &Vc, visible: bool) {
        self.cursor.push(visible);
    }
    fn con_scroll(&mut self, _vc: &Vc, top: u32, bot: u32, dir: ScrollDir, n: u32) {
        self.scroll.push((top, bot, dir, n));
    }
    fn con_switch(&mut self, _vc: &Vc) {
        self.switch_calls += 1;
    }
}

// A fresh `Vc` starts all-rows-dirty (initial full paint). `drive`
// clears that initial state with a priming render, then feeds the test
// bytes and renders again — so the recorder only captures the ops the
// input actually dirtied.
fn drive(cols: u16, rows: u16, bytes: &[u8]) -> (Vc, RecordingConsw) {
    let mut vc = Vc::new(cols, rows);
    let mut prime = RecordingConsw::default();
    render(&mut vc, &mut prime); // drain the initial all-dirty paint
    let mut em = Emulator::new();
    let mut cw = RecordingConsw::default();
    em.feed_bytes(&mut vc, bytes);
    render(&mut vc, &mut cw);
    (vc, cw)
}

#[test]
fn initial_render_paints_all_rows() {
    // A fresh Vc is fully dirty: first render must putcs every row.
    let mut vc = Vc::new(20, 4);
    let mut cw = RecordingConsw::default();
    render(&mut vc, &mut cw);
    assert_eq!(cw.putcs.len(), 4);
}

#[test]
fn render_blits_only_dirty_rows() {
    // Print one line on row 0 (no LF). Only row 0 should be putcs'd.
    let (vc, cw) = drive(20, 4, b"hello");
    assert_eq!(cw.putcs, alloc::vec![(0, 0, 20)]);
    // cursor repainted once.
    assert_eq!(cw.cursor, alloc::vec![true]);
    let _ = vc;
}

#[test]
fn render_clears_dirty_after_pass() {
    let mut vc = Vc::new(10, 3);
    let mut em = Emulator::new();
    let mut cw = RecordingConsw::default();
    em.feed_bytes(&mut vc, b"x");
    render(&mut vc, &mut cw);
    let first = cw.putcs.len();
    // Second render with no new input: nothing dirty → no putcs.
    render(&mut vc, &mut cw);
    assert_eq!(cw.putcs.len(), first, "clean render must not re-blit");
}

#[test]
fn multi_row_marks_each_touched_row() {
    // Two CRLF-separated lines dirties rows 0 and 1.
    let (_vc, cw) = drive(10, 4, b"a\r\nb");
    let rows: Vec<u32> = cw.putcs.iter().map(|p| p.0).collect();
    assert!(rows.contains(&0));
    assert!(rows.contains(&1));
}

#[test]
fn scroll_marks_whole_region_dirty() {
    // 3 rows: overflow scrolls → all 3 rows repaint.
    let (_vc, cw) = drive(10, 3, b"r0\r\nr1\r\nr2\r\nr3");
    let rows: Vec<u32> = cw.putcs.iter().map(|p| p.0).collect();
    assert!(rows.contains(&0) && rows.contains(&1) && rows.contains(&2));
}

#[test]
fn switch_repaints_all_rows_via_con_switch() {
    let mut vc = Vc::new(10, 3);
    let mut em = Emulator::new();
    let mut cw = RecordingConsw::default();
    em.feed_bytes(&mut vc, b"hi");
    switch(&mut vc, &mut cw);
    assert_eq!(cw.switch_calls, 1);
    // after switch, dirty cleared → plain render does nothing.
    let before = cw.putcs.len();
    render(&mut vc, &mut cw);
    assert_eq!(cw.putcs.len(), before);
}

#[test]
fn default_con_switch_putcs_every_row() {
    // A renderer that doesn't override con_switch falls back to per-row
    // putcs + a cursor draw.
    #[derive(Default)]
    struct Plain {
        putcs: Vec<(u32, u32, u32)>,
        cursor: u32,
        inited: Vec<(u32, u32)>,
    }
    impl Consw for Plain {
        fn con_init(&mut self, c: u32, r: u32) {
            self.inited.push((c, r));
        }
        fn con_clear(&mut self, _v: &Vc, _x: u32, _y: u32, _w: u32, _h: u32) {}
        fn con_putcs(&mut self, _v: &Vc, row: u32, col: u32, n: u32) {
            self.putcs.push((row, col, n));
        }
        fn con_cursor(&mut self, _v: &Vc, _vis: bool) {
            self.cursor += 1;
        }
    }
    let mut vc = Vc::new(8, 3);
    let mut p = Plain::default();
    p.con_init(8, 3);
    p.con_switch(&vc);
    assert_eq!(p.inited, alloc::vec![(8, 3)]);
    assert_eq!(p.putcs.len(), 3); // one putcs per row
    assert_eq!(p.cursor, 1);
    let _ = &mut vc;
}
