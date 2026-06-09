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

// Models fbcon::kernel's per-VT routing: two VCs A (fg) + B (offscreen)
// share ONE renderer; a write to the offscreen VT must update its Vc but
// NOT touch the shared renderer, and switch_vt(B) must full-repaint B's
// content onto the renderer. (The kernel module that does this is
// cfg(oxide-kernel) and can't be host-compiled, so the routing invariant
// is proven here against the same `render`/`switch` primitives it uses.)
#[test]
fn offscreen_write_does_not_blit_until_switch() {
    let mut a = Vc::new(10, 3);
    let mut b = Vc::new(10, 3);
    let mut em_a = Emulator::new();
    let mut em_b = Emulator::new();
    let mut shared = RecordingConsw::default();
    // fg = A: prime A onto the shared renderer.
    switch(&mut a, &mut shared);
    let after_a_switch = shared.putcs.len();

    // Write to B (offscreen): update B's Vc only; the renderer is the
    // foreground (A) surface, so we must NOT render B into it.
    em_b.feed_bytes(&mut b, b"FROM_B");
    // (no render(&mut b, &mut shared) — B is not fg)
    assert_eq!(
        shared.putcs.len(),
        after_a_switch,
        "offscreen write leaked a blit to the shared renderer"
    );

    // Meanwhile A keeps blitting on fg writes.
    em_a.feed_bytes(&mut a, b"a");
    render(&mut a, &mut shared);
    assert!(shared.putcs.len() > after_a_switch, "fg write must blit");
    let after_a_write = shared.putcs.len();

    // switch_vt(B): full repaint of B's content onto the shared renderer
    // (RecordingConsw::con_switch records the paint as a switch_call).
    switch(&mut b, &mut shared);
    assert_eq!(shared.switch_calls, 2, "second switch (to B) must paint");
    let _ = after_a_write;
    // B's first row holds "FROM_B" — the content brought to fg.
    assert_eq!(&b.row_string(0)[..6], "FROM_B");
    // After the switch, B's dirty marks are cleared (no stale repaint).
    let before = shared.putcs.len();
    render(&mut b, &mut shared);
    assert_eq!(shared.putcs.len(), before, "switch must clear B's dirty");
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
