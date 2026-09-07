//! One control's typed characters from damage to presented pixels.
//!
//! The application draws its whole line every paint; the coverage the paint
//! admitted is what decides which of those pixels survive. A control whose
//! first character appears and whose later characters never do is this chain
//! answering differently for damage at the client origin and damage that
//! starts part-way along the line, so both are driven here.

use ipc::win32_gdi::{GdiManager, PaintBacking, Rect};
use ipc::win32_window::{PaintRegion, WindowManager, WindowRect};

/// Client width of the control under test, wide enough for a token line.
const CLIENT_WIDTH: i32 = 120;
/// Client height of the control under test.
const CLIENT_HEIGHT: i32 = 20;
/// Line height one character cell occupies.
const LINE_HEIGHT: i32 = 13;
/// Advance one character cell occupies.
const CELL: i32 = 7;
/// Colour the control draws its glyph run in.
const INK: u32 = 0x0000_00;
/// Colour the control's background carries.
const PAPER: u32 = 0x00ff_ffff;
/// Owning thread of every window in the fixture.
const TID: u64 = 7;

struct Fixture { windows: WindowManager, gdi: GdiManager, child: u32, backing: u32 }

fn rect(left: i32, top: i32, right: i32, bottom: i32) -> WindowRect { WindowRect { left, top, right, bottom } }

fn layout() -> PaintBacking {
    PaintBacking { width: CLIENT_WIDTH, height: CLIENT_HEIGHT,
        client: Rect { left: 0, top: 0, right: CLIENT_WIDTH, bottom: CLIENT_HEIGHT } }
}

fn fixture() -> Fixture {
    let mut windows = WindowManager::new();
    let parent = windows.create(TID, None, 0).unwrap();
    windows.set_rect(parent, rect(10, 10, 10 + CLIENT_WIDTH, 10 + CLIENT_HEIGHT + 30)).unwrap();
    windows.set_visible(parent, true).unwrap();
    let child = windows.create(TID, Some(parent), 0).unwrap();
    windows.set_rect(child, rect(0, 30, CLIENT_WIDTH, 30 + CLIENT_HEIGHT)).unwrap();
    windows.set_visible(child, true).unwrap();
    let mut gdi = GdiManager::new();
    let backing = gdi.acquire_window_dc(child.raw(), CLIENT_WIDTH, CLIENT_HEIGHT).unwrap();
    gdi.fill_rect(backing, Rect { left: 0, top: 0, right: CLIENT_WIDTH, bottom: CLIENT_HEIGHT }, PAPER).unwrap();
    Fixture { windows, gdi, child: child.raw(), backing }
}

/// One paint of the control: it is invalidated over `damage`, the paint takes
/// its coverage, and the control draws every cell of `text` from the client
/// origin regardless of what was damaged, exactly as the reference control
/// repaints a whole line. Returns the coverage the paint admitted.
fn paint(f: &mut Fixture, damage: WindowRect, cells: i32) -> PaintRegion {
    let id = ipc::win32_window::WindowId::from_raw(f.child).unwrap();
    f.windows.invalidate(id, Some(damage)).unwrap();
    f.windows.begin_paint(id).unwrap();
    let region = f.windows.paint_region(id).unwrap();
    let paint_dc = f.gdi.create_dc(CLIENT_WIDTH, CLIENT_HEIGHT).unwrap();
    f.gdi.seed_paint(f.child, paint_dc, layout()).unwrap();
    f.windows.bind_paint_dc(id, paint_dc).unwrap();
    f.gdi.set_paint_region(paint_dc, region.try_copy().unwrap()).unwrap();
    // The whole line, cell by cell, from the client origin.
    for cell in 0..cells {
        f.gdi.fill_rect(paint_dc, Rect { left: cell * CELL, top: 0, right: cell * CELL + CELL - 1, bottom: LINE_HEIGHT }, INK).unwrap();
    }
    if !region.is_empty() {
        assert_eq!(f.gdi.retain_paint_region(f.child, paint_dc, &region, layout()), Ok(f.backing));
    }
    f.windows.end_paint_session(id, paint_dc).unwrap();
    f.gdi.delete_object(paint_dc).unwrap();
    region
}

fn inked(f: &Fixture, cell: i32) -> bool {
    let pixels = f.gdi.pixels(f.backing).unwrap();
    pixels[(LINE_HEIGHT / 2) as usize * CLIENT_WIDTH as usize + (cell * CELL) as usize] == INK
}

#[test]
fn damage_away_from_the_client_origin_still_presents_the_cells_it_covers() {
    let mut f = fixture();
    // First character: damage at the client origin, one cell wide.
    let first = paint(&mut f, rect(0, 0, CELL, LINE_HEIGHT), 1);
    assert_eq!(first.bounds(), Some(rect(0, 0, CELL, LINE_HEIGHT)));
    assert!(inked(&f, 0));
    // Twelve more characters: the damage begins one cell in and reaches the
    // end of the line, which is what the control invalidates for an insert.
    let rest = paint(&mut f, rect(CELL, 0, 13 * CELL, LINE_HEIGHT), 13);
    assert_eq!(rest.bounds(), Some(rect(CELL, 0, 13 * CELL, LINE_HEIGHT)));
    for cell in 0..13 { assert!(inked(&f, cell), "cell {cell} never reached the window backing"); }
}

#[test]
fn coverage_outside_the_admitted_damage_is_not_presented() {
    let mut f = fixture();
    paint(&mut f, rect(0, 0, CELL, LINE_HEIGHT), 13);
    assert!(inked(&f, 0));
    for cell in 1..13 { assert!(!inked(&f, cell), "cell {cell} escaped the admitted coverage"); }
}

#[test]
fn twelve_separate_invalidations_paint_as_one_admitted_coverage() {
    let mut f = fixture();
    let id = ipc::win32_window::WindowId::from_raw(f.child).unwrap();
    for cell in 1..13 { f.windows.invalidate(id, Some(rect(cell * CELL, 0, 13 * CELL, LINE_HEIGHT))).unwrap(); }
    f.windows.begin_paint(id).unwrap();
    let region = f.windows.paint_region(id).unwrap();
    assert_eq!(region.bounds(), Some(rect(CELL, 0, 13 * CELL, LINE_HEIGHT)));
    let paint_dc = f.gdi.create_dc(CLIENT_WIDTH, CLIENT_HEIGHT).unwrap();
    f.gdi.seed_paint(f.child, paint_dc, layout()).unwrap();
    f.windows.bind_paint_dc(id, paint_dc).unwrap();
    f.gdi.set_paint_region(paint_dc, region.try_copy().unwrap()).unwrap();
    for cell in 0..13 {
        f.gdi.fill_rect(paint_dc, Rect { left: cell * CELL, top: 0, right: cell * CELL + CELL - 1, bottom: LINE_HEIGHT }, INK).unwrap();
    }
    assert_eq!(f.gdi.retain_paint_region(f.child, paint_dc, &region, layout()), Ok(f.backing));
    for cell in 1..13 { assert!(inked(&f, cell), "cell {cell} never reached the window backing"); }
    assert!(!inked(&f, 0));
}
