//! The run one edit control issues for a whole typed line.
//!
//! The control repaints its line as one paired-delta run whose glyph units
//! are characters: the script cache reports no sfnt face, so no glyph-index
//! flag is set, and the advances arrive interleaved with a zero vertical
//! delta per unit. A run of one unit and a run of thirteen take the same
//! path, so both are driven against the real face and every character cell
//! is required to carry ink.
use super::render::{self, Sink};
use syscall::nt_native_gdi as abi;
use windows_gdi::{RasterFont, RasterSurface, Rect};

/// Surface the control's client area occupies in the fixture.
const WIDTH: i32 = 400;
/// Height of that surface.
const HEIGHT: i32 = 40;
/// Point size the control's font is rasterized at.
const SIZE: f32 = 16.0;
/// Face the composed image substitutes for the control's fixed-pitch font.
const FACE: &str = "/usr/share/fonts/liberation-mono-fonts/LiberationMono-Regular.ttf";
/// Colour the control's text carries.
const INK: u32 = 0x0000_0000;
/// Colour the control's background carries.
const PAPER: u32 = 0x00ff_ffff;
/// Flags the reference script layer sets for a face with no glyph indices.
const RUN_FLAGS: u32 = abi::IGNORE_LANGUAGE | abi::PDY;

struct Surface { owner: ipc::win32_gdi::GdiManager, uploads: usize }
impl Sink for Surface {
    fn fill(&mut self, dc: u64, rect: Rect, color: u32) -> Result<(), ()> {
        self.owner.fill_rect(dc as u32, ipc::win32_gdi::Rect { left: rect.left, top: rect.top, right: rect.right, bottom: rect.bottom }, color).map_err(|_| ())
    }
    fn upload(&mut self, dc: u64, x: i32, y: i32, raster: &RasterSurface, clip: Option<Rect>, alpha: bool) -> Result<(), ()> {
        self.uploads += 1;
        if alpha {
            let Some((x, y, tile)) = render::alpha_tile(x, y, raster, clip)? else { return Ok(()); };
            return self.owner.blend_pixels(dc as u32, x, y, tile.width, tile.height, &tile.pixels).map_err(|_| ());
        }
        self.owner.blit_pixels(dc as u32, x, y, raster.width as i32, raster.height as i32,
            raster.width as i32, &raster.pixels).map_err(|_| ())
    }
}

fn request(dc: u32, count: u32, advances: u64) -> abi::TextRequest {
    abi::TextRequest { version: abi::VERSION, size: core::mem::size_of::<abi::TextRequest>() as u32,
        dc: dc as u64, x: 4, y: 1, flags: RUN_FLAGS, count, text: 1, advances,
        rect: [0, 0, 0, 0], height: SIZE as i32, width: 0, weight: 400, italic: 0,
        foreground: INK, background: PAPER, has_rect: 0, reserved: 0,
        background_mode: abi::BACKGROUND_OPAQUE, alignment: 0, current_x: 0, current_y: 0,
        break_extra: 0, break_rem: 0 }
}

/// Paired deltas the reference script layer builds: one advance per unit and
/// a zero vertical delta beside it.
fn paired(font: &RasterFont, text: &[u16]) -> Vec<i32> {
    let measured = font.measure_utf16(text, i32::MAX).unwrap();
    let mut previous = 0;
    let mut out = Vec::new();
    for position in measured.cumulative.iter() { out.push(position - previous); out.push(0); previous = *position; }
    out
}

fn run(text: &str) -> (Surface, u32, Vec<i32>, Vec<u16>) {
    let bytes = std::fs::read(FACE).unwrap();
    let font = RasterFont::from_bytes(&bytes, SIZE).unwrap();
    let mut sink = Surface { owner: ipc::win32_gdi::GdiManager::new(), uploads: 0 };
    let dc = sink.owner.create_dc(WIDTH, HEIGHT).unwrap();
    sink.fill(dc as u64, Rect { left: 0, top: 0, right: WIDTH, bottom: HEIGHT }, PAPER).unwrap();
    let units: Vec<u16> = text.encode_utf16().collect();
    let advances = paired(&font, &units);
    let request = request(dc, units.len() as u32, advances.as_ptr() as u64);
    render::draw(&font, &request, &units, Some(&advances), &mut sink).unwrap();
    (sink, dc, advances, units)
}

fn ink_columns(sink: &Surface, dc: u32) -> Vec<i32> {
    let (_, _, pixels) = sink.owner.surface(dc).unwrap();
    (0..WIDTH).filter(|x| (0..HEIGHT).any(|y| pixels[y as usize * WIDTH as usize + *x as usize] != PAPER)).collect()
}

#[test]
fn a_single_character_run_inks_the_first_cell() {
    let (sink, dc, _, _) = run("o");
    let columns = ink_columns(&sink, dc);
    assert!(!columns.is_empty(), "one-unit run left no ink");
    assert!(columns.iter().all(|x| *x < 4 + 12), "one-unit run inked beyond its own cell: {columns:?}");
    assert_eq!(sink.uploads, 1);
}

#[test]
fn every_cell_of_a_thirteen_character_run_is_inked() {
    let token = "oxide-2994177";
    let (sink, dc, advances, _) = run(token);
    let columns = ink_columns(&sink, dc);
    assert!(!columns.is_empty(), "thirteen-unit run left no ink");
    let mut origin = 4;
    for (index, unit) in token.chars().enumerate() {
        let advance = advances[index * 2];
        assert!(advance > 0, "unit {index} carries no advance");
        let cell = origin..origin + advance;
        assert!(columns.iter().any(|x| cell.contains(x)),
            "character {index} ({unit}) left its cell {cell:?} blank; inked columns {columns:?}");
        origin += advance;
    }
    assert!(*columns.last().unwrap() >= 4 + advances.iter().step_by(2).take(12).sum::<i32>(),
        "the run stops short of its last cell");
    assert_eq!(sink.uploads, 1);
}
