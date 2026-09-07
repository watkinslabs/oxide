//! GetGlyphOutline: glyph metrics, the two bitmap families and the two
//! polygon families, from the same realization the renderer draws with.
use super::{outline_data, put, put16};
use syscall::nt_native_gdi as abi;
use windows_gdi::RasterFont;

const GGO_METRICS: u32 = 0;
const GGO_BITMAP: u32 = 1;
const GGO_NATIVE: u32 = 2;
const GGO_BEZIER: u32 = 3;
const GGO_GRAY2_BITMAP: u32 = 4;
const GGO_GRAY4_BITMAP: u32 = 5;
const GGO_GRAY8_BITMAP: u32 = 6;
const GGO_GLYPH_INDEX: u32 = 0x80;
const GGO_UNHINTED: u32 = 0x100;
/// Coverage at or above half opacity sets a bit in the monochrome form.
const MONO_THRESHOLD: u8 = 128;
const MONO_ALIGNMENT: usize = 32;
const GRAY_ALIGNMENT: usize = 4;
const COVERAGE_LEVELS: u32 = 256;
/// The identity transform, as the eight words of a 2-by-2 fixed-point matrix.
const IDENTITY: [u16; 8] = [0, 1, 0, 0, 0, 0, 0, 1];

fn max_level(format: u32) -> u32 {
    match format { GGO_GRAY2_BITMAP => 4, GGO_GRAY4_BITMAP => 16, GGO_GRAY8_BITMAP => 64, _ => 255 }
}

/// Glyph metrics in the Windows record order. # C: O(1)
fn metrics(raster: &windows_gdi::GlyphRaster) -> Vec<u8> {
    let mut bytes = vec![0u8; abi::GLYPH_METRICS_BYTES as usize];
    put(&mut bytes, 0, raster.width.max(1) as i32);
    put(&mut bytes, 4, raster.height.max(1) as i32);
    put(&mut bytes, 8, raster.left);
    put(&mut bytes, 12, raster.bottom + raster.height as i32);
    put16(&mut bytes, 16, raster.advance as i16 as u16);
    bytes
}

fn mono(raster: &windows_gdi::GlyphRaster) -> (usize, Vec<u8>) {
    let pitch = (raster.width + MONO_ALIGNMENT - 1) / MONO_ALIGNMENT * (MONO_ALIGNMENT / 8);
    let mut bits = vec![0u8; pitch * raster.height];
    for row in 0..raster.height {
        for column in 0..raster.width {
            if raster.coverage[row * raster.width + column] >= MONO_THRESHOLD {
                bits[row * pitch + column / 8] |= 0x80 >> (column % 8);
            }
        }
    }
    (pitch * raster.height, bits)
}

fn gray(raster: &windows_gdi::GlyphRaster, format: u32) -> (usize, Vec<u8>) {
    let pitch = (raster.width + GRAY_ALIGNMENT - 1) / GRAY_ALIGNMENT * GRAY_ALIGNMENT;
    let level = max_level(format);
    let mut bytes = vec![0u8; pitch * raster.height];
    for row in 0..raster.height {
        for column in 0..raster.width {
            let coverage = u32::from(raster.coverage[row * raster.width + column]);
            bytes[row * pitch + column] = (coverage * (level + 1) / COVERAGE_LEVELS) as u8;
        }
    }
    (pitch * raster.height, bytes)
}

/// Answer one glyph-outline request; the caller's transform must be the
/// identity because this realization rasterizes no transformed outline.
/// # C: O(glyph pixels or glyph points)
pub(super) fn execute(font: &RasterFont, bytes: &[u8], request: &abi::QueryRequest, input: &[u16]) -> Option<(u32, Vec<u8>)> {
    if input.len() != abi::MAT2_WORDS as usize { return None; }
    let identity = input == IDENTITY;
    let format = request.flags & !GGO_UNHINTED;
    let glyph = if format & GGO_GLYPH_INDEX != 0 { u16::try_from(request.first).ok()? }
        else { font.glyph_for(request.first) };
    let format = format & !GGO_GLYPH_INDEX;
    let raster = font.glyph_raster(glyph).ok()?;
    let mut data = if request.aux == 0 { Vec::new() } else { metrics(&raster) };
    if format == GGO_METRICS { return Some((1, data)); }
    if !identity { return None; }
    let (needed, produced) = match format {
        GGO_BITMAP => mono(&raster),
        GGO_GRAY2_BITMAP | GGO_GRAY4_BITMAP | GGO_GRAY8_BITMAP => gray(&raster, format),
        GGO_NATIVE | GGO_BEZIER => {
            let outline = outline_data::outline(bytes, glyph, font.design_units_per_em(), font.pixel_size())?;
            let polygons = if format == GGO_NATIVE { outline_data::native(&outline) } else { outline_data::bezier(&outline) };
            (polygons.len(), polygons)
        }
        _ => return None,
    };
    let needed = u32::try_from(needed).ok()?;
    if request.output == 0 || request.capacity == 0 { return Some((needed, data)); }
    // An empty glyph and a buffer that cannot hold the form are both refusals.
    if needed == 0 || needed > request.capacity { return None; }
    data.extend_from_slice(&produced);
    Some((needed, data))
}
