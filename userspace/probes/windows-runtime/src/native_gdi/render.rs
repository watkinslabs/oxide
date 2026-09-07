use syscall::nt_native_gdi as abi;
use windows_gdi::{Gdi, RasterFont, RasterSurface, Rect};

pub(super) trait Sink {
    fn fill(&mut self, dc: u64, rect: Rect, color: u32) -> Result<(), ()>;
    fn upload(&mut self, dc: u64, x: i32, y: i32, raster: &RasterSurface, clip: Option<Rect>, alpha: bool) -> Result<(), ()>;
}

pub(super) struct NativeSink;
impl Sink for NativeSink {
    fn fill(&mut self, dc: u64, rect: Rect, color: u32) -> Result<(), ()> {
        Gdi::new().fill_rect(dc, rect, color).map_err(|_| ())
    }
    fn upload(&mut self, dc: u64, x: i32, y: i32, raster: &RasterSurface, clip: Option<Rect>, alpha: bool) -> Result<(), ()> {
        if alpha { return upload_alpha(dc, x, y, raster, clip); }
        let gdi = Gdi::new();
        match clip {
            Some(clip) => gdi.draw_raster_clipped(dc, x, y, raster, clip),
            None => gdi.draw_raster(dc, x, y, raster),
        }.map_err(|_| ())
    }
}

/// Per-unit advances that reproduce the justified character positions the
/// extent query reports; no justification synthesizes nothing. # C: O(count)
pub(super) fn justified_advances(font: &RasterFont, flags: u32, weight: i32, italic: u32,
    extra: i32, remainder: i32, text: &[u16]) -> Result<Option<Vec<i32>>, ()> {
    if (extra == 0 && remainder == 0) || text.is_empty() { return Ok(None); }
    let metrics = font.text_metrics_w(weight, italic).map_err(|_| ())?;
    let glyph_form = flags & abi::GLYPH_INDEX != 0;
    let measured = if glyph_form { font.measure_glyphs(text, i32::MAX) } else { font.measure_utf16(text, i32::MAX) }.map_err(|_| ())?;
    let mut positions = measured.cumulative;
    super::measure::justify(font, &metrics, text, glyph_form, &mut positions, extra, remainder);
    let mut previous = 0;
    Ok(Some(positions.iter().map(|position| { let delta = position - previous; previous = *position; delta }).collect()))
}

pub(super) fn draw(font: &RasterFont, request: &abi::TextRequest, text: &[u16], advances: Option<&[i32]>, sink: &mut impl Sink) -> Result<(), ()> {
    if !request.valid() || text.len() != request.count as usize
        || advances.is_some_and(|a| a.len() != request.advance_count())
        || (request.advances != 0) != advances.is_some() { return Err(()); }
    let rect = Rect { left: request.rect[0], top: request.rect[1], right: request.rect[2], bottom: request.rect[3] };
    // Justified text without caller advances carries the same per-character
    // positions the extent query reports, turned back into per-unit advances.
    let justified = match advances { Some(_) => None, None => justified_advances(font, request.flags,
        request.weight, request.italic, request.break_extra, request.break_rem, text)? };
    let advances = justified.as_deref().or(advances);
    // Raster admission precedes mutation; malformed text cannot partially fill the DC.
    let raster = if text.is_empty() { None } else {
        Some(font.rasterize_positioned(text, advances, request.flags, request.foreground,
            (request.background_mode != abi::TRANSPARENT).then_some(request.background)).map_err(|_| ())?)
    };
    let raster = match raster {
        Some((x, y, raster)) => Some((request.x.checked_add(x).ok_or(())?, request.y.checked_add(y).ok_or(())?, raster)),
        None => None,
    };
    if request.flags & abi::OPAQUE != 0 { sink.fill(request.dc, rect, request.background)?; }
    if let Some((x, y, raster)) = raster {
        sink.upload(request.dc, x, y, &raster,
            (request.flags & abi::CLIPPED != 0).then_some(rect), request.background_mode == abi::TRANSPARENT)?;
    }
    Ok(())
}

fn upload_alpha(dc: u64, x: i32, y: i32, raster: &RasterSurface, clip: Option<Rect>) -> Result<(), ()> {
    let Some((left, top, raster)) = alpha_tile(x, y, raster, clip)? else { return Ok(()); };
    let dimensions = raster.width as u64 | (raster.height as u64) << 32;
    let origin = left as u32 as u64 | (top as u32 as u64) << 32;
    // SAFETY: contiguous ARGB allocation remains alive through bounded synchronous upload.
    let status = unsafe { libc::syscall(syscall::nt::NtService::QueryVirtualMemory.entry() as libc::c_long,
        abi::ALPHA_UPLOAD, dc, abi::INFO_CLASS, raster.pixels.as_ptr() as u64, dimensions, origin) };
    if status == 0 { Ok(()) } else { Err(()) }
}

pub(super) fn alpha_tile(x: i32, y: i32, raster: &RasterSurface, clip: Option<Rect>) -> Result<Option<(i32, i32, RasterSurface)>, ()> {
    let words = (raster.width as usize).checked_mul(raster.height as usize).ok_or(())?;
    if words > 16 * 1024 * 1024 || words != raster.pixels.len()
        || raster.width > i32::MAX as u32 || raster.height > i32::MAX as u32 { return Err(()); }
    let right = x.checked_add(raster.width as i32).ok_or(())?;
    let bottom = y.checked_add(raster.height as i32).ok_or(())?;
    let clip = clip.unwrap_or(Rect { left: x, top: y, right, bottom });
    let left = x.max(clip.left); let top = y.max(clip.top);
    let right = right.min(clip.right); let bottom = bottom.min(clip.bottom);
    if right <= left || bottom <= top { return Ok(None); }
    let width = (right - left) as usize; let height = (bottom - top) as usize;
    let mut pixels = Vec::with_capacity(width * height);
    for row in 0..height {
        let start = ((top - y) as usize + row) * raster.width as usize + (left - x) as usize;
        pixels.extend_from_slice(&raster.pixels[start..start + width]);
    }
    Ok(Some((left, top, RasterSurface { width: width as u32, height: height as u32, pixels })))
}
