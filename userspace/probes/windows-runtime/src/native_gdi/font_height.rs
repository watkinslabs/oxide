//! Select raster em size from logical cell/em height; no glyph parsing or font registry.
use syscall::nt_native_gdi::MAX_HEIGHT;

pub(crate) fn word(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes(bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?))
}
pub(crate) fn table<'a>(bytes: &'a [u8], tag: &[u8; 4]) -> Option<&'a [u8]> {
    let count = word(bytes, 4)? as usize;
    let directory = bytes.get(12..12usize.checked_add(count.checked_mul(16)?)?)?;
    for entry in directory.chunks_exact(16) {
        if &entry[..4] != tag { continue; }
        let offset = u32::from_be_bytes(entry[8..12].try_into().ok()?) as usize;
        let len = u32::from_be_bytes(entry[12..16].try_into().ok()?) as usize;
        return bytes.get(offset..offset.checked_add(len)?);
    }
    None
}

pub(super) fn pixel_size(bytes: &[u8], height: i32) -> Option<f32> {
    if height.checked_abs()? > MAX_HEIGHT { return None; }
    if height < 0 { return Some((-height) as f32); }
    let height = if height == 0 { 16 } else { height } as u64;
    let em = u64::from(word(table(bytes, b"head")?, 18)?);
    if em == 0 { return None; }
    let os2 = table(bytes, b"OS/2")?;
    let ascent = u64::from(word(os2, 74)?);
    let descent = i64::from(word(os2, 76)? as i16).unsigned_abs();
    let mut cell = ascent + descent;
    if cell == 0 {
        let hhea = table(bytes, b"hhea")?;
        let units = i32::from(word(hhea, 4)? as i16) - i32::from(word(hhea, 6)? as i16);
        cell = u64::try_from(units).ok()?;
    }
    if cell == 0 { return None; }
    let mut ppem = (em * height + cell / 2) / cell;
    if ppem > 1 && (cell * ppem + em / 2) / em > height { ppem -= 1; }
    (ppem > 0).then_some(ppem as f32)
}

#[cfg(test)]
#[path = "font_height_tests.rs"]
mod tests;
