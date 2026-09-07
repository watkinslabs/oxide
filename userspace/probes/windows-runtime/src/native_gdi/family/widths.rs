//! Character widths, the width-info record and the kerning pair table.
use super::{put, put16};
use super::super::native::font_height::{table, word};
use syscall::nt_native_gdi as abi;
use windows_gdi::RasterFont;

/// Widths are reported as integers rather than the float form.
const CHAR_WIDTH_INT: u32 = 0x02;
const CHAR_WIDTH_INDICES: u32 = 0x08;
/// The float form scales device widths by the inverse of the reference's
/// fixed sixteenth-unit denominator under an identity transform.
const FLOAT_WIDTH_DENOMINATOR: f32 = 16.0;
const KERN_HEADER: usize = 4;
const SUBTABLE_HEADER: usize = 6;
const PAIR_BYTES: usize = 6;
const FORMAT0_HEADER: usize = 8;
/// Design units per character advance in the hhea record.
const HHEA_MIN_LEFT: usize = 12;
const HHEA_MIN_RIGHT: usize = 14;

/// One width per requested character or glyph; an unavailable glyph is zero.
/// # C: O(count)
pub(super) fn char_width(font: &RasterFont, request: &abi::QueryRequest, input: &[u16]) -> Option<(u32, Vec<u8>)> {
    let indices = request.flags & CHAR_WIDTH_INDICES != 0;
    let integer = indices || request.flags & CHAR_WIDTH_INT != 0;
    let mut data = Vec::with_capacity(request.count as usize * 4);
    for index in 0..request.count {
        let value = if request.input == 0 { request.first.wrapping_add(index) } else { *input.get(index as usize)? as u32 };
        let glyph = if indices { u16::try_from(value).ok()? } else { font.glyph_for(value) };
        let width = font.glyph_abc(glyph).map(|abc| abc[0] + abc[1] + abc[2]).unwrap_or(0);
        if integer { data.extend_from_slice(&width.to_le_bytes()); }
        else { data.extend_from_slice(&(width as f32 / FLOAT_WIDTH_DENOMINATOR).to_le_bytes()); }
    }
    Some((1, data))
}

/// Minimum side bearings of the realized face, scaled by its em size. # C: O(1)
pub(super) fn width_info(font: &RasterFont, bytes: &[u8]) -> Option<(u32, Vec<u8>)> {
    let hhea = table(bytes, b"hhea")?;
    let mut data = vec![0u8; abi::CHAR_WIDTH_INFO_BYTES as usize];
    for (offset, source) in [(0, HHEA_MIN_LEFT), (4, HHEA_MIN_RIGHT)] {
        let units = word(hhea, source)? as i16 as i32;
        put(&mut data, offset, font.scale_design_units(units, false) as i16 as i32);
    }
    Some((1, data))
}

/// Character codes for every glyph, lowest code first, as the reference maps
/// kerning pairs back from glyph identifiers. # C: O(characters)
fn glyph_characters(font: &RasterFont) -> Vec<u16> {
    let mut map = vec![0u16; usize::from(font.glyph_count()) + 1];
    for code in font.character_codes() {
        let Ok(code) = u16::try_from(code) else { continue; };
        let glyph = usize::from(font.glyph_for(u32::from(code)));
        if glyph < map.len() && map[glyph] == 0 { map[glyph] = code; }
    }
    map
}

fn pairs(font: &RasterFont, bytes: &[u8]) -> Option<Vec<[u8; 8]>> {
    let kern = table(bytes, b"kern")?;
    let characters = glyph_characters(font);
    let em = font.design_units_per_em() as i32;
    let ppem = font.pixel_size() as i32;
    if em <= 0 { return None; }
    let tables = word(kern, 2)? as usize;
    let mut out = Vec::new();
    let mut offset = KERN_HEADER;
    for _ in 0..tables {
        let length = word(kern, offset + 2)? as usize;
        let coverage = word(kern, offset + 4)?;
        if coverage >> 8 == 0 {
            let start = offset + SUBTABLE_HEADER;
            let count = word(kern, start)? as usize;
            for index in 0..count {
                let entry = start + FORMAT0_HEADER + index * PAIR_BYTES;
                let left = word(kern, entry)? as usize;
                let right = word(kern, entry + 2)? as usize;
                let units = word(kern, entry + 4)? as i16 as i32;
                let mut amount = units.checked_mul(ppem)?;
                if amount < 0 { amount = amount - em / 2 - ppem; } else if amount > 0 { amount = amount + em / 2 + ppem; }
                let mut pair = [0u8; 8];
                put16(&mut pair, 0, characters.get(left).copied().unwrap_or(0));
                put16(&mut pair, 2, characters.get(right).copied().unwrap_or(0));
                put(&mut pair, 4, amount / em);
                out.push(pair);
            }
        }
        offset = offset.checked_add(length.max(SUBTABLE_HEADER))?;
        if offset >= kern.len() { break; }
    }
    Some(out)
}

/// The kerning pair count, and the leading pairs when the caller supplies room.
/// # C: O(pairs)
pub(super) fn kerning(font: &RasterFont, bytes: &[u8], request: &abi::QueryRequest) -> Option<(u32, Vec<u8>)> {
    let pairs = pairs(font, bytes).unwrap_or_default();
    let total = u32::try_from(pairs.len()).ok()?;
    if request.output == 0 || request.value == 0 { return Some((total, Vec::new())); }
    let wanted = (request.value.min(u64::from(total))) as usize;
    Some((total, pairs[..wanted].iter().flatten().copied().collect()))
}
