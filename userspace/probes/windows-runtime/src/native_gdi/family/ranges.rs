//! The supported character set reported as a GLYPHSET record.
use super::put;
use syscall::nt_native_gdi as abi;
use windows_gdi::RasterFont;

const HEADER: usize = abi::GLYPHSET_HEADER_BYTES as usize;
const RANGE_BYTES: usize = 4;

/// Contiguous supported ranges, counted as the reference counts them: the
/// first character of a range opens it without being counted itself.
/// # C: O(characters)
pub(super) fn execute(font: &RasterFont, request: &abi::QueryRequest) -> Option<(u32, Vec<u8>)> {
    let codes: Vec<u32> = font.character_codes();
    let Some((first, rest)) = codes.split_first() else { return Some((HEADER as u32, Vec::new())); };
    let mut ranges: Vec<(u16, u32)> = vec![(*first as u16, 0)];
    let mut supported = 0u32;
    let mut previous = *first;
    for code in rest {
        if *code < previous { return None; }
        if code - previous > 1 { ranges.push((*code as u16, 1)); } else { ranges.last_mut()?.1 += 1; }
        supported += 1;
        previous = *code;
    }
    let size = u32::try_from(HEADER + ranges.len() * RANGE_BYTES).ok()?;
    if request.output == 0 { return Some((size, Vec::new())); }
    let mut data = vec![0u8; size as usize];
    put(&mut data, 0, size as i32);
    put(&mut data, 8, supported as i32);
    put(&mut data, 12, ranges.len() as i32);
    for (index, (low, glyphs)) in ranges.iter().enumerate() {
        super::put16(&mut data, HEADER + index * RANGE_BYTES, *low);
        super::put16(&mut data, HEADER + index * RANGE_BYTES + 2, u16::try_from(*glyphs).unwrap_or(u16::MAX));
    }
    Some((size, data))
}
