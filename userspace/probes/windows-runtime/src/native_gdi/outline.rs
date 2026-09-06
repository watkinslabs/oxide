//! Serialize native 64-bit outline metrics; strings contain relative byte offsets.
use super::native::font_height::{table, word};
use windows_gdi::RasterFont;
const FIXED: usize = 232;
fn put(bytes: &mut [u8], offset: usize, value: i32) { bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes()); }
fn name(bytes: &[u8], id: u16) -> Option<Vec<u8>> {
    let table = table(bytes, b"name")?;
    let count = word(table, 2)? as usize;
    let start = word(table, 4)? as usize;
    let entries = table.get(6..6usize.checked_add(count.checked_mul(12)?)?)?;
    let entry = entries.chunks_exact(12).filter(|e| word(e, 0) == Some(3) && word(e, 6) == Some(id))
        .max_by_key(|e| usize::from(word(e, 4) == Some(0x409)))?;
    let offset = start.checked_add(word(entry, 10)? as usize)?;
    let data = table.get(offset..offset.checked_add(word(entry, 8)? as usize)?)?;
    if data.len() % 2 != 0 { return None; }
    let mut out = Vec::with_capacity(data.len() + 2);
    for unit in data.chunks_exact(2) { out.extend_from_slice(&[unit[1], unit[0]]); }
    out.extend_from_slice(&[0, 0]);
    Some(out)
}
pub(super) fn metrics(font: &RasterFont, bytes: &[u8], weight: i32, italic: u32) -> Option<Vec<u8>> {
    let head = table(bytes, b"head")?;
    let os2 = table(bytes, b"OS/2")?;
    let hhea = table(bytes, b"hhea")?;
    let post = table(bytes, b"post")?;
    let mut out = vec![0; FIXED];
    let tm = font.text_metrics_w(weight, italic).ok()?;
    out[4..64].copy_from_slice(&tm);
    out[65..75].copy_from_slice(os2.get(32..42)?);
    put(&mut out, 76, word(os2, 62)? as i32);
    put(&mut out, 80, (word(os2, 8)? & 0x30e) as i32);
    put(&mut out, 84, word(hhea, 18)? as i16 as i32);
    put(&mut out, 88, word(hhea, 20)? as i16 as i32);
    // The ABI's italic angle and minimum PPEM fields are zero for this scalable realization.
    put(&mut out, 96, word(head, 18)? as i32);
    for (dest, source) in [(100, 68), (104, 70), (108, 72), (112, 88), (116, 86)] {
        put(&mut out, dest, font.scale_design_units(word(os2, source)? as i16 as i32, false));
    }
    for (dest, source, horizontal) in [(120, 36, true), (124, 42, false), (128, 40, true), (132, 38, false)] {
        put(&mut out, dest, font.scale_design_units(word(head, source)? as i16 as i32, horizontal));
    }
    put(&mut out, 136, i32::from_le_bytes(tm[4..8].try_into().ok()?));
    put(&mut out, 140, -i32::from_le_bytes(tm[8..12].try_into().ok()?));
    put(&mut out, 144, font.scale_design_units(word(hhea, 8)? as i16 as i32, false));
    for (dest, source, horizontal) in [(152, 10, true), (156, 12, false), (160, 14, true), (164, 16, false),
        (168, 18, true), (172, 20, false), (176, 22, true), (180, 24, false), (184, 26, false), (188, 28, false)] {
        put(&mut out, dest, font.scale_design_units(word(os2, source)? as i16 as i32, horizontal));
    }
    put(&mut out, 192, font.scale_design_units(word(post, 10)? as i16 as i32, false));
    put(&mut out, 196, font.scale_design_units(word(post, 8)? as i16 as i32, false));
    for (dest, id) in [(200, 1), (216, 2), (208, 4), (224, 3)] {
        let value = name(bytes, id)?;
        let offset = out.len() as u64;
        out[dest..dest + 8].copy_from_slice(&offset.to_le_bytes());
        out.extend_from_slice(&value);
    }
    let len = i32::try_from(out.len()).ok()?;
    put(&mut out, 0, len);
    Some(out)
}
