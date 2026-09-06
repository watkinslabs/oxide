//! Queries inspect the exact cached static resource used by RasterFont.
use super::native::font_height::{table, word};

pub(super) fn signature(bytes: &[u8]) -> Option<[u8; 24]> {
    let os2 = table(bytes, b"OS/2")?;
    let mut result = [0; 24];
    for (index, offset) in [42, 46, 50, 54, 78, 82].into_iter().enumerate() {
        let value = u32::from_be_bytes(os2.get(offset..offset + 4)?.try_into().ok()?);
        result[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    Some(result)
}

pub(super) fn font_data(bytes: &[u8], tag: u32, offset: u32, capacity: u32, copy: bool) -> Option<(u32, Vec<u8>)> {
    let bytes = if tag == 0 { bytes } else { table(bytes, &tag.to_le_bytes())? };
    if bytes.is_empty() { return None; }
    let size = u32::try_from(bytes.len()).ok()?;
    if !copy || capacity == 0 { return Some((size, Vec::new())); }
    let count = capacity.min(size);
    let start = offset as usize;
    Some((count, bytes.get(start..start.checked_add(count as usize)?)?.to_vec()))
}

pub(super) fn default_character(bytes: &[u8]) -> Option<u16> {
    let os2 = table(bytes, b"OS/2")?;
    if word(os2, 0)? < 2 { Some(0) } else { word(os2, 90) }
}
