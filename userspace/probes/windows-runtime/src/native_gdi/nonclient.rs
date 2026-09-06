//! Normalize a canonical profile using the same native font resource cache as text drawing.
use syscall::nt_native_gdi as abi;
fn integer(bytes: &[u8], offset: usize) -> Option<i32> { Some(i32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?)) }
fn put(bytes: &mut [u8], offset: usize, value: i32) { bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes()); }

pub(super) fn system_metric(input: &[u16], index: u32) -> Option<u32> {
    if !abi::system_metric_needs_font(index) { return None; }
    let bytes = normalize(input, abi::NONCLIENT_BYTES)?;
    let (offset, extra) = match index { 4 => (20, 1), 15 => (220, 1), 31 => (20, 0),
        51 => (120, 1), 53 => (120, 0), 55 => (220, 0), 57 => (20, 6), _ => return None };
    let value = integer(&bytes, offset)?.checked_add(extra)?;
    if value <= 0 { return None; }
    Some(value as u32)
}

pub(super) fn normalize(input: &[u16], size: u32) -> Option<Vec<u8>> {
    if input.len() != abi::NONCLIENT_BYTES as usize / 2 || !matches!(size, abi::NONCLIENT_BYTES | abi::NONCLIENT_LEGACY_BYTES) { return None; }
    let mut bytes: Vec<u8> = input.iter().flat_map(|w| w.to_le_bytes()).collect();
    if integer(&bytes, 0)? as u32 != size { return None; }
    for (offset, minimum) in [(4, 1), (8, 8), (12, 8), (16, 8)] {
        let value = integer(&bytes, offset)?.max(minimum); put(&mut bytes, offset, value);
    }
    for (offset, height_field, external) in [(24, 20, false), (124, 120, false), (224, 220, true)] {
        let font = super::native::selected_font_with_width(integer(&bytes, offset)?, integer(&bytes, offset + 4)?,
            integer(&bytes, offset + 16)?, u32::from(bytes[offset + 20] != 0))?;
        let tm = font.text_metrics_w(integer(&bytes, offset + 16)?, u32::from(bytes[offset + 20] != 0)).ok()?;
        let height = 2i32.checked_add(integer(&tm, 0)?)?.checked_add(if external { integer(&tm, 16)? } else { 0 })?;
        let height = integer(&bytes, height_field)?.max(height);
        put(&mut bytes, height_field, height);
    }
    bytes.truncate(size as usize);
    Some(bytes)
}
