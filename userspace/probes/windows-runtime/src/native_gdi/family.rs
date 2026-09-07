//! Module manifest: charset owns the enumeration charset list; enumerate owns
//! enumeration records; widths owns width, width-info and kerning answers;
//! ranges owns the supported character set; glyph owns the glyph outline;
//! realize owns face name and realization identity; resource owns font
//! resources, font files and the font directory record.
use syscall::nt_native_gdi as abi;
use windows_gdi::RasterFont;

mod charset;
mod enumerate;
mod widths;
mod ranges;
mod glyph;
mod outline_data;
mod realize;
mod resource;

/// Answer one font-family query from the registered font faces.
/// # C: bounded by the query's own record count
pub(super) fn execute(font: &RasterFont, bytes: &[u8], request: &abi::QueryRequest, input: &[u16]) -> Option<(u32, Vec<u8>)> {
    match request.kind {
        abi::QUERY_ENUM_FONTS => enumerate::execute(request, input),
        abi::QUERY_CHAR_WIDTH => widths::char_width(font, request, input),
        abi::QUERY_WIDTH_INFO => widths::width_info(font, bytes),
        abi::QUERY_KERNING_PAIRS => widths::kerning(font, bytes, request),
        abi::QUERY_UNICODE_RANGES => ranges::execute(font, request),
        abi::QUERY_GLYPH_OUTLINE => glyph::execute(font, bytes, request, input),
        abi::QUERY_TEXT_FACE => realize::text_face(bytes, request),
        abi::QUERY_REALIZATION => realize::realization(request),
        _ => resource::execute(request, input),
    }
}

/// Rounded scaling in the reference's integer proportion form. # C: O(1)
pub(super) fn muldiv(value: i32, numerator: i32, denominator: i32) -> i32 {
    if denominator == 0 { return -1; }
    let product = i64::from(value) * i64::from(numerator);
    let half = i64::from(denominator) / 2;
    let scaled = if (product < 0) != (denominator < 0) { (product - half) / i64::from(denominator) }
        else { (product + half) / i64::from(denominator) };
    i32::try_from(scaled).unwrap_or(-1)
}

/// Little-endian field writer shared by every fixed Windows record here. # C: O(1)
pub(super) fn put(bytes: &mut [u8], offset: usize, value: i32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn put16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn read(bytes: &[u8], offset: usize) -> Option<i32> {
    Some(i32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?))
}

/// Copy a NUL-terminated UTF-16 name into a fixed record field. # C: O(field)
pub(super) fn put_name(bytes: &mut [u8], offset: usize, units: usize, name: &[u16]) {
    for (index, unit) in name.iter().take(units.saturating_sub(1)).enumerate() {
        put16(bytes, offset + index * 2, *unit);
    }
}

#[cfg(test)]
#[path = "family/tests.rs"]
mod tests;
