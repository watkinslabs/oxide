use super::{dword, request, run};
use super::super::super::native;
use syscall::nt_native_gdi as abi;

const CHAR_WIDTH_INT: u32 = 0x02;
const CHAR_WIDTH_INDICES: u32 = 0x08;

fn widths(flags: u32, first: u32, count: u32, input: &[u16]) -> Vec<u8> {
    let request = abi::QueryRequest { first, count, flags, input: if input.is_empty() { 0 } else { 1 },
        output: 0x10000, ..request(abi::QUERY_CHAR_WIDTH) };
    let (result, data) = run(&request, input).unwrap();
    assert_eq!(result, 1);
    assert_eq!(data.len(), count as usize * 4);
    data
}

#[test]
fn integer_widths_are_the_advance_the_renderer_uses() {
    native::prepare_fonts().unwrap();
    let font = native::selected_font_with_width(16, 0, 400, 0).unwrap();
    let data = widths(CHAR_WIDTH_INT, 'A' as u32, 3, &[]);
    for (index, code) in ['A', 'B', 'C'].into_iter().enumerate() {
        let abc = font.glyph_abc(font.glyph_for(code as u32)).unwrap();
        assert_eq!(dword(&data, index * 4) as i32, abc[0] + abc[1] + abc[2]);
    }
    // The same characters supplied explicitly answer identically.
    assert_eq!(widths(CHAR_WIDTH_INT, 0, 3, &['A' as u16, 'B' as u16, 'C' as u16]), data);
}

#[test]
fn the_float_form_scales_the_same_device_widths() {
    let integers = widths(CHAR_WIDTH_INT, 'A' as u32, 4, &[]);
    let floats = widths(0, 'A' as u32, 4, &[]);
    for index in 0..4 {
        let integer = dword(&integers, index * 4) as i32;
        let float = f32::from_le_bytes(floats[index * 4..index * 4 + 4].try_into().unwrap());
        assert_eq!(float, integer as f32 / 16.0);
    }
}

#[test]
fn the_index_form_reads_glyph_identifiers_not_character_codes() {
    native::prepare_fonts().unwrap();
    let font = native::selected_font_with_width(16, 0, 400, 0).unwrap();
    let glyph = font.glyph_for('W' as u32);
    let data = widths(CHAR_WIDTH_INDICES, 0, 1, &[glyph]);
    let abc = font.glyph_abc(glyph).unwrap();
    assert_eq!(dword(&data, 0) as i32, abc[0] + abc[1] + abc[2]);
    // A glyph identifier the face does not define reports no width.
    assert_eq!(dword(&widths(CHAR_WIDTH_INDICES, 0, 1, &[u16::MAX]), 0), 0);
}

#[test]
fn side_bearings_come_from_the_faces_own_horizontal_header() {
    native::prepare_fonts().unwrap();
    let font = native::selected_font_with_width(16, 0, 400, 0).unwrap();
    let bytes = native::selected_bytes(400, 0).unwrap();
    let hhea = native::font_height::table(bytes, b"hhea").unwrap();
    let (result, data) = run(&abi::QueryRequest { capacity: abi::CHAR_WIDTH_INFO_BYTES,
        ..request(abi::QUERY_WIDTH_INFO) }, &[]).unwrap();
    assert_eq!((result, data.len()), (1, 12));
    for (offset, source) in [(0, 12), (4, 14)] {
        let units = native::font_height::word(hhea, source).unwrap() as i16 as i32;
        assert_eq!(dword(&data, offset) as i32, font.scale_design_units(units, false) as i16 as i32);
    }
    // The third field is reserved and always reported as zero.
    assert_eq!(dword(&data, 8), 0);
}

#[test]
fn supported_ranges_are_contiguous_ascending_and_self_describing() {
    native::prepare_fonts().unwrap();
    let font = native::selected_font_with_width(16, 0, 400, 0).unwrap();
    let (size, data) = run(&request(abi::QUERY_UNICODE_RANGES), &[]).unwrap();
    assert_eq!(size as usize, data.len());
    assert_eq!(dword(&data, 0), size);
    assert_eq!(dword(&data, 4), 0);
    let ranges = dword(&data, 12) as usize;
    assert_eq!(size as usize, 16 + ranges * 4);
    let mut covered = 1u32;
    let mut previous = 0u32;
    for index in 0..ranges {
        let low = super::short(&data, 16 + index * 4) as u32;
        let glyphs = super::short(&data, 18 + index * 4) as u32;
        assert!(index == 0 || low > previous + 1, "ranges must be separated");
        // The opening range does not count its own first character.
        previous = low + glyphs - u32::from(index != 0);
        covered += glyphs;
    }
    assert_eq!(covered, dword(&data, 8) + 1);
    assert_eq!(covered as usize, font.character_codes().len());
    // A size query reports the same length and writes nothing.
    assert_eq!(run(&abi::QueryRequest { output: 0, ..request(abi::QUERY_UNICODE_RANGES) }, &[]),
        Some((size, Vec::new())));
}

#[test]
fn kerning_reports_the_faces_own_pair_count_in_both_call_forms() {
    let size_query = run(&abi::QueryRequest { output: 0, value: 0, ..request(abi::QUERY_KERNING_PAIRS) }, &[]).unwrap();
    assert!(size_query.1.is_empty());
    let total = size_query.0;
    let filled = run(&abi::QueryRequest { output: 0x10000, value: u64::from(total.max(1)),
        capacity: total.max(1) * abi::KERNING_PAIR_BYTES, ..request(abi::QUERY_KERNING_PAIRS) }, &[]).unwrap();
    assert_eq!(filled.0, total);
    assert_eq!(filled.1.len(), total as usize * abi::KERNING_PAIR_BYTES as usize);
    for pair in filled.1.chunks_exact(8) { assert_ne!(super::short(pair, 0), 0); }
}
