use super::{dword, request, run, short};
use super::super::super::native;
use syscall::nt_native_gdi as abi;

const GGO_METRICS: u32 = 0;
const GGO_BITMAP: u32 = 1;
const GGO_NATIVE: u32 = 2;
const GGO_BEZIER: u32 = 3;
const GGO_GRAY8_BITMAP: u32 = 6;
const GGO_GLYPH_INDEX: u32 = 0x80;
const IDENTITY: [u16; 8] = [0, 1, 0, 0, 0, 0, 0, 1];

fn outline(format: u32, code: u32, capacity: u32, output: u64, matrix: [u16; 8]) -> Option<(u32, Vec<u8>)> {
    let request = abi::QueryRequest { first: code, flags: format, count: abi::MAT2_WORDS, input: 1,
        aux: 0x30000, capacity, output, ..request(abi::QUERY_GLYPH_OUTLINE) };
    run(&request, &matrix)
}

#[test]
fn glyph_metrics_describe_the_bitmap_the_renderer_produces() {
    native::prepare_fonts().unwrap();
    let font = native::selected_font_with_width(16, 0, 400, 0).unwrap();
    let raster = font.glyph_raster(font.glyph_for('W' as u32)).unwrap();
    let (result, metrics) = outline(GGO_METRICS, 'W' as u32, 0, 0, IDENTITY).unwrap();
    assert_eq!((result, metrics.len()), (1, 20));
    assert_eq!(dword(&metrics, 0), raster.width.max(1) as u32);
    assert_eq!(dword(&metrics, 4), raster.height.max(1) as u32);
    assert_eq!(dword(&metrics, 8) as i32, raster.left);
    assert_eq!(dword(&metrics, 12) as i32, raster.bottom + raster.height as i32);
    assert_eq!(short(&metrics, 16) as i16 as i32, raster.advance);
    assert_eq!(short(&metrics, 18), 0);
    // A caller with no metrics record still gets its result.
    let request = abi::QueryRequest { first: 'W' as u32, flags: GGO_METRICS, count: abi::MAT2_WORDS,
        input: 1, aux: 0, capacity: 0, output: 0, ..request(abi::QUERY_GLYPH_OUTLINE) };
    assert_eq!(run(&request, &IDENTITY), Some((1, Vec::new())));
}

#[test]
fn the_glyph_index_form_selects_the_same_glyph_as_its_character() {
    native::prepare_fonts().unwrap();
    let font = native::selected_font_with_width(16, 0, 400, 0).unwrap();
    let glyph = u32::from(font.glyph_for('g' as u32));
    assert_eq!(outline(GGO_METRICS | GGO_GLYPH_INDEX, glyph, 0, 0, IDENTITY),
        outline(GGO_METRICS, 'g' as u32, 0, 0, IDENTITY));
}

#[test]
fn monochrome_and_gray_bitmaps_use_their_own_row_alignment_and_levels() {
    let (needed, metrics) = outline(GGO_BITMAP, 'W' as u32, 0, 0, IDENTITY).unwrap();
    let width = dword(&metrics, 0) as usize;
    let height = dword(&metrics, 4) as usize;
    assert_eq!(needed as usize, (width + 31) / 32 * 4 * height);
    let (again, data) = outline(GGO_BITMAP, 'W' as u32, needed, 0x10000, IDENTITY).unwrap();
    assert_eq!((again, data.len()), (needed, 20 + needed as usize));
    assert!(data[20..].iter().any(|byte| *byte != 0));
    let (gray, metrics) = outline(GGO_GRAY8_BITMAP, 'W' as u32, 0, 0, IDENTITY).unwrap();
    assert_eq!(gray as usize, (dword(&metrics, 0) as usize + 3) / 4 * 4 * dword(&metrics, 4) as usize);
    let (_, data) = outline(GGO_GRAY8_BITMAP, 'W' as u32, gray, 0x10000, IDENTITY).unwrap();
    assert!(data[20..].iter().all(|level| *level <= 64));
    assert!(data[20..].iter().any(|level| *level > 0));
    // A buffer that cannot hold the form is refused rather than truncated.
    assert_eq!(outline(GGO_BITMAP, 'W' as u32, needed - 1, 0x10000, IDENTITY), None);
}

#[test]
fn native_and_bezier_polygons_are_self_describing_and_cover_the_result() {
    for (format, primitive) in [(GGO_NATIVE, 2u16), (GGO_BEZIER, 3u16)] {
        let (needed, _) = outline(format, 'o' as u32, 0, 0, IDENTITY).unwrap();
        assert!(needed >= 16, "a closed contour needs at least one polygon header");
        let (again, data) = outline(format, 'o' as u32, needed, 0x10000, IDENTITY).unwrap();
        assert_eq!((again, data.len()), (needed, 20 + needed as usize));
        let polygons = &data[20..];
        let mut offset = 0usize;
        let mut curves = 0;
        while offset < polygons.len() {
            let length = dword(polygons, offset) as usize;
            assert_eq!(dword(polygons, offset + 4), 24);
            assert!(length >= 16 && offset + length <= polygons.len());
            let mut inner = offset + 16;
            while inner < offset + length {
                let kind = short(polygons, inner);
                let points = short(polygons, inner + 2) as usize;
                assert!(kind == 1 || kind == primitive, "unexpected primitive {kind}");
                if kind == 3 { assert_eq!(points % 3, 0); }
                assert!(points > 0);
                inner += 4 + points * 8;
                curves += 1;
            }
            assert_eq!(inner, offset + length);
            offset += length;
        }
        assert!(curves > 0);
    }
}

#[test]
fn a_transform_this_realization_cannot_apply_is_refused() {
    let doubled = [0, 2, 0, 0, 0, 0, 0, 2];
    for format in [GGO_BITMAP, GGO_NATIVE, GGO_GRAY8_BITMAP] {
        assert_eq!(outline(format, 'W' as u32, 0, 0, doubled), None);
    }
    // Metrics are still answered, as the reference answers them from the cache.
    assert_eq!(outline(GGO_METRICS, 'W' as u32, 0, 0, doubled).map(|(result, _)| result), Some(1));
}
