use syscall::nt_native_gdi as abi;

fn request(count: usize) -> abi::MeasureRequest {
    abi::MeasureRequest { version: 1, size: 88, dc: 1, kind: abi::MEASURE_EXTENT, count: count as u32,
        height: 16, width: 0, weight: 400, italic: 0, max_extent: -1, flags: 0,
        text: 0x1000, metrics: 0, extent: 0x2000, fit: 0x3000, cumulative: 0x4000 }
}

#[test]
fn measurement_uses_the_render_font_not_one_pixel_logical_width() {
    super::native::prepare_fonts().unwrap();
    let text: Vec<u16> = "Notepad typed token".encode_utf16().collect();
    for (weight, italic) in [(400, 0), (700, 0), (400, 1), (700, 1)] {
        let request = abi::MeasureRequest { weight, italic, ..request(text.len()) };
        let font = super::native::selected_font(request.height, weight, italic).unwrap();
        let result = super::measure::measure(&font, &request, &text).unwrap();
        let tile = font.rasterize(&text, 0, 0xffffff).unwrap();
        assert_eq!(result.output.width, tile.width as i32);
        assert!(result.output.width > text.len() as i32 * 5);
        assert_eq!(result.cumulative.len(), text.len());
        assert_eq!(result.cumulative.last().copied(), Some(result.output.width));
        let metrics = &result.output.metrics;
        let word = |offset| i32::from_le_bytes(metrics[offset..offset + 4].try_into().unwrap());
        assert_eq!(word(0), word(4) + word(8));
        assert_eq!(word(0), result.output.height);
        assert!(word(4) > 0 && word(8) > 0 && word(20) > 1 && word(24) >= word(20));
        assert_eq!(word(28), weight); assert_eq!(metrics[52], italic as u8);
        assert_eq!((word(36), word(40)), (96, 96));
        assert!(u16::from_le_bytes(metrics[46..48].try_into().unwrap()) > 127);
        assert_eq!(metrics.len(), 60);
        assert!(metrics[57..].iter().all(|b| *b == 0));
    }
}

#[test]
fn utf16_fit_and_copyout_prefix_are_bounded_and_validated() {
    super::native::prepare_fonts().unwrap();
    let font = super::native::selected_font(16, 400, 0).unwrap();
    let text = [65u16, 0xd83d, 0xde00, 66];
    let mut request = request(text.len());
    let full = super::measure::measure(&font, &request, &text).unwrap();
    assert_eq!(full.cumulative[1], full.cumulative[2]);
    request.max_extent = full.cumulative[0];
    let result = super::measure::measure(&font, &request, &text).unwrap();
    assert_eq!(result.output.fit, 1);
    let bytes: Vec<u8> = result.cumulative.iter().flat_map(|v| v.to_le_bytes()).collect();
    assert_eq!(result.output.extent_copy_count(&request, &bytes), Some(1));
    assert_eq!(result.output.extent_copy_count(&abi::MeasureRequest { fit: 0, ..request }, &bytes), Some(4));
    assert!(result.output.extent_copy_count(&request, &bytes[..4]).is_none());
    let mut invalid = result.output; invalid.count = abi::MAX_UNITS + 1;
    assert!(invalid.extent_copy_count(&request, &bytes).is_none());
    let bad = [1i32, 0, 2, 3].into_iter().flat_map(i32::to_le_bytes).collect::<Vec<_>>();
    assert!(result.output.extent_copy_count(&request, &bad).is_none());
}

#[test]
fn measurement_empty_text_and_malformed_requests_fail_before_outputs() {
    assert_eq!(std::mem::size_of::<abi::MeasureRequest>(), 88);
    assert_eq!(std::mem::size_of::<abi::MeasureOutput>(), 88);
    let valid = request(0);
    for bad in [abi::MeasureRequest { count: abi::MAX_UNITS + 1, ..valid },
        abi::MeasureRequest { kind: 99, ..valid }, abi::MeasureRequest { extent: u64::MAX, ..valid },
        abi::MeasureRequest { count: 1, cumulative: u64::MAX, ..valid },
        abi::MeasureRequest { kind: abi::MEASURE_METRICS, metrics: 0, ..valid }] { assert!(!bad.valid()); }
    super::native::prepare_fonts().unwrap();
    let font = super::native::selected_font(16, 400, 0).unwrap();
    let empty = super::measure::measure(&font, &valid, &[]).unwrap();
    assert_eq!((empty.output.width, empty.output.height, empty.output.fit), (0, 0, 0));
    assert!(empty.cumulative.is_empty());
    let malformed = [0xd800u16, 65];
    let result = super::measure::measure(&font, &request(2), &malformed).unwrap();
    assert_eq!(result.cumulative.len(), 2);
    assert_eq!(result.output.width, font.rasterize(&malformed, 0, 0xffffff).unwrap().width as i32);
}

#[test]
fn metrics_flags_are_ignored_but_extent_glyph_indices_are_not_unicode() {
    super::native::prepare_fonts().unwrap();
    let font = super::native::selected_font(16, 400, 0).unwrap();
    let base = abi::MeasureRequest { kind: abi::MEASURE_METRICS, metrics: 0x1000, ..request(0) };
    let expected = super::measure::measure(&font, &base, &[]).unwrap().output.metrics;
    for flags in [1, 2, 0x80000000, u32::MAX] {
        let metrics = abi::MeasureRequest { flags, ..base };
        assert!(metrics.valid());
        assert_eq!(super::measure::measure(&font, &metrics, &[]).unwrap().output.metrics, expected);
        assert!(abi::MeasureRequest { flags, ..request(0) }.valid());
        let glyphs = font.glyph_indices(&[65, 66, 67], 0, false);
        let measured = super::measure::measure(&font, &abi::MeasureRequest { flags, ..request(3) }, &glyphs).unwrap();
        let unicode = font.measure_utf16(&[65, 66, 67], -1).unwrap();
        assert_eq!(measured.cumulative, unicode.cumulative);
        assert!(super::measure::measure(&font, &abi::MeasureRequest { flags, ..request(1) }, &[65535]).is_err());
    }
}

#[test]
fn logical_cell_em_and_default_heights_select_distinct_real_font_sizes() {
    super::native::prepare_fonts().unwrap();
    let text = [u16::from(b'M'); 8];
    let cell = super::native::selected_font(16, 400, 0).unwrap();
    let em = super::native::selected_font(-16, 400, 0).unwrap();
    let default = super::native::selected_font(0, 400, 0).unwrap();
    let cell_size = cell.measure_utf16(&text, -1).unwrap();
    let em_size = em.measure_utf16(&text, -1).unwrap();
    assert!(cell_size.width < em_size.width);
    assert!(cell_size.height < em_size.height);
    assert!(std::sync::Arc::ptr_eq(&default, &cell));
    for height in [0, 16, -16] {
        assert!(abi::MeasureRequest { height, ..request(text.len()) }.valid());
    }
}

#[test]
fn system_stock_width_seven_scales_glyphs_and_measurement_without_overriding_lpdx() {
    super::native::prepare_fonts().unwrap();
    let font = super::native::selected_font_with_width(16, 7, 700, 0).unwrap();
    let natural = super::native::selected_font_with_width(16, 0, 700, 0).unwrap();
    let text: Vec<u16> = "Stock System".encode_utf16().collect();
    let request = abi::MeasureRequest { width: 7, weight: 700, ..request(text.len()) };
    assert!(request.valid());
    let measured = super::measure::measure(&font, &request, &text).unwrap();
    assert_eq!(measured.output.width, 7 * text.len() as i32);
    assert_eq!(i32::from_le_bytes(measured.output.metrics[20..24].try_into().unwrap()), 7);
    let scaled = font.rasterize_alpha(&text, None, 0x123456).unwrap();
    let unscaled = natural.rasterize_alpha(&text, None, 0x123456).unwrap();
    assert_eq!(scaled.width as i32, measured.output.width);
    assert!(scaled.width < unscaled.width);
    assert!(scaled.pixels.iter().any(|pixel| *pixel >> 24 != 0));
    let advances = vec![11; text.len()];
    let explicit = font.rasterize_with_advances(&text, Some(&advances), 0, 0xffffff).unwrap();
    assert_eq!(explicit.width, 11 * text.len() as u32);
    let negative = super::native::selected_font_with_width(16, -7, 700, 0).unwrap();
    let negative_request = abi::MeasureRequest { width: -7, ..request };
    assert!(negative_request.valid());
    let negative_measure = super::measure::measure(&negative, &negative_request, &text).unwrap();
    assert_eq!(negative_measure.output.width, measured.output.width);
    assert_eq!(negative_measure.output.metrics, measured.output.metrics);
    assert_eq!(negative.rasterize_alpha(&text, None, 0x123456).unwrap().pixels, scaled.pixels);
    assert!(super::native::selected_font_with_width(16, i32::MIN, 700, 0).is_none());
    assert!(super::native::selected_font_with_width(16, abi::MAX_WIDTH + 1, 700, 0).is_none());
}

#[test]
fn logical_width_expands_actual_glyph_coverage_not_only_the_advance() {
    super::native::prepare_fonts().unwrap();
    let natural = super::native::selected_font_with_width(16, 0, 700, 0).unwrap();
    let expanded = super::native::selected_font_with_width(16, 20, 700, 0).unwrap();
    let text = [u16::from(b'M')];
    let original = natural.rasterize_alpha(&text, None, 0x123456).unwrap();
    let scaled = expanded.rasterize_alpha(&text, None, 0x123456).unwrap();
    let ink_width = |surface: &windows_gdi::RasterSurface| {
        let columns: Vec<usize> = surface.pixels.iter().enumerate()
            .filter(|(_, pixel)| **pixel >> 24 != 0).map(|(index, _)| index % surface.width as usize).collect();
        columns.iter().max().unwrap() - columns.iter().min().unwrap() + 1
    };
    assert!(ink_width(&scaled) >= ink_width(&original) * 2);
    assert_eq!(scaled.height, original.height);
    assert_eq!(scaled.width, 20);
    assert!(scaled.pixels.iter().any(|pixel| *pixel >> 24 > 0 && *pixel >> 24 < 255));
    assert!(scaled.pixels.iter().filter(|pixel| **pixel >> 24 != 0).all(|pixel| *pixel & 0xffffff == 0x123456));
}
