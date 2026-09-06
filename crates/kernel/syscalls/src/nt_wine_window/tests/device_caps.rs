use super::*;

/// A 1920x1080 primary monitor at the default density, true colour, 60Hz.
fn display() -> Device {
    Device { screen: (1920, 1080), desktop: (1920, 1080), dpi: 96, depth: 32, palette_size: 0, refresh_hz: 60 }
}

#[test]
fn a_raster_display_names_its_driver_technology_and_object_limits() {
    let device = display();
    assert_eq!(caps(DRIVERVERSION, device), 0x4000);
    assert_eq!(caps(TECHNOLOGY, device), DT_RASDISPLAY);
    assert_eq!(caps(PLANES, device), 1);
    assert_eq!(caps(NUMBRUSHES, device), -1);
    assert_eq!(caps(NUMPENS, device), -1);
    assert_eq!(caps(NUMMARKERS, device), 0);
    assert_eq!(caps(NUMFONTS, device), 0);
    assert_eq!(caps(PDEVICESIZE, device), 0);
    assert_eq!(caps(NUMRESERVED, device), 20);
    assert_eq!(caps(CAPS1, device), 0);
}

#[test]
fn resolution_and_density_come_from_the_display_owner() {
    let device = display();
    assert_eq!(caps(HORZRES, device), 1920);
    assert_eq!(caps(VERTRES, device), 1080);
    assert_eq!(caps(LOGPIXELSX, device), 96);
    assert_eq!(caps(LOGPIXELSY, device), 96);
    assert_eq!(caps(VREFRESH, device), 60);
    // A multi-monitor desktop is wider than the primary screen it contains.
    let spanned = Device { desktop: (3840, 1080), ..device };
    assert_eq!(caps(HORZRES, spanned), 1920);
    assert_eq!(caps(DESKTOPHORZRES, spanned), 3840);
    assert_eq!(caps(DESKTOPVERTRES, spanned), 1080);
}

#[test]
fn a_device_with_no_monitor_reports_the_fallback_resolution_and_refresh() {
    let device = Device { screen: (0, 0), desktop: (0, 0), refresh_hz: 0, ..display() };
    assert_eq!(caps(HORZRES, device), 640);
    assert_eq!(caps(VERTRES, device), 480);
    assert_eq!(caps(VREFRESH, device), 1);
    // The desktop rectangle is reported as measured, with no fallback.
    assert_eq!(caps(DESKTOPHORZRES, device), 0);
    assert_eq!(caps(DESKTOPVERTRES, device), 0);
}

#[test]
fn physical_size_is_the_resolution_scaled_by_the_density() {
    // 1920 pixels at 96 dpi is 20 inches, 508 millimetres.
    assert_eq!(caps(HORZSIZE, display()), 508);
    assert_eq!(caps(VERTSIZE, display()), 286);
    let dense = Device { dpi: 192, ..display() };
    assert_eq!(caps(HORZSIZE, dense), 254);
    assert_eq!(caps(VERTSIZE, dense), 143);
    // A density of zero divides by zero and reports the scaling failure.
    let unmeasured = Device { dpi: 0, ..display() };
    assert_eq!(caps(HORZSIZE, unmeasured), -1);
    assert_eq!(caps(VERTSIZE, unmeasured), -1);
}

#[test]
fn colour_capabilities_follow_the_surface_depth() {
    let device = display();
    assert_eq!(caps(BITSPIXEL, device), 32);
    assert_eq!(caps(NUMCOLORS, device), -1);
    assert_eq!(caps(COLORRES, device), 24);
    assert_eq!(caps(SIZEPALETTE, device), 0);
    for (depth, colours, colorres) in [(1, 2, 18), (4, 16, 18), (8, -1, 18), (16, -1, 16), (24, -1, 24), (32, -1, 24)] {
        let device = Device { depth, ..device };
        assert_eq!(caps(NUMCOLORS, device), colours, "depth {depth}");
        assert_eq!(caps(COLORRES, device), colorres, "depth {depth}");
    }
}

#[test]
fn the_palette_bit_joins_the_raster_set_only_for_a_palettised_device() {
    assert_eq!(caps(RASTERCAPS, display()), 0xbe99);
    let palettised = Device { depth: 8, palette_size: 256, ..display() };
    assert_eq!(caps(RASTERCAPS, palettised), 0xbf99);
    assert_eq!(caps(SIZEPALETTE, palettised), 256);
}

#[test]
fn drawing_capability_words_are_the_reference_bit_sets() {
    let device = display();
    assert_eq!(caps(CURVECAPS, device), 0x01ff);
    assert_eq!(caps(LINECAPS, device), 0x00fe);
    assert_eq!(caps(POLYGONALCAPS, device), 0x00ff);
    assert_eq!(caps(TEXTCAPS, device), 0x79f7);
    assert_eq!(caps(CLIPCAPS, device), 0x0001);
}

#[test]
fn square_pixels_report_equal_aspects_and_their_rounded_diagonal() {
    let device = display();
    assert_eq!(caps(ASPECTX, device), 36);
    assert_eq!(caps(ASPECTY, device), 36);
    // hypot(36, 36) is 50.91, which rounds to 51.
    assert_eq!(caps(ASPECTXY, device), 51);
}

#[test]
fn printer_only_and_unnamed_capabilities_report_zero() {
    let device = display();
    for cap in [PHYSICALWIDTH, PHYSICALHEIGHT, PHYSICALOFFSETX, PHYSICALOFFSETY,
        SCALINGFACTORX, SCALINGFACTORY, BLTALIGNMENT, SHADEBLENDCAPS, COLORMGMTCAPS] {
        assert_eq!(caps(cap, device), 0, "cap {cap}");
    }
    for cap in [1, 3, 5, 46, 87, 92, 100, 122, 4096, -1, i32::MIN, i32::MAX] {
        assert_eq!(caps(cap, device), 0, "cap {cap}");
    }
}

#[test]
fn scaling_rounds_to_nearest_away_from_zero_and_reports_overflow() {
    assert_eq!(muldiv(3, 1, 2), 2);
    assert_eq!(muldiv(-3, 1, 2), -2);
    assert_eq!(muldiv(3, -1, 2), -2);
    assert_eq!(muldiv(1, 1, 3), 0);
    assert_eq!(muldiv(5, 1, 0), -1);
    // A negative divisor is normalised by negating both sides.
    assert_eq!(muldiv(3, 1, -2), -2);
    assert_eq!(muldiv(i32::MAX, 2, 1), -1);
}

#[test]
fn the_diagonal_rounds_at_the_exact_half() {
    // 2^2 + 2^2 = 8, whose root 2.828 rounds up.
    assert_eq!(hypot(2, 2), 3);
    assert_eq!(hypot(3, 4), 5);
    assert_eq!(hypot(0, 0), 0);
    // 1^2 + 1^2 = 2, whose root 1.414 rounds down.
    assert_eq!(hypot(1, 1), 1);
}
