//! `NtGdiGetDeviceCaps`: the raster display driver's capability table.
//!
//! The reference resolves the device context, then asks its driver stack; the
//! display driver answers only the palette size and defers every other index to
//! the null driver's table below. A memory device context selects no separate
//! driver, so it reports the same display geometry, depth and density.
pub(crate) const ORDINAL: u64 = 0x11f4;

pub(crate) const DRIVERVERSION: i32 = 0;
pub(crate) const TECHNOLOGY: i32 = 2;
pub(crate) const HORZSIZE: i32 = 4;
pub(crate) const VERTSIZE: i32 = 6;
pub(crate) const HORZRES: i32 = 8;
pub(crate) const VERTRES: i32 = 10;
pub(crate) const BITSPIXEL: i32 = 12;
pub(crate) const PLANES: i32 = 14;
pub(crate) const NUMBRUSHES: i32 = 16;
pub(crate) const NUMPENS: i32 = 18;
pub(crate) const NUMMARKERS: i32 = 20;
pub(crate) const NUMFONTS: i32 = 22;
pub(crate) const NUMCOLORS: i32 = 24;
pub(crate) const PDEVICESIZE: i32 = 26;
pub(crate) const CURVECAPS: i32 = 28;
pub(crate) const LINECAPS: i32 = 30;
pub(crate) const POLYGONALCAPS: i32 = 32;
pub(crate) const TEXTCAPS: i32 = 34;
pub(crate) const CLIPCAPS: i32 = 36;
pub(crate) const RASTERCAPS: i32 = 38;
pub(crate) const ASPECTX: i32 = 40;
pub(crate) const ASPECTY: i32 = 42;
pub(crate) const ASPECTXY: i32 = 44;
pub(crate) const LOGPIXELSX: i32 = 88;
pub(crate) const LOGPIXELSY: i32 = 90;
pub(crate) const CAPS1: i32 = 94;
pub(crate) const SIZEPALETTE: i32 = 104;
pub(crate) const NUMRESERVED: i32 = 106;
pub(crate) const COLORRES: i32 = 108;
pub(crate) const PHYSICALWIDTH: i32 = 110;
pub(crate) const PHYSICALHEIGHT: i32 = 111;
pub(crate) const PHYSICALOFFSETX: i32 = 112;
pub(crate) const PHYSICALOFFSETY: i32 = 113;
pub(crate) const SCALINGFACTORX: i32 = 114;
pub(crate) const SCALINGFACTORY: i32 = 115;
pub(crate) const VREFRESH: i32 = 116;
pub(crate) const DESKTOPVERTRES: i32 = 117;
pub(crate) const DESKTOPHORZRES: i32 = 118;
pub(crate) const BLTALIGNMENT: i32 = 119;
pub(crate) const SHADEBLENDCAPS: i32 = 120;
pub(crate) const COLORMGMTCAPS: i32 = 121;

/// A raster display, the only technology this personality drives.
pub(crate) const DT_RASDISPLAY: i32 = 1;
/// Version word a GDI display driver reports.
const DRIVER_VERSION: i32 = 0x4000;
/// Curves: circles, pies, chords, ellipses, wide, styled, wide-styled, interiors, round rectangles.
const CURVE_CAPS: i32 = 0x01ff;
/// Lines: polylines, markers, poly-markers, wide, styled, wide-styled, interiors.
const LINE_CAPS: i32 = 0x00fe;
/// Polygons: polygons, rectangles, winding fill, scanlines, wide, styled, wide-styled, interiors.
const POLYGONAL_CAPS: i32 = 0x00ff;
/// Text: character and stroke output, arbitrary rotation, independent scaling,
/// double/integer/continuous scaling, underline, strikeout, raster and vector faces.
const TEXT_CAPS: i32 = 0x79f7;
/// Clipping to rectangles only.
const CLIP_CAPS: i32 = 0x0001;
/// Raster: bit blits, 64K bitmaps, GDI 2.0 output, device-independent bitmaps,
/// DIB-to-device, big fonts, stretch blits, flood fill, stretch DIB, device bitmaps.
const RASTER_CAPS: i32 = 0xbe99;
/// The palette bit joins the raster set only when the device has a palette.
const RC_PALETTE: i32 = 0x0100;
/// Relative pixel width and height of the device's aspect ratio.
const ASPECT: i32 = 36;
/// Reserved system palette entries.
const RESERVED_PALETTE_ENTRIES: i32 = 20;
/// Tenths of a millimetre per inch, for the physical size a resolution and a density imply.
const TENTHS_MM_PER_INCH: i32 = 254;
/// A device with no monitor still reports the reference's fallback resolution.
const FALLBACK_HORZRES: i32 = 640;
const FALLBACK_VERTRES: i32 = 480;
/// A display whose driver reports no frequency still retires frames.
const FALLBACK_VREFRESH: i32 = 1;
/// Palettised depths report their exact colour count; deeper devices report -1.
const PALETTISED_DEPTH: i32 = 4;
/// Colour resolution saturates at the depth a device actually resolves.
const MAX_COLORRES: i32 = 24;
/// Depths of eight bits and below resolve through an eighteen-bit palette DAC.
const PALETTE_COLORRES: i32 = 18;
const PALETTE_DEPTH: i32 = 8;
/// Unbounded object counts report -1, not a limit.
const UNLIMITED: i32 = -1;

/// Display state the capability table reads; every field has one canonical owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Device {
    /// Primary monitor resolution.
    pub screen: (i32, i32),
    /// Virtual screen resolution spanning every monitor.
    pub desktop: (i32, i32),
    pub dpi: i32,
    pub depth: i32,
    pub palette_size: i32,
    pub refresh_hz: i32,
}

/// An index the table does not name reports zero, as does a device context the
/// handle owner cannot resolve. # C: O(1)
pub(crate) fn caps(cap: i32, device: Device) -> i32 {
    let horzres = if device.screen.0 > 0 { device.screen.0 } else { FALLBACK_HORZRES };
    let vertres = if device.screen.1 > 0 { device.screen.1 } else { FALLBACK_VERTRES };
    match cap {
        DRIVERVERSION => DRIVER_VERSION,
        TECHNOLOGY => DT_RASDISPLAY,
        HORZSIZE => muldiv(horzres, TENTHS_MM_PER_INCH, device.dpi.saturating_mul(10)),
        VERTSIZE => muldiv(vertres, TENTHS_MM_PER_INCH, device.dpi.saturating_mul(10)),
        HORZRES => horzres,
        VERTRES => vertres,
        BITSPIXEL => device.depth,
        PLANES => 1,
        NUMBRUSHES | NUMPENS => UNLIMITED,
        NUMMARKERS | NUMFONTS | PDEVICESIZE | CAPS1 => 0,
        NUMCOLORS => if device.depth > PALETTISED_DEPTH { UNLIMITED } else { 1i32.wrapping_shl(device.depth as u32) },
        CURVECAPS => CURVE_CAPS,
        LINECAPS => LINE_CAPS,
        POLYGONALCAPS => POLYGONAL_CAPS,
        TEXTCAPS => TEXT_CAPS,
        CLIPCAPS => CLIP_CAPS,
        RASTERCAPS => RASTER_CAPS | if device.palette_size != 0 { RC_PALETTE } else { 0 },
        ASPECTX | ASPECTY => ASPECT,
        ASPECTXY => hypot(ASPECT, ASPECT),
        LOGPIXELSX | LOGPIXELSY => device.dpi,
        SIZEPALETTE => device.palette_size,
        NUMRESERVED => RESERVED_PALETTE_ENTRIES,
        COLORRES => if device.depth <= PALETTE_DEPTH { PALETTE_COLORRES } else { MAX_COLORRES.min(device.depth) },
        PHYSICALWIDTH | PHYSICALHEIGHT | PHYSICALOFFSETX | PHYSICALOFFSETY => 0,
        SCALINGFACTORX | SCALINGFACTORY => 0,
        VREFRESH => if device.refresh_hz > 0 { device.refresh_hz } else { FALLBACK_VREFRESH },
        DESKTOPHORZRES => device.desktop.0,
        DESKTOPVERTRES => device.desktop.1,
        BLTALIGNMENT | SHADEBLENDCAPS | COLORMGMTCAPS => 0,
        _ => 0,
    }
}

/// Scale rounding to nearest, away from zero, reporting -1 on a zero divisor or
/// a result outside the signed 32-bit range. # C: O(1)
fn muldiv(a: i32, b: i32, c: i32) -> i32 {
    if c == 0 { return -1; }
    let (a, c) = if c < 0 { (-i64::from(a), -i64::from(c)) } else { (i64::from(a), i64::from(c)) };
    let product = a * i64::from(b);
    let ret = if product >= 0 { (product + c / 2) / c } else { (product - c / 2) / c };
    if ret > i64::from(i32::MAX) || ret < -i64::from(i32::MAX) { return -1; }
    ret as i32
}

/// Diagonal aspect: the pixel-count hypotenuse rounded to the nearest whole
/// unit, matching the reference's floating-point half-up rounding. # C: O(1)
fn hypot(x: i32, y: i32) -> i32 {
    let square = i64::from(x) * i64::from(x) + i64::from(y) * i64::from(y);
    let mut root: i64 = 0;
    while (root + 1) * (root + 1) <= square { root += 1; }
    // The reference truncates sqrt + 0.5, which rounds the root up whenever its
    // fractional part reaches one half: (root + 0.5)^2 <= square.
    if 4 * root * root + 4 * root + 1 <= 4 * square { root += 1; }
    root as i32
}

#[cfg(target_os = "oxide-kernel")]
#[path = "device_caps/kernel.rs"]
pub(crate) mod kernel;

#[cfg(test)]
#[path = "tests/device_caps.rs"]
mod tests;
