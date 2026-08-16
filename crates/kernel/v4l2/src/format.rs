//! Pixel-format description and the negotiation every `TRY_FMT`/`S_FMT`
//! performs.
//!
//! The device core owns the parts of negotiation that are the same for every
//! driver: sanitising the colorimetry words a caller left invalid, clamping a
//! requested size into the driver's declared frame sizes, and deriving
//! `bytesperline`/`sizeimage` from the chosen format. A driver supplies the
//! table of what it can produce; it never re-implements the arithmetic.

use crate::uapi::flags;
use crate::uapi::fourcc;

/// One `v4l2_pix_format`, in the fields this core reasons about.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PixFormat {
    pub width: u32,
    pub height: u32,
    pub pixelformat: u32,
    pub field: u32,
    pub bytesperline: u32,
    pub sizeimage: u32,
    pub colorspace: u32,
    pub flags: u32,
    pub enc: u32,
    pub quantization: u32,
    pub xfer_func: u32,
}

impl PixFormat {
    /// A zeroed format with the ABI's "let the device decide" selectors.
    /// # C: O(1)
    pub const fn empty() -> Self {
        PixFormat {
            width: 0, height: 0, pixelformat: 0, field: flags::FIELD_ANY,
            bytesperline: 0, sizeimage: 0, colorspace: flags::COLORSPACE_DEFAULT,
            flags: 0, enc: flags::YCBCR_ENC_DEFAULT,
            quantization: flags::QUANTIZATION_DEFAULT, xfer_func: flags::XFER_FUNC_DEFAULT,
        }
    }
}

/// A rational, as `v4l2_fract` carries frame intervals.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Fract { pub numerator: u32, pub denominator: u32 }

/// One frame size a device can produce.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct FrameSize { pub width: u32, pub height: u32 }

/// One entry of a driver's format table.
#[derive(Copy, Clone, Debug)]
pub struct FormatDesc {
    pub pixelformat: u32,
    pub description: &'static str,
    /// `V4L2_FMT_FLAG_*`. A compressed format must carry
    /// `FMT_FLAG_COMPRESSED`, since that is how an application learns
    /// `bytesperline` will be zero.
    pub flags: u32,
    /// Discrete frame sizes, largest first is not required — the clamp picks
    /// by closeness, not by order.
    pub sizes: &'static [FrameSize],
    /// Frame intervals offered at every size.
    pub intervals: &'static [Fract],
    /// `sizeimage` for a compressed format, where no product describes it.
    pub compressed_sizeimage: u32,
}

/// Colorimetry words carry a `_DEFAULT` selector meaning "the device decides".
/// A caller may also pass a value outside the enumeration; the reference
/// resets such a word to its default rather than refusing the call, so a
/// program that zeroed part of the structure still gets a working format.
/// # C: O(1)
pub fn sanitize_colorimetry(f: &mut PixFormat) {
    if f.colorspace > flags::COLORSPACE_RAW { f.colorspace = flags::COLORSPACE_DEFAULT; }
    if f.xfer_func > flags::XFER_FUNC_NONE { f.xfer_func = flags::XFER_FUNC_DEFAULT; }
    if f.quantization > flags::QUANTIZATION_LIM_RANGE { f.quantization = flags::QUANTIZATION_DEFAULT; }
    // `ycbcr_enc` and `hsv_enc` share one byte; the largest defined selector
    // across both is the SMPTE 240M encoding at 8.
    const ENC_MAX: u32 = 8;
    if f.enc > ENC_MAX { f.enc = flags::YCBCR_ENC_DEFAULT; }
}

/// Pick the entry of `table` matching `pixelformat`, falling back to the first
/// entry — a caller that asked for a format the device does not produce gets
/// the device's preferred one rather than an error, which is what makes
/// `TRY_FMT` a negotiation instead of a test. # C: O(table)
pub fn pick_format(table: &'static [FormatDesc], pixelformat: u32) -> Option<&'static FormatDesc> {
    if table.is_empty() { return None; }
    table.iter().find(|d| d.pixelformat == pixelformat).or_else(|| table.first())
}

/// Nearest declared frame size to the request, measured by total pixel-count
/// difference so neither axis dominates. Ties go to the earlier entry, which
/// makes the choice deterministic for a table listing two equidistant sizes.
/// # C: O(sizes)
pub fn clamp_size(sizes: &[FrameSize], width: u32, height: u32) -> Option<FrameSize> {
    let want = (width as u64) * (height as u64);
    let mut best: Option<(u64, FrameSize)> = None;
    for size in sizes {
        let have = (size.width as u64) * (size.height as u64);
        let distance = have.abs_diff(want);
        match best {
            Some((d, _)) if d <= distance => {}
            _ => best = Some((distance, *size)),
        }
    }
    best.map(|(_, s)| s)
}

/// Nearest declared frame interval to the request. An interval of zero in
/// either term is meaningless, so it selects the device's first (preferred)
/// interval rather than dividing by zero. # C: O(intervals)
pub fn clamp_interval(intervals: &[Fract], want: Fract) -> Option<Fract> {
    let first = *intervals.first()?;
    if want.numerator == 0 || want.denominator == 0 { return Some(first); }
    // Compare as fixed-point microseconds per frame, which keeps the ordering
    // exact for every interval a camera declares without needing a division
    // that can round two distinct intervals onto the same value.
    let want_us = (want.numerator as u64).saturating_mul(1_000_000) / want.denominator as u64;
    let mut best = (u64::MAX, first);
    for interval in intervals {
        if interval.denominator == 0 { continue; }
        let have_us = (interval.numerator as u64).saturating_mul(1_000_000) / interval.denominator as u64;
        let distance = have_us.abs_diff(want_us);
        if distance < best.0 { best = (distance, *interval); }
    }
    Some(best.1)
}

/// Field order the device delivers. A capture device that produces whole
/// progressive frames answers `NONE` for both `ANY` and any interlaced order
/// the caller guessed at, because the reference requires `TRY_FMT` to report
/// what will actually be delivered rather than echoing the request.
/// # C: O(1)
pub fn resolve_field(requested: u32, progressive: bool) -> u32 {
    if progressive { return flags::FIELD_NONE; }
    match requested {
        flags::FIELD_ANY => flags::FIELD_INTERLACED,
        f if f <= flags::FIELD_INTERLACED_BT => f,
        _ => flags::FIELD_INTERLACED,
    }
}

/// The whole `TRY_FMT` negotiation: choose a format the device produces, clamp
/// the size, settle the field order and colorimetry, and derive the two size
/// fields. `f` comes back describing exactly what a subsequent `S_FMT` of the
/// same structure would install — the reference's rule that `TRY_FMT` and
/// `S_FMT` differ only in whether the result is kept.
/// # C: O(table + sizes)
pub fn try_fmt(table: &'static [FormatDesc], f: &mut PixFormat, progressive: bool) -> bool {
    let Some(desc) = pick_format(table, f.pixelformat) else { return false };
    f.pixelformat = desc.pixelformat;
    if let Some(size) = clamp_size(desc.sizes, f.width, f.height) {
        f.width = size.width;
        f.height = size.height;
    }
    f.field = resolve_field(f.field, progressive);
    sanitize_colorimetry(f);
    if f.colorspace == flags::COLORSPACE_DEFAULT { f.colorspace = flags::COLORSPACE_SRGB; }
    f.bytesperline = fourcc::bytesperline(desc.pixelformat, f.width);
    f.sizeimage = fourcc::sizeimage(desc.pixelformat, f.width, f.height, desc.compressed_sizeimage);
    // `priv` is not modelled: the reference only honours it when the caller
    // set the extended-format cookie, and a device that reports
    // `V4L2_CAP_EXT_PIX_FORMAT` must zero the tail regardless.
    f.flags = 0;
    true
}
