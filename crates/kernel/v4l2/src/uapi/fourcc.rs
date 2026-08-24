//! `V4L2_PIX_FMT_*` four-character codes and the image-size arithmetic that
//! depends on them.
//!
//! A fourcc is the little-endian packing of four ASCII bytes, so `'Y','U','Y','V'`
//! is `0x5659_5559`. The values are written expanded; `from_chars` exists for
//! tests to re-derive them from the characters the standard names.

/// Pack four characters into a fourcc the way the ABI orders them. # C: O(1)
pub const fn from_chars(a: u8, b: u8, c: u8, d: u8) -> u32 {
    (a as u32) | ((b as u32) << 8) | ((c as u32) << 16) | ((d as u32) << 24)
}

pub const YUYV: u32 = 0x5659_5559;
pub const UYVY: u32 = 0x5956_5955;
pub const YVYU: u32 = 0x5559_5659;
pub const VYUY: u32 = 0x5955_5956;
pub const RGB565: u32 = 0x5042_4752;
pub const RGB565X: u32 = 0x5242_4752;
pub const RGB444: u32 = 0x3434_3452;
pub const ARGB444: u32 = 0x3231_5241;
pub const XRGB444: u32 = 0x3231_5258;
pub const RGBA444: u32 = 0x3231_4152;
pub const RGBX444: u32 = 0x3231_5852;
pub const ABGR444: u32 = 0x3231_4241;
pub const XBGR444: u32 = 0x3231_4258;
pub const BGRA444: u32 = 0x3231_4147;
pub const BGRX444: u32 = 0x3231_5842;
pub const RGB555: u32 = 0x4f42_4752;
pub const ARGB555: u32 = 0x3531_5241;
pub const XRGB555: u32 = 0x3531_5258;
pub const RGBA555: u32 = 0x3531_4152;
pub const RGBX555: u32 = 0x3531_5852;
pub const ABGR555: u32 = 0x3531_4241;
pub const XBGR555: u32 = 0x3531_4258;
pub const BGRA555: u32 = 0x3531_4142;
pub const BGRX555: u32 = 0x3531_5842;
pub const RGB555X: u32 = 0x5142_4752;
pub const ARGB555X: u32 = 0xb531_5241;
pub const XRGB555X: u32 = 0xb531_5258;
pub const YUV555: u32 = 0x4f56_5559;
pub const YUV565: u32 = 0x5056_5559;
pub const YUV444: u32 = 0x3434_3459;
pub const YUV32: u32 = 0x3456_5559;
pub const AYUV32: u32 = 0x5655_5941;
pub const XYUV32: u32 = 0x5655_5958;
pub const VUYA32: u32 = 0x4159_5556;
pub const VUYX32: u32 = 0x5859_5556;
pub const YUVA32: u32 = 0x4156_5559;
pub const YUVX32: u32 = 0x5856_5559;
pub const RGB332: u32 = 0x3142_4752;
pub const RGB24: u32 = 0x3342_4752;
pub const BGR24: u32 = 0x3352_4742;
pub const XRGB32: u32 = 0x3432_5842;
pub const ARGB32: u32 = 0x3432_4142;
pub const BGR32: u32 = 0x3452_4742;
pub const ABGR32: u32 = 0x3432_5241;
pub const XBGR32: u32 = 0x3432_5258;
pub const BGRA32: u32 = 0x3432_4152;
pub const BGRX32: u32 = 0x3432_5852;
pub const RGB32: u32 = 0x3442_4752;
pub const RGBA32: u32 = 0x3432_4241;
pub const RGBX32: u32 = 0x3432_4258;
pub const HSV24: u32 = 0x3356_5348;
pub const HSV32: u32 = 0x3456_5348;
pub const SBGGR8: u32 = 0x3138_4142;
pub const SGBRG8: u32 = 0x4752_4247;
pub const SGRBG8: u32 = 0x4742_5247;
pub const SRGGB8: u32 = 0x4247_4752;
pub const GREY: u32 = 0x5945_5247;
pub const Y10: u32 = 0x2030_3159;
pub const Y12: u32 = 0x2032_3159;
pub const Y16: u32 = 0x2036_3159;
pub const Y16_BE: u32 = 0x5036_3159;
pub const NV12: u32 = 0x3231_564e;
pub const NV21: u32 = 0x3132_564e;
pub const NV16: u32 = 0x3631_564e;
pub const NV61: u32 = 0x3136_564e;
pub const NV24: u32 = 0x3432_564e;
pub const NV42: u32 = 0x3234_564e;
pub const YUV420: u32 = 0x3231_5559;
pub const YVU420: u32 = 0x3231_5659;
pub const YUV422P: u32 = 0x5032_3234;
pub const NV12M: u32 = 0x3231_4d4e;
pub const NV21M: u32 = 0x3132_4d4e;
pub const YUV420M: u32 = 0x3231_4d59;
pub const YVU420M: u32 = 0x3132_4d59;
pub const YUV422M: u32 = 0x3631_4d59;
pub const NV16M: u32 = 0x3631_4d4e;
pub const NV61M: u32 = 0x3136_4d4e;
pub const YVU422M: u32 = 0x3136_4d59;
pub const YUV444M: u32 = 0x3432_4d59;
pub const YVU444M: u32 = 0x3234_4d59;
pub const MJPEG: u32 = 0x4750_4a4d;
pub const JPEG: u32 = 0x4745_504a;
pub const H264: u32 = 0x3436_3248;
pub const H264_NO_SC: u32 = 0x3143_5641;
pub const HEVC: u32 = 0x4356_4548;
pub const VP8: u32 = 0x3038_5056;
pub const VP9: u32 = 0x3039_5056;

/// How the image size of one frame is computed for a pixel format.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SizeRule {
    /// Uncompressed, one plane, `bytesperline = width * bpp / 8` and
    /// `sizeimage = bytesperline * height`.
    Packed { bits_per_pixel: u32 },
    /// Planar with a chroma plane appended: luma is `width * height` bytes and
    /// the chroma planes together add `width * height * num / den`.
    Planar { chroma_num: u32, chroma_den: u32 },
    /// Compressed bytestream: `bytesperline` is zero and `sizeimage` is a
    /// driver-chosen maximum rather than a computed product.
    Compressed,
}

/// Size rule for a pixel format, or `None` for a format this core does not
/// describe. # C: O(1)
pub fn size_rule(pixelformat: u32) -> Option<SizeRule> {
    Some(match pixelformat {
        GREY | SBGGR8 | SGBRG8 | SGRBG8 | SRGGB8 => SizeRule::Packed { bits_per_pixel: 8 },
        RGB332 => SizeRule::Packed { bits_per_pixel: 8 },
        Y10 | Y12 | Y16 | Y16_BE => SizeRule::Packed { bits_per_pixel: 16 },
        YUYV | UYVY | YVYU | VYUY | RGB565 | RGB565X |
        RGB444 | ARGB444 | XRGB444 | RGBA444 | RGBX444 | ABGR444 | XBGR444 | BGRA444 | BGRX444 |
        RGB555 | ARGB555 | XRGB555 | RGBA555 | RGBX555 | ABGR555 | XBGR555 | BGRA555 | BGRX555 |
        RGB555X | ARGB555X | XRGB555X | YUV555 | YUV565 | YUV444 =>
            SizeRule::Packed { bits_per_pixel: 16 },
        RGB24 | BGR24 | HSV24 => SizeRule::Packed { bits_per_pixel: 24 },
        XRGB32 | ARGB32 | BGR32 | ABGR32 | XBGR32 | BGRA32 | BGRX32 |
        RGB32 | RGBA32 | RGBX32 | HSV32 | YUV32 | AYUV32 | XYUV32 | VUYA32 | VUYX32 | YUVA32 | YUVX32 =>
            SizeRule::Packed { bits_per_pixel: 32 },
        NV12 | NV21 | YUV420 | YVU420 | NV12M | NV21M | YUV420M | YVU420M =>
            SizeRule::Planar { chroma_num: 1, chroma_den: 2 },
        NV16 | NV61 | YUV422P | YUV422M | NV16M | NV61M | YVU422M =>
            SizeRule::Planar { chroma_num: 1, chroma_den: 1 },
        NV24 | NV42 | YUV444M | YVU444M => SizeRule::Planar { chroma_num: 2, chroma_den: 1 },
        MJPEG | JPEG | H264 | H264_NO_SC | HEVC | VP8 | VP9 => SizeRule::Compressed,
        _ => return None,
    })
}

/// Is this a compressed bytestream format? # C: O(1)
pub fn is_compressed(pixelformat: u32) -> bool {
    matches!(size_rule(pixelformat), Some(SizeRule::Compressed))
}

/// `bytesperline` for one line of `width` pixels: zero for a compressed
/// bytestream, which has no line stride. # C: O(1)
pub fn bytesperline(pixelformat: u32, width: u32) -> u32 {
    match size_rule(pixelformat) {
        Some(SizeRule::Packed { bits_per_pixel }) => width.saturating_mul(bits_per_pixel) / 8,
        // A planar format's stride describes the LUMA plane only, one byte per
        // pixel; the chroma planes follow it and are counted by `sizeimage`.
        Some(SizeRule::Planar { .. }) => width,
        _ => 0,
    }
}

/// Total bytes one frame occupies. A compressed format has no product to
/// compute, so the caller's `fallback` (the driver's declared maximum) stands.
/// # C: O(1)
pub fn sizeimage(pixelformat: u32, width: u32, height: u32, fallback: u32) -> u32 {
    match size_rule(pixelformat) {
        Some(SizeRule::Packed { .. }) => bytesperline(pixelformat, width).saturating_mul(height),
        Some(SizeRule::Planar { chroma_num, chroma_den }) => {
            let luma = width.saturating_mul(height);
            luma.saturating_add(luma.saturating_mul(chroma_num) / chroma_den)
        }
        _ => fallback,
    }
}
