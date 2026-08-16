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
pub const RGB24: u32 = 0x3342_4752;
pub const BGR24: u32 = 0x3352_4742;
pub const XRGB32: u32 = 0x3432_5842;
pub const ARGB32: u32 = 0x3432_4142;
pub const GREY: u32 = 0x5945_5247;
pub const Y10: u32 = 0x2030_3159;
pub const Y16: u32 = 0x2036_3159;
pub const NV12: u32 = 0x3231_564e;
pub const NV21: u32 = 0x3132_564e;
pub const NV16: u32 = 0x3631_564e;
pub const YUV420: u32 = 0x3231_5559;
pub const YVU420: u32 = 0x3231_5659;
pub const YUV422P: u32 = 0x5032_3234;
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
        GREY => SizeRule::Packed { bits_per_pixel: 8 },
        Y10 | Y16 => SizeRule::Packed { bits_per_pixel: 16 },
        YUYV | UYVY | YVYU | VYUY | RGB565 | RGB565X => SizeRule::Packed { bits_per_pixel: 16 },
        RGB24 | BGR24 => SizeRule::Packed { bits_per_pixel: 24 },
        XRGB32 | ARGB32 => SizeRule::Packed { bits_per_pixel: 32 },
        NV12 | NV21 | YUV420 | YVU420 => SizeRule::Planar { chroma_num: 1, chroma_den: 2 },
        NV16 | YUV422P => SizeRule::Planar { chroma_num: 1, chroma_den: 1 },
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
