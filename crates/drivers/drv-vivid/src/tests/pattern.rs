//! The test-pattern generator.

use crate::tpg::{self, Motion, Rgb, BARS};
use v4l2::uapi::fourcc;

#[test]
fn the_bars_divide_the_width_evenly_and_cover_every_column() {
    let width = 640u32;
    let mut runs = alloc::vec::Vec::new();
    let mut current = tpg::bar_at(0, width, 0);
    let mut length = 0u32;
    for x in 0..width {
        let c = tpg::bar_at(x, width, 0);
        if c == current { length += 1; } else { runs.push(length); current = c; length = 1; }
    }
    runs.push(length);
    assert_eq!(runs.len(), BARS.len(), "every bar must appear exactly once");
    for run in runs.iter() { assert_eq!(*run, width / BARS.len() as u32); }
    assert_eq!(tpg::bar_at(0, width, 0), BARS[0]);
    assert_eq!(tpg::bar_at(width - 1, width, 0), BARS[BARS.len() - 1]);
    // A column past the end is clamped rather than indexing out of the table.
    assert_eq!(tpg::bar_at(width + 100, width, 0), BARS[BARS.len() - 1]);
    // A zero width cannot divide by zero.
    let _ = tpg::bar_at(0, 0, 0);
}

#[test]
fn the_pattern_scrolls_one_bar_per_frame_and_wraps() {
    let width = 640u32;
    for shift in 0..BARS.len() as u32 {
        assert_eq!(tpg::bar_at(0, width, shift), BARS[shift as usize]);
    }
    // A full cycle returns to the start, so a viewer sees a repeating scroll
    // rather than the pattern walking off the table.
    assert_eq!(tpg::bar_at(0, width, BARS.len() as u32), BARS[0]);
    assert_eq!(tpg::bar_at(0, width, BARS.len() as u32 * 3 + 2), BARS[2]);
}

#[test]
fn luma_orders_the_bars_from_white_down_to_black() {
    let lumas: alloc::vec::Vec<u8> = BARS.iter().map(|c| tpg::luma(*c)).collect();
    assert_eq!(lumas[0], 255, "white is full luma");
    assert_eq!(*lumas.last().unwrap(), 0, "black is none");
    for pair in lumas.windows(2) {
        assert!(pair[0] > pair[1], "the bars must descend in luminance: {lumas:?}");
    }
    // A neutral colour carries no chroma offset.
    let grey = Rgb { r: 128, g: 128, b: 128 };
    assert_eq!(tpg::chroma_u(grey), 128);
    assert_eq!(tpg::chroma_v(grey), 128);
    // Blue pushes the blue-difference term up, red the red-difference term.
    assert!(tpg::chroma_u(Rgb { r: 0, g: 0, b: 255 }) > 200);
    assert!(tpg::chroma_v(Rgb { r: 255, g: 0, b: 0 }) > 200);
}

#[test]
fn a_rendered_line_is_exactly_the_formats_stride() {
    let width = 64u32;
    for format in [fourcc::YUYV, fourcc::UYVY, fourcc::YVYU, fourcc::VYUY,
                   fourcc::RGB24, fourcc::BGR24, fourcc::RGB565, fourcc::RGB565X,
                   fourcc::GREY, fourcc::Y10, fourcc::Y16, fourcc::Y16_BE] {
        let stride = fourcc::bytesperline(format, width) as usize;
        let mut line = alloc::vec![0u8; stride];
        assert_eq!(tpg::render_line(format, width, 0, &mut line), stride,
                   "format {format:#x} must fill its whole stride");
        // A buffer shorter than the stride is refused rather than partly
        // written, which would leave a torn line in the frame.
        let mut short = alloc::vec![0u8; stride - 1];
        assert_eq!(tpg::render_line(format, width, 0, &mut short), 0);
    }
    // A format this generator does not produce writes nothing.
    let mut line = alloc::vec![0u8; 1024];
    assert_eq!(tpg::render_line(fourcc::MJPEG, width, 0, &mut line), 0);
}

#[test]
fn rgb_and_bgr_are_the_same_pixels_in_the_opposite_order() {
    let width = 32u32;
    let mut rgb = alloc::vec![0u8; width as usize * 3];
    let mut bgr = alloc::vec![0u8; width as usize * 3];
    tpg::render_line(fourcc::RGB24, width, 0, &mut rgb);
    tpg::render_line(fourcc::BGR24, width, 0, &mut bgr);
    for x in 0..width as usize {
        assert_eq!(rgb[x * 3], bgr[x * 3 + 2]);
        assert_eq!(rgb[x * 3 + 1], bgr[x * 3 + 1]);
        assert_eq!(rgb[x * 3 + 2], bgr[x * 3]);
    }
    // The first pixel is the first bar's colour, unswapped.
    assert_eq!(&rgb[0..3], &[BARS[0].r, BARS[0].g, BARS[0].b]);
}

#[test]
fn xrgb_and_argb_use_the_reference_little_endian_byte_order() {
    let width = 8u32;
    let mut xrgb = alloc::vec![0u8; width as usize * 4];
    let mut argb = alloc::vec![0u8; width as usize * 4];
    tpg::render_line(fourcc::XRGB32, width, 0, &mut xrgb);
    tpg::render_line(fourcc::ARGB32, width, 0, &mut argb);
    assert_eq!(&xrgb[..4], &[0, 255, 255, 255]);
    assert_eq!(&argb[..4], &[255, 255, 255, 255]);
}

#[test]
fn packed_chroma_comes_from_the_left_pixel_of_each_pair() {
    let width = 16u32;
    let mut yuyv = alloc::vec![0u8; width as usize * 2];
    tpg::render_line(fourcc::YUYV, width, 0, &mut yuyv);
    for x in (0..width as usize).step_by(2) {
        let left = tpg::bar_at(x as u32, width, 0);
        let right = tpg::bar_at(x as u32 + 1, width, 0);
        assert_eq!(yuyv[x * 2], tpg::luma(left), "luma of the left pixel");
        assert_eq!(yuyv[x * 2 + 1], tpg::chroma_u(left), "blue difference of the pair");
        assert_eq!(yuyv[x * 2 + 2], tpg::luma(right), "luma of the right pixel");
        assert_eq!(yuyv[x * 2 + 3], tpg::chroma_v(left), "red difference of the pair");
    }
    // The other packing order carries the same values with luma second.
    let mut uyvy = alloc::vec![0u8; width as usize * 2];
    tpg::render_line(fourcc::UYVY, width, 0, &mut uyvy);
    for x in (0..width as usize).step_by(2) {
        assert_eq!(uyvy[x * 2], yuyv[x * 2 + 1]);
        assert_eq!(uyvy[x * 2 + 1], yuyv[x * 2]);
        assert_eq!(uyvy[x * 2 + 2], yuyv[x * 2 + 3]);
        assert_eq!(uyvy[x * 2 + 3], yuyv[x * 2 + 2]);
    }

    let mut yvyu = alloc::vec![0u8; width as usize * 2];
    tpg::render_line(fourcc::YVYU, width, 0, &mut yvyu);
    for x in (0..width as usize).step_by(2) {
        assert_eq!(yvyu[x * 2], yuyv[x * 2]);
        assert_eq!(yvyu[x * 2 + 1], yuyv[x * 2 + 3]);
        assert_eq!(yvyu[x * 2 + 2], yuyv[x * 2 + 2]);
        assert_eq!(yvyu[x * 2 + 3], yuyv[x * 2 + 1]);
    }
    let mut vyuy = alloc::vec![0u8; width as usize * 2];
    tpg::render_line(fourcc::VYUY, width, 0, &mut vyuy);
    for x in (0..width as usize).step_by(2) {
        assert_eq!(vyuy[x * 2], yuyv[x * 2 + 3]);
        assert_eq!(vyuy[x * 2 + 1], yuyv[x * 2]);
        assert_eq!(vyuy[x * 2 + 2], yuyv[x * 2 + 1]);
        assert_eq!(vyuy[x * 2 + 3], yuyv[x * 2 + 2]);
    }
}

#[test]
fn packed_rgb565_and_luma_formats_match_linux_byte_order() {
    let mut little = [0u8; 2];
    let mut big = [0u8; 2];
    tpg::render_line(fourcc::RGB565, 1, 0, &mut little);
    tpg::render_line(fourcc::RGB565X, 1, 0, &mut big);
    assert_eq!(little[0], big[1]);
    assert_eq!(little[1], big[0]);

    let mut y10 = [0u8; 2];
    let mut y16 = [0u8; 2];
    let mut y16be = [0u8; 2];
    tpg::render_line(fourcc::Y10, 1, 0, &mut y10);
    tpg::render_line(fourcc::Y16, 1, 0, &mut y16);
    tpg::render_line(fourcc::Y16_BE, 1, 0, &mut y16be);
    assert_eq!(y16[0], y16be[1]);
    assert_eq!(y16[1], y16be[0]);
    assert_eq!(y10[0], 0xfc);
    assert_eq!(y10[1], 0x03);
}

#[test]
fn single_planar_formats_write_the_linux_chroma_sections() {
    let (width, height) = (8u32, 4u32);
    let y_bytes = (width * height) as usize;
    let mut nv12 = alloc::vec![0u8; tpg::frame_bytes(fourcc::NV12, width, height)];
    let mut nv21 = alloc::vec![0u8; tpg::frame_bytes(fourcc::NV21, width, height)];
    assert_eq!(tpg::render_frame(fourcc::NV12, width, height, 0, &mut nv12), nv12.len());
    assert_eq!(tpg::render_frame(fourcc::NV21, width, height, 0, &mut nv21), nv21.len());
    // NV12/NV21 share the luma section and swap each interleaved chroma pair.
    assert_eq!(&nv12[..y_bytes], &nv21[..y_bytes]);
    assert_eq!(nv12[y_bytes], nv21[y_bytes + 1]);
    assert_eq!(nv12[y_bytes + 1], nv21[y_bytes]);

    let mut yuv420 = alloc::vec![0u8; tpg::frame_bytes(fourcc::YUV420, width, height)];
    let mut yvu420 = alloc::vec![0u8; tpg::frame_bytes(fourcc::YVU420, width, height)];
    assert_eq!(tpg::render_frame(fourcc::YUV420, width, height, 0, &mut yuv420), yuv420.len());
    assert_eq!(tpg::render_frame(fourcc::YVU420, width, height, 0, &mut yvu420), yvu420.len());
    assert_eq!(&yuv420[..y_bytes], &yvu420[..y_bytes]);
    let chroma = y_bytes / 4;
    assert_eq!(yuv420[y_bytes], yvu420[y_bytes + chroma]);
    assert_eq!(yuv420[y_bytes + chroma], yvu420[y_bytes]);
}

#[test]
fn a_whole_frame_is_stride_times_height_and_every_line_is_identical() {
    let (width, height) = (32u32, 8u32);
    let stride = fourcc::bytesperline(fourcc::RGB24, width) as usize;
    let mut frame = alloc::vec![0u8; tpg::frame_bytes(fourcc::RGB24, width, height)];
    let written = tpg::render_frame(fourcc::RGB24, width, height, 0, &mut frame);
    assert_eq!(written, stride * height as usize);
    let first = &frame[..stride];
    for row in 1..height as usize {
        assert_eq!(&frame[row * stride..(row + 1) * stride], first,
                   "vertical bars make every line the same");
    }
    // A destination too small for the whole frame is filled as far as it goes
    // rather than overrunning.
    let mut small = alloc::vec![0u8; stride * 3 + 1];
    assert_eq!(tpg::render_frame(fourcc::RGB24, width, height, 0, &mut small), stride * 3);
}

#[test]
fn every_declared_format_can_actually_be_rendered() {
    // A format the device advertises but the generator cannot produce would
    // deliver empty frames to whatever negotiated it.
    for desc in crate::tables::FORMATS {
        let width = 64u32;
        let stride = fourcc::bytesperline(desc.pixelformat, width) as usize;
        assert!(stride > 0, "{} has no stride", desc.description);
        let mut line = alloc::vec![0u8; stride];
        assert_eq!(tpg::render_line(desc.pixelformat, width, 0, &mut line), stride,
                   "{} is advertised but cannot be rendered", desc.description);
    }
}

#[test]
fn moving_object_changes_position_with_the_frame_sequence() {
    let (width, height) = (96u32, 64u32);
    let stride = fourcc::bytesperline(fourcc::RGB24, width) as usize;
    let mut first = alloc::vec![0u8; stride];
    let mut next = alloc::vec![0u8; stride];
    let motion = Motion { horizontal: 3, vertical: 0 };
    tpg::render_line_at(fourcc::RGB24, width, height, height / 2, 0, 0, motion, &mut first);
    tpg::render_line_at(fourcc::RGB24, width, height, height / 2, 0, 1, motion, &mut next);
    assert_ne!(first, next, "a moving-object control must affect successive frames");
    assert!(first.chunks_exact(3).any(|p| p == [128, 128, 128]),
            "the test object must be visible in the frame");
}
