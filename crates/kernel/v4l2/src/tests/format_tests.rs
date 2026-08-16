//! Format negotiation, size clamping and image-size arithmetic.

use super::harness::{FakeCtx, Rig, FORMATS, INTERVALS, SIZES};
use crate::format::{self, Fract, FrameSize, PixFormat};
use crate::uapi::ioctl::*;
use crate::uapi::layout as l;
use crate::uapi::{flags, fourcc};
use crate::usermem::{r32, w32};
use syscall::errno::Errno;

#[test]
fn image_size_follows_the_format_not_the_caller() {
    // Packed formats are a product of stride and height.
    assert_eq!(fourcc::bytesperline(fourcc::YUYV, 640), 1280);
    assert_eq!(fourcc::sizeimage(fourcc::YUYV, 640, 480, 0), 1280 * 480);
    assert_eq!(fourcc::bytesperline(fourcc::RGB24, 640), 1920);
    assert_eq!(fourcc::sizeimage(fourcc::RGB24, 640, 480, 0), 1920 * 480);
    assert_eq!(fourcc::bytesperline(fourcc::GREY, 640), 640);
    assert_eq!(fourcc::sizeimage(fourcc::GREY, 640, 480, 0), 640 * 480);
    assert_eq!(fourcc::bytesperline(fourcc::XRGB32, 640), 2560);
    // A planar format's stride describes the luma plane and its size adds the
    // chroma planes.
    assert_eq!(fourcc::bytesperline(fourcc::NV12, 640), 640);
    assert_eq!(fourcc::sizeimage(fourcc::NV12, 640, 480, 0), 640 * 480 * 3 / 2);
    assert_eq!(fourcc::sizeimage(fourcc::NV16, 640, 480, 0), 640 * 480 * 2);
    // A compressed bytestream has no stride and takes the driver's maximum.
    assert!(fourcc::is_compressed(fourcc::MJPEG));
    assert_eq!(fourcc::bytesperline(fourcc::MJPEG, 640), 0);
    assert_eq!(fourcc::sizeimage(fourcc::MJPEG, 640, 480, 4096), 4096);
}

#[test]
fn try_fmt_clamps_to_the_nearest_declared_size() {
    let mut f = PixFormat { width: 700, height: 500, pixelformat: fourcc::YUYV,
                            ..PixFormat::empty() };
    assert!(format::try_fmt(FORMATS, &mut f, true));
    assert_eq!((f.width, f.height), (640, 480));
    let mut small = PixFormat { width: 1, height: 1, pixelformat: fourcc::YUYV,
                                ..PixFormat::empty() };
    assert!(format::try_fmt(FORMATS, &mut small, true));
    assert_eq!((small.width, small.height), (320, 240));
    let mut huge = PixFormat { width: 4096, height: 4096, pixelformat: fourcc::YUYV,
                               ..PixFormat::empty() };
    assert!(format::try_fmt(FORMATS, &mut huge, true));
    assert_eq!((huge.width, huge.height), (1280, 720));
}

#[test]
fn try_fmt_substitutes_the_preferred_format_for_an_unknown_one() {
    let mut f = PixFormat { width: 640, height: 480, pixelformat: fourcc::VP9,
                            ..PixFormat::empty() };
    assert!(format::try_fmt(FORMATS, &mut f, true));
    assert_eq!(f.pixelformat, FORMATS[0].pixelformat);
    assert_eq!(f.sizeimage, 640 * 480 * 2);
}

#[test]
fn try_fmt_settles_field_order_and_colorimetry() {
    let mut f = PixFormat { width: 640, height: 480, pixelformat: fourcc::YUYV,
                            field: flags::FIELD_INTERLACED, colorspace: 250,
                            quantization: 99, xfer_func: 99, enc: 99,
                            ..PixFormat::empty() };
    assert!(format::try_fmt(FORMATS, &mut f, true));
    // A progressive device reports whole frames whatever was asked for.
    assert_eq!(f.field, flags::FIELD_NONE);
    assert_eq!(f.colorspace, flags::COLORSPACE_SRGB);
    assert_eq!(f.quantization, flags::QUANTIZATION_DEFAULT);
    assert_eq!(f.xfer_func, flags::XFER_FUNC_DEFAULT);
    assert_eq!(f.enc, flags::YCBCR_ENC_DEFAULT);
    // An interlaced device keeps the order it was asked for.
    let mut g = PixFormat { width: 640, height: 480, pixelformat: fourcc::YUYV,
                            field: flags::FIELD_SEQ_TB, ..PixFormat::empty() };
    assert!(format::try_fmt(FORMATS, &mut g, false));
    assert_eq!(g.field, flags::FIELD_SEQ_TB);
    let mut h = PixFormat { width: 640, height: 480, pixelformat: fourcc::YUYV,
                            field: flags::FIELD_ANY, ..PixFormat::empty() };
    assert!(format::try_fmt(FORMATS, &mut h, false));
    assert_eq!(h.field, flags::FIELD_INTERLACED);
}

#[test]
fn interval_clamping_picks_the_closest_declared_rate() {
    // 25 fps is nearer 30 than 15.
    let want = Fract { numerator: 1, denominator: 25 };
    assert_eq!(format::clamp_interval(INTERVALS, want), Some(INTERVALS[0]));
    // 12 fps is nearer 15 than 5.
    let slow = Fract { numerator: 1, denominator: 12 };
    assert_eq!(format::clamp_interval(INTERVALS, slow), Some(INTERVALS[1]));
    // A meaningless request takes the device's preferred rate.
    let zero = Fract { numerator: 0, denominator: 0 };
    assert_eq!(format::clamp_interval(INTERVALS, zero), Some(INTERVALS[0]));
    assert_eq!(format::clamp_interval(&[], want), None);
}

#[test]
fn size_clamping_is_deterministic_between_equidistant_entries() {
    let sizes = [FrameSize { width: 100, height: 100 }, FrameSize { width: 300, height: 300 }];
    // 100x100 = 10_000 and 300x300 = 90_000; a request of 50_000 pixels is
    // 40_000 from each, and the earlier entry wins.
    let midpoint = format::clamp_size(&sizes, 500, 100);
    assert_eq!(midpoint, Some(sizes[0]));
}

#[test]
fn try_fmt_and_s_fmt_agree_and_s_fmt_installs() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    let mut arg = alloc::vec![0u8; l::FORMAT_SIZE];
    w32(&mut arg, l::FORMAT_TYPE, flags::BUF_TYPE_VIDEO_CAPTURE);
    w32(&mut arg, l::FORMAT_FMT + l::PIX_WIDTH, 700);
    w32(&mut arg, l::FORMAT_FMT + l::PIX_HEIGHT, 500);
    w32(&mut arg, l::FORMAT_FMT + l::PIX_PIXELFORMAT, fourcc::RGB24);
    let mut tried = arg.clone();
    rig.call(VIDIOC_TRY_FMT, &mut tried, &ctx).expect("try_fmt succeeds");
    let mut set = arg.clone();
    rig.call(VIDIOC_S_FMT, &mut set, &ctx).expect("s_fmt succeeds");
    assert_eq!(tried, set, "try_fmt must predict s_fmt exactly");
    let mut got = alloc::vec![0u8; l::FORMAT_SIZE];
    w32(&mut got, l::FORMAT_TYPE, flags::BUF_TYPE_VIDEO_CAPTURE);
    rig.call(VIDIOC_G_FMT, &mut got, &ctx).expect("g_fmt succeeds");
    assert_eq!(r32(&got, l::FORMAT_FMT + l::PIX_WIDTH), 640);
    assert_eq!(r32(&got, l::FORMAT_FMT + l::PIX_PIXELFORMAT), fourcc::RGB24);
    assert_eq!(r32(&got, l::FORMAT_FMT + l::PIX_BYTESPERLINE), 1920);
    assert_eq!(r32(&got, l::FORMAT_FMT + l::PIX_SIZEIMAGE), 1920 * 480);
}

#[test]
fn s_fmt_is_refused_once_buffers_exist() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    rig.reqbufs(2, &ctx).expect("buffers allocate");
    let mut arg = alloc::vec![0u8; l::FORMAT_SIZE];
    w32(&mut arg, l::FORMAT_TYPE, flags::BUF_TYPE_VIDEO_CAPTURE);
    w32(&mut arg, l::FORMAT_FMT + l::PIX_WIDTH, 320);
    w32(&mut arg, l::FORMAT_FMT + l::PIX_HEIGHT, 240);
    w32(&mut arg, l::FORMAT_FMT + l::PIX_PIXELFORMAT, fourcc::YUYV);
    assert_eq!(rig.call(VIDIOC_S_FMT, &mut arg, &ctx), Err(Errno::Ebusy));
    // Trying is still allowed: only installing would invalidate the pool.
    rig.call(VIDIOC_TRY_FMT, &mut arg, &ctx).expect("try_fmt is not refused");
}

#[test]
fn enumerations_terminate_with_einval() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    for index in 0..FORMATS.len() as u32 {
        let mut arg = alloc::vec![0u8; l::FMTDESC_SIZE];
        w32(&mut arg, l::FMTDESC_INDEX, index);
        w32(&mut arg, l::FMTDESC_TYPE, flags::BUF_TYPE_VIDEO_CAPTURE);
        rig.call(VIDIOC_ENUM_FMT, &mut arg, &ctx).expect("format enumerates");
        assert_eq!(r32(&arg, l::FMTDESC_PIXELFORMAT), FORMATS[index as usize].pixelformat);
    }
    let mut past = alloc::vec![0u8; l::FMTDESC_SIZE];
    w32(&mut past, l::FMTDESC_INDEX, FORMATS.len() as u32);
    w32(&mut past, l::FMTDESC_TYPE, flags::BUF_TYPE_VIDEO_CAPTURE);
    assert_eq!(rig.call(VIDIOC_ENUM_FMT, &mut past, &ctx), Err(Errno::Einval));

    for index in 0..SIZES.len() as u32 {
        let mut arg = alloc::vec![0u8; l::FRMSIZEENUM_SIZE];
        w32(&mut arg, l::FRMSIZE_INDEX, index);
        w32(&mut arg, l::FRMSIZE_PIXEL_FORMAT, fourcc::YUYV);
        rig.call(VIDIOC_ENUM_FRAMESIZES, &mut arg, &ctx).expect("size enumerates");
        assert_eq!(r32(&arg, l::FRMSIZE_TYPE), flags::FRMSIZE_TYPE_DISCRETE);
        assert_eq!(r32(&arg, l::FRMSIZE_DISCRETE_WIDTH), SIZES[index as usize].width);
    }
    let mut past = alloc::vec![0u8; l::FRMSIZEENUM_SIZE];
    w32(&mut past, l::FRMSIZE_INDEX, SIZES.len() as u32);
    w32(&mut past, l::FRMSIZE_PIXEL_FORMAT, fourcc::YUYV);
    assert_eq!(rig.call(VIDIOC_ENUM_FRAMESIZES, &mut past, &ctx), Err(Errno::Einval));
}

#[test]
fn frame_intervals_are_only_reported_for_a_size_the_format_offers() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    let mut arg = alloc::vec![0u8; l::FRMIVALENUM_SIZE];
    w32(&mut arg, l::FRMIVAL_PIXEL_FORMAT, fourcc::YUYV);
    w32(&mut arg, l::FRMIVAL_WIDTH, 640);
    w32(&mut arg, l::FRMIVAL_HEIGHT, 480);
    rig.call(VIDIOC_ENUM_FRAMEINTERVALS, &mut arg, &ctx).expect("interval enumerates");
    assert_eq!(r32(&arg, l::FRMIVAL_DISCRETE_DEN), 30);
    let mut wrong = alloc::vec![0u8; l::FRMIVALENUM_SIZE];
    w32(&mut wrong, l::FRMIVAL_PIXEL_FORMAT, fourcc::YUYV);
    w32(&mut wrong, l::FRMIVAL_WIDTH, 641);
    w32(&mut wrong, l::FRMIVAL_HEIGHT, 480);
    assert_eq!(rig.call(VIDIOC_ENUM_FRAMEINTERVALS, &mut wrong, &ctx), Err(Errno::Einval));
}

#[test]
fn s_parm_reports_the_rate_that_will_be_used() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    let mut arg = alloc::vec![0u8; l::STREAMPARM_SIZE];
    w32(&mut arg, l::STREAMPARM_TYPE, flags::BUF_TYPE_VIDEO_CAPTURE);
    w32(&mut arg, l::STREAMPARM_PARM + l::CAPTUREPARM_TIMEPERFRAME_NUM, 1);
    w32(&mut arg, l::STREAMPARM_PARM + l::CAPTUREPARM_TIMEPERFRAME_DEN, 12);
    rig.call(VIDIOC_S_PARM, &mut arg, &ctx).expect("s_parm succeeds");
    assert_eq!(r32(&arg, l::STREAMPARM_PARM + l::CAPTUREPARM_TIMEPERFRAME_DEN), 15);
    assert_eq!(r32(&arg, l::STREAMPARM_PARM + l::CAPTUREPARM_CAPABILITY), flags::CAP_TIMEPERFRAME);
    let mut got = alloc::vec![0u8; l::STREAMPARM_SIZE];
    w32(&mut got, l::STREAMPARM_TYPE, flags::BUF_TYPE_VIDEO_CAPTURE);
    rig.call(VIDIOC_G_PARM, &mut got, &ctx).expect("g_parm succeeds");
    assert_eq!(r32(&got, l::STREAMPARM_PARM + l::CAPTUREPARM_TIMEPERFRAME_DEN), 15);
}

#[test]
fn querycap_names_the_driver_and_its_capabilities() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    let mut arg = alloc::vec![0u8; l::CAPABILITY_SIZE];
    rig.call(VIDIOC_QUERYCAP, &mut arg, &ctx).expect("querycap succeeds");
    assert_eq!(&arg[l::CAP_DRIVER..l::CAP_DRIVER + 4], b"fake");
    assert_eq!(&arg[l::CAP_CARD..l::CAP_CARD + 11], b"Fake Camera");
    let caps = r32(&arg, l::CAP_CAPABILITIES);
    assert!(caps & flags::CAP_VIDEO_CAPTURE != 0);
    assert!(caps & flags::CAP_STREAMING != 0);
    // The whole-driver word must carry the marker saying the per-node word is
    // meaningful; the per-node word must not.
    assert!(caps & flags::CAP_DEVICE_CAPS != 0);
    assert_eq!(r32(&arg, l::CAP_DEVICE_CAPS) & flags::CAP_DEVICE_CAPS, 0);
}

#[test]
fn a_buffer_type_the_device_lacks_is_einval_everywhere() {
    let rig = Rig::new();
    let ctx = FakeCtx::new(true);
    let wrong = flags::BUF_TYPE_VIDEO_OUTPUT;
    let mut fmt = alloc::vec![0u8; l::FORMAT_SIZE];
    w32(&mut fmt, l::FORMAT_TYPE, wrong);
    assert_eq!(rig.call(VIDIOC_G_FMT, &mut fmt, &ctx), Err(Errno::Einval));
    assert_eq!(rig.call(VIDIOC_TRY_FMT, &mut fmt, &ctx), Err(Errno::Einval));
    assert_eq!(rig.call(VIDIOC_S_FMT, &mut fmt, &ctx), Err(Errno::Einval));
    let mut parm = alloc::vec![0u8; l::STREAMPARM_SIZE];
    w32(&mut parm, l::STREAMPARM_TYPE, wrong);
    assert_eq!(rig.call(VIDIOC_G_PARM, &mut parm, &ctx), Err(Errno::Einval));
    let mut on = wrong.to_le_bytes().to_vec();
    assert_eq!(rig.call(VIDIOC_STREAMON, &mut on, &ctx), Err(Errno::Einval));
    assert_eq!(rig.call(VIDIOC_STREAMOFF, &mut on, &ctx), Err(Errno::Einval));
}
