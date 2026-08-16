//! The ABI, re-derived from its definition rather than restated.
//!
//! These are the provenance for every number the surface writes: each ioctl
//! encoding is rebuilt from its direction, type, ordinal and argument size,
//! and each argument size is the one the structure's own field offsets add up
//! to. A number that drifts fails here rather than in an application.

use crate::uapi::ioctl::*;
use crate::uapi::layout as l;
use crate::uapi::{ctrl_ids as cid, flags, fourcc};

/// Rebuild an `_IOC` encoding the way the ABI defines it.
fn ioc(dir: u64, nr: u64, size: usize) -> u64 {
    (dir << IOC_DIRSHIFT) | ((size as u64) << IOC_SIZESHIFT) | (V4L2_IOC_TYPE << IOC_TYPESHIFT) | nr
}
fn ior(nr: u64, size: usize) -> u64 { ioc(IOC_READ, nr, size) }
fn iow(nr: u64, size: usize) -> u64 { ioc(IOC_WRITE, nr, size) }
fn iowr(nr: u64, size: usize) -> u64 { ioc(IOC_READ | IOC_WRITE, nr, size) }

#[test]
fn ioctl_encodings_match_their_direction_ordinal_and_size() {
    assert_eq!(VIDIOC_QUERYCAP, ior(0, l::CAPABILITY_SIZE));
    assert_eq!(VIDIOC_ENUM_FMT, iowr(2, l::FMTDESC_SIZE));
    assert_eq!(VIDIOC_G_FMT, iowr(4, l::FORMAT_SIZE));
    assert_eq!(VIDIOC_S_FMT, iowr(5, l::FORMAT_SIZE));
    assert_eq!(VIDIOC_REQBUFS, iowr(8, l::REQUESTBUFFERS_SIZE));
    assert_eq!(VIDIOC_QUERYBUF, iowr(9, l::BUFFER_SIZE));
    assert_eq!(VIDIOC_QBUF, iowr(15, l::BUFFER_SIZE));
    assert_eq!(VIDIOC_EXPBUF, iowr(16, l::EXPORTBUFFER_SIZE));
    assert_eq!(VIDIOC_DQBUF, iowr(17, l::BUFFER_SIZE));
    assert_eq!(VIDIOC_STREAMON, iow(18, 4));
    assert_eq!(VIDIOC_STREAMOFF, iow(19, 4));
    assert_eq!(VIDIOC_G_PARM, iowr(21, l::STREAMPARM_SIZE));
    assert_eq!(VIDIOC_S_PARM, iowr(22, l::STREAMPARM_SIZE));
    assert_eq!(VIDIOC_ENUMINPUT, iowr(26, l::INPUT_SIZE));
    assert_eq!(VIDIOC_G_CTRL, iowr(27, l::CONTROL_SIZE));
    assert_eq!(VIDIOC_S_CTRL, iowr(28, l::CONTROL_SIZE));
    assert_eq!(VIDIOC_QUERYCTRL, iowr(36, l::QUERYCTRL_SIZE));
    assert_eq!(VIDIOC_QUERYMENU, iowr(37, l::QUERYMENU_SIZE));
    assert_eq!(VIDIOC_G_INPUT, ior(38, 4));
    assert_eq!(VIDIOC_S_INPUT, iowr(39, 4));
    assert_eq!(VIDIOC_CROPCAP, iowr(58, l::CROPCAP_SIZE));
    assert_eq!(VIDIOC_G_CROP, iowr(59, l::CROP_SIZE));
    assert_eq!(VIDIOC_S_CROP, iow(60, l::CROP_SIZE));
    assert_eq!(VIDIOC_TRY_FMT, iowr(64, l::FORMAT_SIZE));
    assert_eq!(VIDIOC_G_PRIORITY, ior(67, 4));
    assert_eq!(VIDIOC_S_PRIORITY, iow(68, 4));
    assert_eq!(VIDIOC_LOG_STATUS, ioc(0, 70, 0));
    assert_eq!(VIDIOC_G_EXT_CTRLS, iowr(71, l::EXT_CONTROLS_SIZE));
    assert_eq!(VIDIOC_S_EXT_CTRLS, iowr(72, l::EXT_CONTROLS_SIZE));
    assert_eq!(VIDIOC_TRY_EXT_CTRLS, iowr(73, l::EXT_CONTROLS_SIZE));
    assert_eq!(VIDIOC_ENUM_FRAMESIZES, iowr(74, l::FRMSIZEENUM_SIZE));
    assert_eq!(VIDIOC_ENUM_FRAMEINTERVALS, iowr(75, l::FRMIVALENUM_SIZE));
    assert_eq!(VIDIOC_DQEVENT, ior(89, l::EVENT_SIZE));
    assert_eq!(VIDIOC_SUBSCRIBE_EVENT, iow(90, l::EVENT_SUBSCRIPTION_SIZE));
    assert_eq!(VIDIOC_UNSUBSCRIBE_EVENT, iow(91, l::EVENT_SUBSCRIPTION_SIZE));
    assert_eq!(VIDIOC_CREATE_BUFS, iowr(92, l::CREATE_BUFFERS_SIZE));
    assert_eq!(VIDIOC_PREPARE_BUF, iowr(93, l::BUFFER_SIZE));
    assert_eq!(VIDIOC_G_SELECTION, iowr(94, l::SELECTION_SIZE));
    assert_eq!(VIDIOC_S_SELECTION, iowr(95, l::SELECTION_SIZE));
    assert_eq!(VIDIOC_QUERY_EXT_CTRL, iowr(103, l::QUERY_EXT_CTRL_SIZE));
}

#[test]
fn every_argument_size_is_the_sum_of_its_fields() {
    // Each structure's declared size must be its last field's end, rounded up
    // to the alignment its widest member forces.
    assert_eq!(l::CAPABILITY_SIZE, l::CAP_RESERVED + l::CAP_RESERVED_LEN);
    assert_eq!(l::FMTDESC_SIZE, l::FMTDESC_RESERVED + l::FMTDESC_RESERVED_LEN);
    assert_eq!(l::PIX_FORMAT_SIZE, l::PIX_XFER_FUNC + 4);
    assert_eq!(l::FORMAT_SIZE, l::FORMAT_FMT + l::FORMAT_FMT_LEN);
    assert_eq!(l::FRMSIZEENUM_SIZE, l::FRMSIZE_RESERVED + l::FRMSIZE_RESERVED_LEN);
    assert_eq!(l::FRMIVALENUM_SIZE, l::FRMIVAL_RESERVED + l::FRMIVAL_RESERVED_LEN);
    assert_eq!(l::REQUESTBUFFERS_SIZE, l::REQBUFS_RESERVED + l::REQBUFS_RESERVED_LEN);
    assert_eq!(l::CREATE_BUFFERS_SIZE, l::CREATE_RESERVED + l::CREATE_RESERVED_LEN);
    assert_eq!(l::CREATE_FORMAT + l::FORMAT_SIZE, l::CREATE_CAPABILITIES);
    assert_eq!(l::BUFFER_SIZE, l::BUF_REQUEST_FD + 4 + 4);
    assert_eq!(l::PLANE_SIZE, l::PLANE_RESERVED + l::PLANE_RESERVED_LEN);
    assert_eq!(l::EXPORTBUFFER_SIZE, l::EXPBUF_RESERVED + l::EXPBUF_RESERVED_LEN);
    assert_eq!(l::STREAMPARM_SIZE, l::STREAMPARM_PARM + l::STREAMPARM_PARM_LEN);
    assert_eq!(l::CAPTUREPARM_SIZE, l::CAPTUREPARM_RESERVED + l::CAPTUREPARM_RESERVED_LEN);
    // `v4l2_input` holds a 64-bit standard set, so its size is the last
    // field's end rounded up to eight rather than the bare sum.
    assert_eq!(l::INPUT_SIZE, (l::INPUT_RESERVED + l::INPUT_RESERVED_LEN).next_multiple_of(8));
    assert_eq!(l::QUERYCTRL_SIZE, l::QUERYCTRL_RESERVED + l::QUERYCTRL_RESERVED_LEN);
    assert_eq!(l::QUERY_EXT_CTRL_SIZE, l::QEC_RESERVED + l::QEC_RESERVED_LEN);
    assert_eq!(l::QUERYMENU_SIZE, l::QUERYMENU_RESERVED + 4);
    assert_eq!(l::EXT_CONTROL_SIZE, l::EXT_CTRL_VALUE + 8);
    assert_eq!(l::EXT_CONTROLS_SIZE, l::EXT_CTRLS_CONTROLS + 8);
    // `v4l2_event` carries a `timespec`, so it too rounds up to eight.
    assert_eq!(l::EVENT_SIZE, (l::EVENT_RESERVED + l::EVENT_RESERVED_LEN).next_multiple_of(8));
    assert_eq!(l::EVENT_SUBSCRIPTION_SIZE, l::EVSUB_RESERVED + l::EVSUB_RESERVED_LEN);
    assert_eq!(l::SELECTION_SIZE, l::SEL_RESERVED + l::SEL_RESERVED_LEN);
    assert_eq!(l::PLANE_PIX_FORMAT_SIZE * l::MAX_PLANES, l::PIX_MP_NUM_PLANES - l::PIX_MP_PLANE_FMT);
    // The event union must hold the largest payload put in it.
    assert!(l::EVENT_CTRL_DEFAULT_VALUE + 4 <= l::EVENT_U_LEN);
}

#[test]
fn fourcc_values_are_their_characters() {
    assert_eq!(fourcc::YUYV, fourcc::from_chars(b'Y', b'U', b'Y', b'V'));
    assert_eq!(fourcc::UYVY, fourcc::from_chars(b'U', b'Y', b'V', b'Y'));
    assert_eq!(fourcc::RGB24, fourcc::from_chars(b'R', b'G', b'B', b'3'));
    assert_eq!(fourcc::BGR24, fourcc::from_chars(b'B', b'G', b'R', b'3'));
    assert_eq!(fourcc::RGB565, fourcc::from_chars(b'R', b'G', b'B', b'P'));
    assert_eq!(fourcc::RGB565X, fourcc::from_chars(b'R', b'G', b'B', b'R'));
    assert_eq!(fourcc::XRGB32, fourcc::from_chars(b'B', b'X', b'2', b'4'));
    assert_eq!(fourcc::ARGB32, fourcc::from_chars(b'B', b'A', b'2', b'4'));
    assert_eq!(fourcc::GREY, fourcc::from_chars(b'G', b'R', b'E', b'Y'));
    assert_eq!(fourcc::Y10, fourcc::from_chars(b'Y', b'1', b'0', b' '));
    assert_eq!(fourcc::Y16, fourcc::from_chars(b'Y', b'1', b'6', b' '));
    assert_eq!(fourcc::NV12, fourcc::from_chars(b'N', b'V', b'1', b'2'));
    assert_eq!(fourcc::NV21, fourcc::from_chars(b'N', b'V', b'2', b'1'));
    assert_eq!(fourcc::NV16, fourcc::from_chars(b'N', b'V', b'1', b'6'));
    assert_eq!(fourcc::YUV420, fourcc::from_chars(b'Y', b'U', b'1', b'2'));
    assert_eq!(fourcc::YVU420, fourcc::from_chars(b'Y', b'V', b'1', b'2'));
    assert_eq!(fourcc::YUV422P, fourcc::from_chars(b'4', b'2', b'2', b'P'));
    assert_eq!(fourcc::MJPEG, fourcc::from_chars(b'M', b'J', b'P', b'G'));
    assert_eq!(fourcc::JPEG, fourcc::from_chars(b'J', b'P', b'E', b'G'));
    assert_eq!(fourcc::H264, fourcc::from_chars(b'H', b'2', b'6', b'4'));
    assert_eq!(fourcc::H264_NO_SC, fourcc::from_chars(b'A', b'V', b'C', b'1'));
    assert_eq!(fourcc::HEVC, fourcc::from_chars(b'H', b'E', b'V', b'C'));
    assert_eq!(fourcc::VP8, fourcc::from_chars(b'V', b'P', b'8', b'0'));
    assert_eq!(fourcc::VP9, fourcc::from_chars(b'V', b'P', b'9', b'0'));
}

#[test]
fn control_ids_are_their_class_plus_ordinal() {
    assert_eq!(cid::CID_BASE, cid::CTRL_CLASS_USER | 0x900);
    assert_eq!(cid::CID_BRIGHTNESS, 0x0098_0900);
    assert_eq!(cid::CID_CONTRAST, 0x0098_0901);
    assert_eq!(cid::CID_SATURATION, 0x0098_0902);
    assert_eq!(cid::CID_HUE, 0x0098_0903);
    assert_eq!(cid::CID_AUTO_WHITE_BALANCE, 0x0098_090c);
    assert_eq!(cid::CID_GAMMA, 0x0098_0910);
    assert_eq!(cid::CID_GAIN, 0x0098_0913);
    assert_eq!(cid::CID_HFLIP, 0x0098_0914);
    assert_eq!(cid::CID_VFLIP, 0x0098_0915);
    assert_eq!(cid::CID_POWER_LINE_FREQUENCY, 0x0098_0918);
    assert_eq!(cid::CID_WHITE_BALANCE_TEMPERATURE, 0x0098_091a);
    assert_eq!(cid::CID_SHARPNESS, 0x0098_091b);
    assert_eq!(cid::CID_BACKLIGHT_COMPENSATION, 0x0098_091c);
    assert_eq!(cid::CID_EXPOSURE_AUTO, 0x009a_0901);
    assert_eq!(cid::CID_EXPOSURE_ABSOLUTE, 0x009a_0902);
    assert_eq!(cid::CID_FOCUS_ABSOLUTE, 0x009a_090a);
    assert_eq!(cid::CID_FOCUS_AUTO, 0x009a_090c);
    assert_eq!(cid::CID_ZOOM_ABSOLUTE, 0x009a_090d);
    // A control's class is recoverable from its id, which is what the
    // extended-control `which` selector relies on.
    assert_eq!(cid::id2class(cid::CID_BRIGHTNESS), cid::CTRL_CLASS_USER);
    assert_eq!(cid::id2class(cid::CID_ZOOM_ABSOLUTE), cid::CTRL_CLASS_CAMERA);
}

#[test]
fn buffer_type_classification_matches_the_enumeration() {
    assert!(flags::is_multiplanar(flags::BUF_TYPE_VIDEO_CAPTURE_MPLANE));
    assert!(flags::is_multiplanar(flags::BUF_TYPE_VIDEO_OUTPUT_MPLANE));
    assert!(!flags::is_multiplanar(flags::BUF_TYPE_VIDEO_CAPTURE));
    assert!(flags::is_output(flags::BUF_TYPE_VIDEO_OUTPUT));
    assert!(flags::is_output(flags::BUF_TYPE_VIDEO_OUTPUT_MPLANE));
    assert!(!flags::is_output(flags::BUF_TYPE_VIDEO_CAPTURE));
    assert!(!flags::is_output(flags::BUF_TYPE_VIDEO_CAPTURE_MPLANE));
}

#[test]
fn ioc_accessors_decompose_what_they_encode() {
    assert!(is_v4l2(VIDIOC_QBUF));
    assert!(!is_v4l2(0x8004_5500));
    assert_eq!(ioc_nr(VIDIOC_QBUF), 15);
    assert_eq!(ioc_size(VIDIOC_QBUF), l::BUFFER_SIZE);
    assert_eq!(ioc_dir(VIDIOC_QBUF), IOC_READ | IOC_WRITE);
    assert_eq!(ioc_dir(VIDIOC_STREAMON), IOC_WRITE);
    assert_eq!(ioc_dir(VIDIOC_QUERYCAP), IOC_READ);
    assert_eq!(ioc_size(VIDIOC_CREATE_BUFS), crate::usermem::MAX_ARG_BYTES);
}
