//! What the virtual camera reports it can do.

use v4l2::format::{Fract, FormatDesc, FrameSize};
use v4l2::ops::InputDesc;
use v4l2::uapi::{ctrl_ids as cid, flags, fourcc};
use v4l2::ctrl::{standard, ControlDesc};

pub const CID_HOR_MOVEMENT: u32 = 0x0098_20a0;
pub const CID_VERT_MOVEMENT: u32 = 0x0098_20a1;
/// Linux Vivid's streaming control: the next completed buffer carries
/// `V4L2_BUF_FLAG_ERROR`. # C: O(1)
pub const CID_DQBUF_ERROR: u32 = 0x00f0_f042;

pub const MOVEMENT_MENU: &[&str] = &[
    "Move Left Fast", "Move Left", "Move Left Slow", "No Movement",
    "Move Right Slow", "Move Right", "Move Right Fast",
];

pub const SIZES: &[FrameSize] = &[
    FrameSize { width: 320, height: 240 },
    FrameSize { width: 640, height: 480 },
    FrameSize { width: 800, height: 600 },
    FrameSize { width: 1280, height: 720 },
];

pub const INTERVALS: &[Fract] = &[
    Fract { numerator: 1, denominator: 30 },
    Fract { numerator: 1, denominator: 15 },
    Fract { numerator: 1, denominator: 10 },
    Fract { numerator: 1, denominator: 5 },
];

/// Formats in preference order. The packed 4:2:2 form comes first because it
/// is what a video-conferencing application asks for before anything else.
pub const FORMATS: &[FormatDesc] = &[
    FormatDesc { pixelformat: fourcc::YUYV, description: "YUYV 4:2:2", flags: 0,
                 sizes: SIZES, intervals: INTERVALS, compressed_sizeimage: 0 },
    FormatDesc { pixelformat: fourcc::UYVY, description: "UYVY 4:2:2", flags: 0,
                 sizes: SIZES, intervals: INTERVALS, compressed_sizeimage: 0 },
    FormatDesc { pixelformat: fourcc::RGB24, description: "24-bit RGB 8-8-8", flags: 0,
                 sizes: SIZES, intervals: INTERVALS, compressed_sizeimage: 0 },
    FormatDesc { pixelformat: fourcc::BGR24, description: "24-bit BGR 8-8-8", flags: 0,
                 sizes: SIZES, intervals: INTERVALS, compressed_sizeimage: 0 },
    FormatDesc { pixelformat: fourcc::RGB565, description: "16-bit RGB 5-6-5", flags: 0,
                 sizes: SIZES, intervals: INTERVALS, compressed_sizeimage: 0 },
    FormatDesc { pixelformat: fourcc::XRGB32, description: "32-bit XRGB 8-8-8-8", flags: 0,
                 sizes: SIZES, intervals: INTERVALS, compressed_sizeimage: 0 },
    FormatDesc { pixelformat: fourcc::ARGB32, description: "32-bit ARGB 8-8-8-8", flags: 0,
                 sizes: SIZES, intervals: INTERVALS, compressed_sizeimage: 0 },
    FormatDesc { pixelformat: fourcc::GREY, description: "8-bit Greyscale", flags: 0,
                 sizes: SIZES, intervals: INTERVALS, compressed_sizeimage: 0 },
];

pub const INPUTS: &[InputDesc] = &[
    InputDesc { name: "Camera", input_type: flags::INPUT_TYPE_CAMERA, status: 0,
                capabilities: 0 },
];

/// The controls a camera application expects to find. Every name is the one
/// the reference gives, because a renamed control is a missing control.
/// # C: O(1)
pub fn controls() -> alloc::vec::Vec<ControlDesc> {
    alloc::vec![
        standard::USER_CLASS,
        standard::simple(cid::CID_BRIGHTNESS, cid::CTRL_TYPE_INTEGER, "Brightness",
                         0, 255, 1, 128),
        standard::simple(cid::CID_CONTRAST, cid::CTRL_TYPE_INTEGER, "Contrast",
                         0, 255, 1, 128),
        standard::simple(cid::CID_SATURATION, cid::CTRL_TYPE_INTEGER, "Saturation",
                         0, 255, 1, 128),
        standard::simple(cid::CID_HUE, cid::CTRL_TYPE_INTEGER, "Hue", -128, 127, 1, 0),
        standard::simple(cid::CID_GAMMA, cid::CTRL_TYPE_INTEGER, "Gamma", 100, 300, 1, 220),
        standard::simple(cid::CID_GAIN, cid::CTRL_TYPE_INTEGER, "Gain", 0, 255, 1, 0),
        standard::simple(cid::CID_SHARPNESS, cid::CTRL_TYPE_INTEGER, "Sharpness",
                         0, 255, 1, 128),
        standard::simple(cid::CID_BACKLIGHT_COMPENSATION, cid::CTRL_TYPE_INTEGER,
                         "Backlight Compensation", 0, 2, 1, 1),
        standard::simple(cid::CID_HFLIP, cid::CTRL_TYPE_BOOLEAN, "Horizontal Flip", 0, 1, 1, 0),
        standard::simple(cid::CID_VFLIP, cid::CTRL_TYPE_BOOLEAN, "Vertical Flip", 0, 1, 1, 0),
        standard::POWER_LINE_FREQUENCY,
        standard::AUTO_WHITE_BALANCE,
        standard::simple(cid::CID_WHITE_BALANCE_TEMPERATURE, cid::CTRL_TYPE_INTEGER,
                         "White Balance Temperature", 2800, 6500, 100, 4600),
        standard::CAMERA_CLASS,
        standard::EXPOSURE_AUTO,
        standard::simple(cid::CID_EXPOSURE_ABSOLUTE, cid::CTRL_TYPE_INTEGER,
                         "Exposure Time, Absolute", 1, 5000, 1, 156),
        standard::simple(cid::CID_EXPOSURE_AUTO_PRIORITY, cid::CTRL_TYPE_BOOLEAN,
                         "Exposure, Dynamic Framerate", 0, 1, 1, 0),
        standard::FOCUS_AUTO,
        standard::simple(cid::CID_FOCUS_ABSOLUTE, cid::CTRL_TYPE_INTEGER,
                         "Focus, Absolute", 0, 255, 5, 0),
        standard::simple(cid::CID_ZOOM_ABSOLUTE, cid::CTRL_TYPE_INTEGER,
                         "Zoom, Absolute", 100, 500, 1, 100),
        ControlDesc {
            id: CID_HOR_MOVEMENT, ctrl_type: cid::CTRL_TYPE_MENU,
            name: "Horizontal Movement", minimum: 0, maximum: 6, step: 0,
            default_value: 3, flags: 0, menu: MOVEMENT_MENU,
            menu_values: &[], cluster: &[],
        },
        ControlDesc {
            id: CID_VERT_MOVEMENT, ctrl_type: cid::CTRL_TYPE_MENU,
            name: "Vertical Movement", minimum: 0, maximum: 6, step: 0,
            default_value: 3, flags: 0, menu: MOVEMENT_MENU,
            menu_values: &[], cluster: &[],
        },
        standard::simple(CID_DQBUF_ERROR, cid::CTRL_TYPE_BUTTON,
                         "Inject V4L2_BUF_FLAG_ERROR", 0, 0, 0, 0),
    ]
}

/// Capabilities this node has: capture and streaming, plus the marker saying
/// the extended pixel-format fields are meaningful. No read capability — this
/// device delivers frames through the buffer queue only, and an application
/// that sees the read bit will try `read(2)` and get nothing.
pub const DEVICE_CAPS: u32 =
    flags::CAP_VIDEO_CAPTURE | flags::CAP_READWRITE | flags::CAP_STREAMING
    | flags::CAP_EXT_PIX_FORMAT;
