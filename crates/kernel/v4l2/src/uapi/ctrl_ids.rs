//! Control classes, standard control identifiers, control types and control
//! flags.
//!
//! A control id carries its class in bits 16-27, so `CTRL_CLASS_USER | n` is a
//! user control and `id2class` recovers the class from any id. The `WHICH_*`
//! selectors in `v4l2_ext_controls.which` reuse the same field with reserved
//! class values.

/// Mask of the bits a control id occupies.
pub const CTRL_ID_MASK: u32 = 0x0fff_ffff;
/// Mask selecting the class field of a control id.
pub const CTRL_CLASS_MASK: u32 = 0x0fff_0000;
/// Ordinal field within a class.
pub const CTRL_ID_ORDINAL_MASK: u32 = 0x0000_ffff;

pub const CTRL_CLASS_USER: u32 = 0x0098_0000;
pub const CTRL_CLASS_CODEC: u32 = 0x0099_0000;
pub const CTRL_CLASS_CAMERA: u32 = 0x009a_0000;
pub const CTRL_CLASS_FM_TX: u32 = 0x009b_0000;
pub const CTRL_CLASS_FLASH: u32 = 0x009c_0000;
pub const CTRL_CLASS_JPEG: u32 = 0x009d_0000;
pub const CTRL_CLASS_IMAGE_SOURCE: u32 = 0x009e_0000;
pub const CTRL_CLASS_IMAGE_PROC: u32 = 0x009f_0000;
pub const CTRL_CLASS_DV: u32 = 0x00a0_0000;
pub const CTRL_CLASS_DETECT: u32 = 0x00a3_0000;
pub const CTRL_CLASS_COLORIMETRY: u32 = 0x00a5_0000;

/// Class of a control id. # C: O(1)
pub fn id2class(id: u32) -> u32 { id & CTRL_CLASS_MASK }
/// Class-representative id (`V4L2_CTRL_ID2WHICH`). # C: O(1)
pub fn id2which(id: u32) -> u32 { id & 0x0fff_0000 }

/// `which` selectors in `v4l2_ext_controls`.
pub const CTRL_WHICH_CUR_VAL: u32 = 0;
pub const CTRL_WHICH_DEF_VAL: u32 = 0x0f00_0000;
pub const CTRL_WHICH_REQUEST_VAL: u32 = 0x0f01_0000;
pub const CTRL_WHICH_MIN_VAL: u32 = 0x0f02_0000;
pub const CTRL_WHICH_MAX_VAL: u32 = 0x0f03_0000;

/// First id of the user class; `V4L2_CID_BASE` names the same value.
pub const CID_BASE: u32 = CTRL_CLASS_USER | 0x900;
pub const CID_USER_BASE: u32 = CID_BASE;
pub const CID_PRIVATE_BASE: u32 = 0x0800_0000;
pub const CID_CAMERA_CLASS_BASE: u32 = CTRL_CLASS_CAMERA | 0x900;

// ---- user class ----------------------------------------------------------
pub const CID_USER_CLASS: u32 = CTRL_CLASS_USER | 1;
pub const CID_BRIGHTNESS: u32 = CID_BASE;
pub const CID_CONTRAST: u32 = CID_BASE + 1;
pub const CID_SATURATION: u32 = CID_BASE + 2;
pub const CID_HUE: u32 = CID_BASE + 3;
pub const CID_AUDIO_VOLUME: u32 = CID_BASE + 5;
pub const CID_AUDIO_MUTE: u32 = CID_BASE + 9;
pub const CID_AUTO_WHITE_BALANCE: u32 = CID_BASE + 12;
pub const CID_DO_WHITE_BALANCE: u32 = CID_BASE + 13;
pub const CID_RED_BALANCE: u32 = CID_BASE + 14;
pub const CID_BLUE_BALANCE: u32 = CID_BASE + 15;
pub const CID_GAMMA: u32 = CID_BASE + 16;
pub const CID_EXPOSURE: u32 = CID_BASE + 17;
pub const CID_AUTOGAIN: u32 = CID_BASE + 18;
pub const CID_GAIN: u32 = CID_BASE + 19;
pub const CID_HFLIP: u32 = CID_BASE + 20;
pub const CID_VFLIP: u32 = CID_BASE + 21;
pub const CID_POWER_LINE_FREQUENCY: u32 = CID_BASE + 24;
pub const CID_HUE_AUTO: u32 = CID_BASE + 25;
pub const CID_WHITE_BALANCE_TEMPERATURE: u32 = CID_BASE + 26;
pub const CID_SHARPNESS: u32 = CID_BASE + 27;
pub const CID_BACKLIGHT_COMPENSATION: u32 = CID_BASE + 28;
pub const CID_COLOR_KILLER: u32 = CID_BASE + 34;
pub const CID_ALPHA_COMPONENT: u32 = CID_BASE + 41;

/// `V4L2_CID_POWER_LINE_FREQUENCY` menu ordinals.
pub const POWER_LINE_FREQUENCY_DISABLED: i64 = 0;
pub const POWER_LINE_FREQUENCY_50HZ: i64 = 1;
pub const POWER_LINE_FREQUENCY_60HZ: i64 = 2;
pub const POWER_LINE_FREQUENCY_AUTO: i64 = 3;

// ---- camera class --------------------------------------------------------
pub const CID_CAMERA_CLASS: u32 = CTRL_CLASS_CAMERA | 1;
pub const CID_EXPOSURE_AUTO: u32 = CID_CAMERA_CLASS_BASE + 1;
pub const CID_EXPOSURE_ABSOLUTE: u32 = CID_CAMERA_CLASS_BASE + 2;
pub const CID_EXPOSURE_AUTO_PRIORITY: u32 = CID_CAMERA_CLASS_BASE + 3;
pub const CID_PAN_RELATIVE: u32 = CID_CAMERA_CLASS_BASE + 4;
pub const CID_TILT_RELATIVE: u32 = CID_CAMERA_CLASS_BASE + 5;
pub const CID_PAN_RESET: u32 = CID_CAMERA_CLASS_BASE + 6;
pub const CID_TILT_RESET: u32 = CID_CAMERA_CLASS_BASE + 7;
pub const CID_PAN_ABSOLUTE: u32 = CID_CAMERA_CLASS_BASE + 8;
pub const CID_TILT_ABSOLUTE: u32 = CID_CAMERA_CLASS_BASE + 9;
pub const CID_FOCUS_ABSOLUTE: u32 = CID_CAMERA_CLASS_BASE + 10;
pub const CID_FOCUS_RELATIVE: u32 = CID_CAMERA_CLASS_BASE + 11;
pub const CID_FOCUS_AUTO: u32 = CID_CAMERA_CLASS_BASE + 12;
pub const CID_ZOOM_ABSOLUTE: u32 = CID_CAMERA_CLASS_BASE + 13;
pub const CID_ZOOM_RELATIVE: u32 = CID_CAMERA_CLASS_BASE + 14;
pub const CID_ZOOM_CONTINUOUS: u32 = CID_CAMERA_CLASS_BASE + 15;
pub const CID_PRIVACY: u32 = CID_CAMERA_CLASS_BASE + 16;
pub const CID_IRIS_ABSOLUTE: u32 = CID_CAMERA_CLASS_BASE + 17;
pub const CID_IRIS_RELATIVE: u32 = CID_CAMERA_CLASS_BASE + 18;
pub const CID_AUTO_EXPOSURE_BIAS: u32 = CID_CAMERA_CLASS_BASE + 19;
pub const CID_AUTO_N_PRESET_WHITE_BALANCE: u32 = CID_CAMERA_CLASS_BASE + 20;
pub const CID_IMAGE_STABILIZATION: u32 = CID_CAMERA_CLASS_BASE + 23;
pub const CID_CAMERA_ORIENTATION: u32 = CID_CAMERA_CLASS_BASE + 34;
pub const CID_CAMERA_SENSOR_ROTATION: u32 = CID_CAMERA_CLASS_BASE + 35;

/// `V4L2_CID_EXPOSURE_AUTO` menu ordinals.
pub const EXPOSURE_AUTO: i64 = 0;
pub const EXPOSURE_MANUAL: i64 = 1;
pub const EXPOSURE_SHUTTER_PRIORITY: i64 = 2;
pub const EXPOSURE_APERTURE_PRIORITY: i64 = 3;

// ---- v4l2_ctrl_type ------------------------------------------------------
pub const CTRL_TYPE_INTEGER: u32 = 1;
pub const CTRL_TYPE_BOOLEAN: u32 = 2;
pub const CTRL_TYPE_MENU: u32 = 3;
pub const CTRL_TYPE_BUTTON: u32 = 4;
pub const CTRL_TYPE_INTEGER64: u32 = 5;
pub const CTRL_TYPE_CTRL_CLASS: u32 = 6;
pub const CTRL_TYPE_STRING: u32 = 7;
pub const CTRL_TYPE_BITMASK: u32 = 8;
pub const CTRL_TYPE_INTEGER_MENU: u32 = 9;
pub const CTRL_TYPE_U8: u32 = 0x0100;
pub const CTRL_TYPE_U16: u32 = 0x0101;
pub const CTRL_TYPE_U32: u32 = 0x0102;

// ---- v4l2_queryctrl.flags ------------------------------------------------
pub const CTRL_FLAG_DISABLED: u32 = 0x0001;
pub const CTRL_FLAG_GRABBED: u32 = 0x0002;
pub const CTRL_FLAG_READ_ONLY: u32 = 0x0004;
pub const CTRL_FLAG_UPDATE: u32 = 0x0008;
pub const CTRL_FLAG_INACTIVE: u32 = 0x0010;
pub const CTRL_FLAG_SLIDER: u32 = 0x0020;
pub const CTRL_FLAG_WRITE_ONLY: u32 = 0x0040;
pub const CTRL_FLAG_VOLATILE: u32 = 0x0080;
pub const CTRL_FLAG_HAS_PAYLOAD: u32 = 0x0100;
pub const CTRL_FLAG_EXECUTE_ON_WRITE: u32 = 0x0200;
pub const CTRL_FLAG_MODIFY_LAYOUT: u32 = 0x0400;
pub const CTRL_FLAG_DYNAMIC_ARRAY: u32 = 0x0800;
/// Query flag, never a control property: walk to the next id above the one given.
pub const CTRL_FLAG_NEXT_CTRL: u32 = 0x8000_0000;
/// Same walk, admitting compound controls too.
pub const CTRL_FLAG_NEXT_COMPOUND: u32 = 0x4000_0000;
/// The two walk flags together, which is what a query id must be masked with.
pub const CTRL_QUERY_FLAGS: u32 = CTRL_FLAG_NEXT_CTRL | CTRL_FLAG_NEXT_COMPOUND;

/// `V4L2_CTRL_MAX_DIMS`.
pub const CTRL_MAX_DIMS: usize = 4;
