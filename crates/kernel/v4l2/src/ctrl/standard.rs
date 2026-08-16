//! The standard control descriptions a camera application expects.
//!
//! Names matter as much as ids: a program looking for the brightness slider
//! matches on the name the reference gives it, so a renamed control is a
//! missing control. A driver builds its handler from these, overriding only
//! the range it actually has.

use crate::uapi::ctrl_ids as cid;
use super::desc::ControlDesc;

/// A control with no menu, no cluster and no driver flags — the shape almost
/// every entry below takes. # C: O(1)
pub const fn simple(id: u32, ctrl_type: u32, name: &'static str,
                    minimum: i64, maximum: i64, step: u64, default_value: i64) -> ControlDesc {
    ControlDesc {
        id, ctrl_type, name, minimum, maximum, step, default_value,
        flags: 0, menu: &[], menu_values: &[], cluster: &[],
    }
}

/// Menu entries of `V4L2_CID_POWER_LINE_FREQUENCY`, in index order.
pub const POWER_LINE_MENU: &[&str] = &["Disabled", "50 Hz", "60 Hz", "Auto"];
/// Menu entries of `V4L2_CID_EXPOSURE_AUTO`.
pub const EXPOSURE_AUTO_MENU: &[&str] =
    &["Auto Mode", "Manual Mode", "Shutter Priority Mode", "Aperture Priority Mode"];

/// The name the reference gives each standard control. A driver that builds a
/// description by hand should take the name from here rather than restating
/// it, so a device's controls are the ones userspace looks for.
/// # C: O(1)
pub fn name_of(id: u32) -> Option<&'static str> {
    Some(match id {
        cid::CID_USER_CLASS => "User Controls",
        cid::CID_BRIGHTNESS => "Brightness",
        cid::CID_CONTRAST => "Contrast",
        cid::CID_SATURATION => "Saturation",
        cid::CID_HUE => "Hue",
        cid::CID_AUTO_WHITE_BALANCE => "White Balance, Automatic",
        cid::CID_DO_WHITE_BALANCE => "Do White Balance",
        cid::CID_RED_BALANCE => "Red Balance",
        cid::CID_BLUE_BALANCE => "Blue Balance",
        cid::CID_GAMMA => "Gamma",
        cid::CID_EXPOSURE => "Exposure",
        cid::CID_AUTOGAIN => "Gain, Automatic",
        cid::CID_GAIN => "Gain",
        cid::CID_HFLIP => "Horizontal Flip",
        cid::CID_VFLIP => "Vertical Flip",
        cid::CID_POWER_LINE_FREQUENCY => "Power Line Frequency",
        cid::CID_HUE_AUTO => "Hue, Automatic",
        cid::CID_WHITE_BALANCE_TEMPERATURE => "White Balance Temperature",
        cid::CID_SHARPNESS => "Sharpness",
        cid::CID_BACKLIGHT_COMPENSATION => "Backlight Compensation",
        cid::CID_COLOR_KILLER => "Color Killer",
        cid::CID_CAMERA_CLASS => "Camera Controls",
        cid::CID_EXPOSURE_AUTO => "Auto Exposure",
        cid::CID_EXPOSURE_ABSOLUTE => "Exposure Time, Absolute",
        cid::CID_EXPOSURE_AUTO_PRIORITY => "Exposure, Dynamic Framerate",
        cid::CID_PAN_ABSOLUTE => "Pan, Absolute",
        cid::CID_TILT_ABSOLUTE => "Tilt, Absolute",
        cid::CID_FOCUS_ABSOLUTE => "Focus, Absolute",
        cid::CID_FOCUS_RELATIVE => "Focus, Relative",
        cid::CID_FOCUS_AUTO => "Focus, Automatic Continuous",
        cid::CID_ZOOM_ABSOLUTE => "Zoom, Absolute",
        cid::CID_ZOOM_RELATIVE => "Zoom, Relative",
        cid::CID_ZOOM_CONTINUOUS => "Zoom, Continuous",
        cid::CID_PRIVACY => "Privacy",
        cid::CID_IRIS_ABSOLUTE => "Iris, Absolute",
        _ => return None,
    })
}

/// The user-class marker control. Every class a device has controls in
/// contributes one of these, and it is what an application enumerating by
/// class anchors on.
pub const USER_CLASS: ControlDesc = ControlDesc {
    id: cid::CID_USER_CLASS, ctrl_type: cid::CTRL_TYPE_CTRL_CLASS,
    name: "User Controls", minimum: 0, maximum: 0, step: 0, default_value: 0,
    flags: cid::CTRL_FLAG_READ_ONLY, menu: &[], menu_values: &[], cluster: &[],
};

/// The camera-class marker control.
pub const CAMERA_CLASS: ControlDesc = ControlDesc {
    id: cid::CID_CAMERA_CLASS, ctrl_type: cid::CTRL_TYPE_CTRL_CLASS,
    name: "Camera Controls", minimum: 0, maximum: 0, step: 0, default_value: 0,
    flags: cid::CTRL_FLAG_READ_ONLY, menu: &[], menu_values: &[], cluster: &[],
};

/// `V4L2_CID_POWER_LINE_FREQUENCY`, whose four entries are what a camera
/// application offers as the anti-flicker setting.
pub const POWER_LINE_FREQUENCY: ControlDesc = ControlDesc {
    id: cid::CID_POWER_LINE_FREQUENCY, ctrl_type: cid::CTRL_TYPE_MENU,
    name: "Power Line Frequency", minimum: 0, maximum: 3, step: 0,
    default_value: cid::POWER_LINE_FREQUENCY_50HZ,
    flags: 0, menu: POWER_LINE_MENU, menu_values: &[], cluster: &[],
};

/// `V4L2_CID_EXPOSURE_AUTO`. It clusters with the manual exposure time and the
/// dynamic-framerate flag: while the mode is automatic, those two are inactive
/// and an application must show them as such rather than writing values the
/// device will ignore.
pub const EXPOSURE_AUTO: ControlDesc = ControlDesc {
    id: cid::CID_EXPOSURE_AUTO, ctrl_type: cid::CTRL_TYPE_MENU,
    name: "Auto Exposure", minimum: 0, maximum: 3, step: 0,
    default_value: cid::EXPOSURE_AUTO,
    flags: cid::CTRL_FLAG_UPDATE, menu: EXPOSURE_AUTO_MENU, menu_values: &[],
    cluster: &[cid::CID_EXPOSURE_ABSOLUTE, cid::CID_EXPOSURE_AUTO_PRIORITY],
};

/// `V4L2_CID_AUTO_WHITE_BALANCE`, clustered with the colour temperature it
/// takes over while it is on.
pub const AUTO_WHITE_BALANCE: ControlDesc = ControlDesc {
    id: cid::CID_AUTO_WHITE_BALANCE, ctrl_type: cid::CTRL_TYPE_BOOLEAN,
    name: "White Balance, Automatic", minimum: 0, maximum: 1, step: 1,
    default_value: 1, flags: cid::CTRL_FLAG_UPDATE, menu: &[], menu_values: &[],
    cluster: &[cid::CID_WHITE_BALANCE_TEMPERATURE],
};

/// `V4L2_CID_FOCUS_AUTO`, clustered with the absolute focus position.
pub const FOCUS_AUTO: ControlDesc = ControlDesc {
    id: cid::CID_FOCUS_AUTO, ctrl_type: cid::CTRL_TYPE_BOOLEAN,
    name: "Focus, Automatic Continuous", minimum: 0, maximum: 1, step: 1,
    default_value: 1, flags: cid::CTRL_FLAG_UPDATE, menu: &[], menu_values: &[],
    cluster: &[cid::CID_FOCUS_ABSOLUTE],
};

/// Should this control be inactive given the current value of the automatic
/// control that governs it?
///
/// The rule is one place because it is the same rule for every pairing: while
/// the automatic control is engaged, its dependants are inactive.
/// # C: O(1)
pub fn cluster_inactive(auto_value: i64, auto_id: u32) -> bool {
    match auto_id {
        cid::CID_EXPOSURE_AUTO => auto_value != cid::EXPOSURE_MANUAL,
        _ => auto_value != 0,
    }
}
