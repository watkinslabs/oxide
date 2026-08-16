// Linux backlight class ABI: the enums, their sysfs text, the power states
// and the `state` bitmask. Constants only — every decision that consumes them
// lives in `device`, `attrs` or `registry`.

/// Backlight provider category. Userspace picks between competing devices on
/// this value, so the ordinals and the rendered text are ABI. The enum starts
/// at 1: zero is not a valid registered type.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum BacklightType {
    /// Direct register-level control of the panel's PWM.
    Raw = 1,
    /// A platform/embedded-controller interface.
    Platform = 2,
    /// A firmware interface (ACPI video and friends).
    Firmware = 3,
}

/// First ordinal that is not a valid `BacklightType`.
pub const BACKLIGHT_TYPE_MAX: u32 = 4;

impl BacklightType {
    /// `type` attribute text. # C: O(1)
    pub const fn text(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Platform => "platform",
            Self::Firmware => "firmware",
        }
    }

    /// Registration coerces an out-of-range type to `Raw` rather than
    /// refusing the device, matching the class core. # C: O(1)
    pub const fn from_raw(value: u32) -> Self {
        match value {
            2 => Self::Platform,
            3 => Self::Firmware,
            _ => Self::Raw,
        }
    }
}

/// Relationship between the brightness index and perceived luminance.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum BacklightScale {
    Unknown = 0,
    Linear = 1,
    NonLinear = 2,
}

impl BacklightScale {
    /// `scale` attribute text. # C: O(1)
    pub const fn text(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Linear => "linear",
            Self::NonLinear => "non-linear",
        }
    }
}

/// `bl_power` full-on. Numerically the framebuffer unblank state.
pub const BACKLIGHT_POWER_ON: i32 = 0;
/// `bl_power` reduced-power state.
pub const BACKLIGHT_POWER_REDUCED: i32 = 1;
/// `bl_power` full-off. Numerically the framebuffer power-down state.
pub const BACKLIGHT_POWER_OFF: i32 = 4;

/// `props.state`: the driver is suspended.
pub const BL_CORE_SUSPENDED: u32 = 1 << 0;
/// `props.state`: the display this backlight serves is blanked.
pub const BL_CORE_FBBLANK: u32 = 1 << 1;

/// `ops.options`: the class calls `update_status` across suspend/resume.
pub const BL_CORE_SUSPENDRESUME: u32 = 1 << 0;

/// Why a change notification is being generated. Rendered into the change
/// uevent's `SOURCE=` variable.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum UpdateReason {
    /// A brightness hotkey moved the level behind the class's back.
    Hotkey = 0,
    /// A userspace write to `brightness` or `bl_power`.
    Sysfs = 1,
}

impl UpdateReason {
    /// `SOURCE=` value of the generated change event. # C: O(1)
    pub const fn source(self) -> &'static str {
        match self {
            Self::Hotkey => "hotkey",
            Self::Sysfs => "sysfs",
        }
    }
}

/// `SOURCE=` value for a notification with no recognised reason.
pub const UPDATE_SOURCE_UNKNOWN: &str = "unknown";

/// Class name: the `/sys/class/<name>` directory and the uevent SUBSYSTEM.
pub const CLASS_NAME: &str = "backlight";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn type_ordinals_and_text_are_the_published_abi() {
        assert_eq!(BacklightType::Raw as u32, 1);
        assert_eq!(BacklightType::Platform as u32, 2);
        assert_eq!(BacklightType::Firmware as u32, 3);
        assert_eq!(BACKLIGHT_TYPE_MAX, 4);
        assert_eq!(BacklightType::Raw.text(), "raw");
        assert_eq!(BacklightType::Platform.text(), "platform");
        assert_eq!(BacklightType::Firmware.text(), "firmware");
    }

    #[test]
    fn an_out_of_range_registration_type_becomes_raw() {
        assert_eq!(BacklightType::from_raw(0), BacklightType::Raw);
        assert_eq!(BacklightType::from_raw(1), BacklightType::Raw);
        assert_eq!(BacklightType::from_raw(2), BacklightType::Platform);
        assert_eq!(BacklightType::from_raw(3), BacklightType::Firmware);
        assert_eq!(BacklightType::from_raw(BACKLIGHT_TYPE_MAX), BacklightType::Raw);
        assert_eq!(BacklightType::from_raw(u32::MAX), BacklightType::Raw);
    }

    #[test]
    fn scale_text_uses_the_hyphenated_non_linear_spelling() {
        assert_eq!(BacklightScale::Unknown as u32, 0);
        assert_eq!(BacklightScale::Linear as u32, 1);
        assert_eq!(BacklightScale::NonLinear as u32, 2);
        assert_eq!(BacklightScale::Unknown.text(), "unknown");
        assert_eq!(BacklightScale::Linear.text(), "linear");
        assert_eq!(BacklightScale::NonLinear.text(), "non-linear");
    }

    #[test]
    fn power_states_match_the_framebuffer_blank_numbering() {
        assert_eq!(BACKLIGHT_POWER_ON, 0);
        assert_eq!(BACKLIGHT_POWER_REDUCED, 1);
        assert_eq!(BACKLIGHT_POWER_OFF, 4);
    }

    #[test]
    fn update_reason_renders_the_event_source() {
        assert_eq!(UpdateReason::Hotkey.source(), "hotkey");
        assert_eq!(UpdateReason::Sysfs.source(), "sysfs");
        assert_eq!(UPDATE_SOURCE_UNKNOWN, "unknown");
    }
}
