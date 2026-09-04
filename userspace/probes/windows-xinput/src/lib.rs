//! Windows XInput state contract over the native HID/controller owner.
//!
//! HID discovery and device lifetime stay in the kernel input subsystem. This
//! boundary validates the fixed XInput state layout and exposes normalized
//! controls to the Windows API implementation.

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XInputGamepad {
    pub buttons: u16,
    pub left_trigger: u8,
    pub right_trigger: u8,
    pub thumb_lx: i16,
    pub thumb_ly: i16,
    pub thumb_rx: i16,
    pub thumb_ry: i16,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XInputState { pub packet_number: u32, pub gamepad: XInputGamepad }

pub const GAMEPAD_DPAD_UP: u16 = 0x0001;
pub const GAMEPAD_DPAD_DOWN: u16 = 0x0002;
pub const GAMEPAD_DPAD_LEFT: u16 = 0x0004;
pub const GAMEPAD_DPAD_RIGHT: u16 = 0x0008;
pub const GAMEPAD_START: u16 = 0x0010;
pub const GAMEPAD_BACK: u16 = 0x0020;
pub const GAMEPAD_LEFT_THUMB: u16 = 0x0040;
pub const GAMEPAD_RIGHT_THUMB: u16 = 0x0080;
pub const GAMEPAD_LEFT_SHOULDER: u16 = 0x0100;
pub const GAMEPAD_RIGHT_SHOULDER: u16 = 0x0200;
pub const GAMEPAD_A: u16 = 0x1000;
pub const GAMEPAD_B: u16 = 0x2000;
pub const GAMEPAD_X: u16 = 0x4000;
pub const GAMEPAD_Y: u16 = 0x8000;
pub const XUSER_MAX_COUNT: u32 = 4;
pub const ERROR_SUCCESS: u32 = 0;
pub const ERROR_BAD_ARGUMENTS: u32 = 160;
pub const ERROR_DEVICE_NOT_CONNECTED: u32 = 1167;

/// Advance the packet identity for one complete native input report. Zero is
/// reserved for the disconnected state, so a wrapping identity restarts at
/// one exactly as the Windows controller owner requires.
/// # C: O(1)
pub const fn next_packet_number(packet_number: u32) -> u32 {
    let next = packet_number.wrapping_add(1);
    if next == 0 { 1 } else { next }
}

/// One Linux EV_ABS-style sample, including the range advertised by the
/// native input device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeAxis {
    pub value: i32,
    pub min: i32,
    pub max: i32,
}

/// One complete native controller report. Button usages are already translated
/// to the XInput button mask; axes retain their native input ranges.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeGamepadReport {
    pub buttons: u16,
    pub left_trigger: NativeAxis,
    pub right_trigger: NativeAxis,
    pub thumb_lx: NativeAxis,
    pub thumb_ly: NativeAxis,
    pub thumb_rx: NativeAxis,
    pub thumb_ry: NativeAxis,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XInputAxis { LeftTrigger, RightTrigger, ThumbLx, ThumbLy, ThumbRx, ThumbRy }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XInputNormalizationError { InvalidButtons, InvalidAxis(XInputAxis) }

/// Own the cached XInput state for one native controller.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XInputStateTracker { state: XInputState }

impl XInputStateTracker {
    /// Apply one complete native report, or clear the state on disconnect.
    /// Invalid reports leave the previous state and packet number untouched.
    /// # C: O(1)
    pub fn update(&mut self, report: Option<NativeGamepadReport>) -> Result<(), XInputNormalizationError> {
        let Some(report) = report else {
            self.state = XInputState::default();
            return Ok(());
        };
        if report.buttons & !known_buttons() != 0 { return Err(XInputNormalizationError::InvalidButtons); }
        let gamepad = XInputGamepad {
            buttons: report.buttons,
            left_trigger: normalize_trigger(report.left_trigger).ok_or(XInputNormalizationError::InvalidAxis(XInputAxis::LeftTrigger))?,
            right_trigger: normalize_trigger(report.right_trigger).ok_or(XInputNormalizationError::InvalidAxis(XInputAxis::RightTrigger))?,
            thumb_lx: normalize_thumb(report.thumb_lx).ok_or(XInputNormalizationError::InvalidAxis(XInputAxis::ThumbLx))?,
            thumb_ly: normalize_thumb(report.thumb_ly).ok_or(XInputNormalizationError::InvalidAxis(XInputAxis::ThumbLy))?,
            thumb_rx: normalize_thumb(report.thumb_rx).ok_or(XInputNormalizationError::InvalidAxis(XInputAxis::ThumbRx))?,
            thumb_ry: normalize_thumb(report.thumb_ry).ok_or(XInputNormalizationError::InvalidAxis(XInputAxis::ThumbRy))?,
        };
        self.state = XInputState { packet_number: next_packet_number(self.state.packet_number), gamepad };
        Ok(())
    }

    /// Return the cached ABI state. Packet zero is the disconnected sentinel.
    /// # C: O(1)
    pub const fn state(&self) -> XInputState { self.state }

    /// Return whether the cached controller state is connected.
    /// # C: O(1)
    pub const fn is_connected(&self) -> bool { self.state.packet_number != 0 }
}

const fn known_buttons() -> u16 {
    GAMEPAD_DPAD_UP | GAMEPAD_DPAD_DOWN | GAMEPAD_DPAD_LEFT | GAMEPAD_DPAD_RIGHT
        | GAMEPAD_START | GAMEPAD_BACK | GAMEPAD_LEFT_THUMB | GAMEPAD_RIGHT_THUMB
        | GAMEPAD_LEFT_SHOULDER | GAMEPAD_RIGHT_SHOULDER | GAMEPAD_A | GAMEPAD_B | GAMEPAD_X | GAMEPAD_Y
}

fn normalize_trigger(axis: NativeAxis) -> Option<u8> {
    let offset = i64::from(axis.value) - i64::from(axis.min);
    let span = i64::from(axis.max) - i64::from(axis.min);
    if span <= 0 || offset < 0 || offset > span { return None; }
    Some(((offset * 255 + span / 2) / span) as u8)
}

fn normalize_thumb(axis: NativeAxis) -> Option<i16> {
    let offset = i64::from(axis.value) - i64::from(axis.min);
    let span = i64::from(axis.max) - i64::from(axis.min);
    if span <= 0 || offset < 0 || offset > span { return None; }
    Some((((offset * 65_535 + span / 2) / span) - 32_768) as i16)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum XInputRequestError { BadArguments, DeviceNotConnected }

/// Validate the API-level request before consulting the native controller owner.
/// # C: O(1)
pub fn validate_request(index: u32, output_present: bool) -> Result<(), XInputRequestError> {
    if index >= XUSER_MAX_COUNT || !output_present { Err(XInputRequestError::BadArguments) } else { Ok(()) }
}

/// Translate a validated controller lookup into the stable Win32 result code.
/// # C: O(1)
pub const fn result_code(error: Option<XInputRequestError>) -> u32 {
    match error { None => ERROR_SUCCESS, Some(XInputRequestError::BadArguments) => ERROR_BAD_ARGUMENTS, Some(XInputRequestError::DeviceNotConnected) => ERROR_DEVICE_NOT_CONNECTED }
}

/// Validate that a kernel-provided state has the exact Windows ABI shape and
/// no impossible button bits. Analog values are signed full-range controls.
/// # C: O(1)
pub fn validate_state(state: &XInputState) -> bool {
    state.gamepad.buttons & !known_buttons() == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xinput_layout_is_fixed_64_bit_compatible() {
        assert_eq!(core::mem::size_of::<XInputGamepad>(), 12);
        assert_eq!(core::mem::size_of::<XInputState>(), 16);
        assert_eq!(core::mem::offset_of!(XInputState, gamepad), 4);
    }

    #[test]
    fn accepts_full_range_controls_and_rejects_unknown_buttons() {
        let state = XInputState { packet_number: 9, gamepad: XInputGamepad { buttons: GAMEPAD_A,
            left_trigger: 255, right_trigger: 0, thumb_lx: i16::MIN, thumb_ly: i16::MAX,
            thumb_rx: -1, thumb_ry: 1 } };
        assert!(validate_state(&state));
        let invalid = XInputState { gamepad: XInputGamepad { buttons: 0x0800, ..Default::default() }, ..Default::default() };
        assert!(!validate_state(&invalid));
    }

    #[test]
    fn request_contract_matches_wine_xinput_error_semantics() {
        assert!(validate_request(0, true).is_ok());
        assert_eq!(validate_request(XUSER_MAX_COUNT, true), Err(XInputRequestError::BadArguments));
        assert_eq!(validate_request(0, false), Err(XInputRequestError::BadArguments));
        assert_eq!(result_code(None), ERROR_SUCCESS);
        assert_eq!(result_code(Some(XInputRequestError::DeviceNotConnected)), ERROR_DEVICE_NOT_CONNECTED);
    }

    #[test]
    fn packet_identity_advances_and_reserves_zero_for_disconnect() {
        assert_eq!(next_packet_number(0), 1);
        assert_eq!(next_packet_number(1), 2);
        assert_eq!(next_packet_number(u32::MAX - 1), u32::MAX);
        assert_eq!(next_packet_number(u32::MAX), 1);
    }

    fn axis(value: i32) -> NativeAxis { NativeAxis { value, min: -100, max: 100 } }

    fn report() -> NativeGamepadReport {
        NativeGamepadReport {
            buttons: GAMEPAD_A, left_trigger: NativeAxis { value: 0, min: 0, max: 1023 },
            right_trigger: NativeAxis { value: 1023, min: 0, max: 1023 },
            thumb_lx: axis(-100), thumb_ly: axis(0), thumb_rx: axis(100), thumb_ry: axis(0),
        }
    }

    #[test]
    fn native_ranges_normalize_to_xinput_widths_and_advance_once_per_report() {
        let mut tracker = XInputStateTracker::default();
        tracker.update(Some(report())).unwrap();
        assert_eq!(tracker.state().packet_number, 1);
        assert_eq!(tracker.state().gamepad.left_trigger, 0);
        assert_eq!(tracker.state().gamepad.right_trigger, 255);
        assert_eq!(tracker.state().gamepad.thumb_lx, i16::MIN);
        assert_eq!(tracker.state().gamepad.thumb_ly, 0);
        assert_eq!(tracker.state().gamepad.thumb_rx, i16::MAX);
        tracker.update(Some(report())).unwrap();
        assert_eq!(tracker.state().packet_number, 2);
    }

    #[test]
    fn malformed_report_is_transactional_and_disconnect_clears_cached_state() {
        let mut tracker = XInputStateTracker::default();
        tracker.update(Some(report())).unwrap();
        let previous = tracker.state();
        let mut invalid = report();
        invalid.thumb_lx = NativeAxis { value: 0, min: 1, max: 1 };
        assert_eq!(tracker.update(Some(invalid)), Err(XInputNormalizationError::InvalidAxis(XInputAxis::ThumbLx)));
        assert_eq!(tracker.state(), previous);
        tracker.update(None).unwrap();
        assert!(!tracker.is_connected());
        assert_eq!(tracker.state(), XInputState::default());
        tracker.update(Some(report())).unwrap();
        assert_eq!(tracker.state().packet_number, 1);
    }
}
