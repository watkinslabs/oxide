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

/// XInput's two-motor vibration request. The field order is part of the
/// Windows ABI and is intentionally identical to the native force-feedback
/// rumble payload after translation.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XInputVibration {
    pub left_motor_speed: u16,
    pub right_motor_speed: u16,
}

/// Canonical native rumble effect consumed by the Linux-shaped input owner.
/// Strong is the heavy motor and weak is the light motor.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct NativeRumbleEffect {
    pub strong_magnitude: u16,
    pub weak_magnitude: u16,
}

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
pub const GAMEPAD_GUIDE: u16 = 0x0400;
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
pub enum XInputNormalizationError { InvalidButtons, InvalidAxis(XInputAxis), MissingAxis(XInputAxis) }

const EVDEV_KEY_WORDS: usize = 12;
const EVDEV_ABS_AXES: usize = 64;
const BTN_SOUTH: u16 = 0x130;
const BTN_EAST: u16 = 0x131;
const BTN_NORTH: u16 = 0x133;
const BTN_WEST: u16 = 0x134;
const BTN_TL: u16 = 0x136;
const BTN_TR: u16 = 0x137;
const BTN_SELECT: u16 = 0x13a;
const BTN_START: u16 = 0x13b;
const BTN_MODE: u16 = 0x13c;
const BTN_THUMBL: u16 = 0x13d;
const BTN_THUMBR: u16 = 0x13e;
const BTN_DPAD_UP: u16 = 0x220;
const BTN_DPAD_DOWN: u16 = 0x221;
const BTN_DPAD_LEFT: u16 = 0x222;
const BTN_DPAD_RIGHT: u16 = 0x223;
const ABS_X: u16 = 0x00;
const ABS_Y: u16 = 0x01;
const ABS_Z: u16 = 0x02;
const ABS_RX: u16 = 0x03;
const ABS_RY: u16 = 0x04;
const ABS_RZ: u16 = 0x05;

/// Snapshot of one canonical Linux gamepad state: key bitmap plus ABS values.
/// Unknown keys and axes remain available to other consumers and are ignored.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EvdevGamepadState {
    pub key_bits: [u64; EVDEV_KEY_WORDS],
    pub abs: [Option<NativeAxis>; EVDEV_ABS_AXES],
}

impl EvdevGamepadState {
    /// Read one button from the canonical EV_KEY bitmap.
    /// # C: O(1)
    pub const fn key_down(&self, code: u16) -> bool {
        let word = code as usize / 64;
        let bit = code as usize % 64;
        word < EVDEV_KEY_WORDS && self.key_bits[word] & (1u64 << bit) != 0
    }

    /// Read one canonical EV_ABS sample, including its advertised range.
    /// # C: O(1)
    pub const fn axis(&self, code: u16) -> Option<NativeAxis> {
        if code as usize >= EVDEV_ABS_AXES { None } else { self.abs[code as usize] }
    }
}

/// Translate Linux's standard gamepad codes into the XInput report shape.
/// Linux ABS_Y/ABS_RY grow down; XInput thumb Y grows up, so those ranges are
/// mirrored before the shared normalization and validation path consumes them.
/// # C: O(1)
pub fn evdev_report(input: &EvdevGamepadState) -> Result<NativeGamepadReport, XInputNormalizationError> {
    let button = |code, mask| if input.key_down(code) { mask } else { 0 };
    let axis = |code, kind| input.axis(code).ok_or(XInputNormalizationError::MissingAxis(kind));
    Ok(NativeGamepadReport {
        buttons: button(BTN_DPAD_UP, GAMEPAD_DPAD_UP) | button(BTN_DPAD_DOWN, GAMEPAD_DPAD_DOWN)
            | button(BTN_DPAD_LEFT, GAMEPAD_DPAD_LEFT) | button(BTN_DPAD_RIGHT, GAMEPAD_DPAD_RIGHT)
            | button(BTN_START, GAMEPAD_START) | button(BTN_SELECT, GAMEPAD_BACK)
            | button(BTN_MODE, GAMEPAD_GUIDE)
            | button(BTN_THUMBL, GAMEPAD_LEFT_THUMB) | button(BTN_THUMBR, GAMEPAD_RIGHT_THUMB)
            | button(BTN_TL, GAMEPAD_LEFT_SHOULDER) | button(BTN_TR, GAMEPAD_RIGHT_SHOULDER)
            | button(BTN_SOUTH, GAMEPAD_A) | button(BTN_EAST, GAMEPAD_B)
            | button(BTN_NORTH, GAMEPAD_X) | button(BTN_WEST, GAMEPAD_Y),
        left_trigger: axis(ABS_Z, XInputAxis::LeftTrigger)?,
        right_trigger: axis(ABS_RZ, XInputAxis::RightTrigger)?,
        thumb_lx: axis(ABS_X, XInputAxis::ThumbLx)?,
        thumb_ly: mirror_axis(axis(ABS_Y, XInputAxis::ThumbLy)?),
        thumb_rx: axis(ABS_RX, XInputAxis::ThumbRx)?,
        thumb_ry: mirror_axis(axis(ABS_RY, XInputAxis::ThumbRy)?),
    })
}

fn mirror_axis(axis: NativeAxis) -> NativeAxis {
    NativeAxis { value: (axis.min as i64 + axis.max as i64 - axis.value as i64) as i32, ..axis }
}

/// Own the cached XInput state for one native controller.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XInputStateTracker { state: XInputState }

/// Cached controller state and output ownership for one XInput slot.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct XInputController {
    tracker: XInputStateTracker,
    vibration: XInputVibration,
}

impl XInputController {
    /// Apply one input report while retaining output state only for a live
    /// controller. Disconnect therefore cannot leave a stale motor request
    /// to be replayed when another device occupies the slot.
    /// # C: O(1)
    pub fn update(&mut self, report: Option<NativeGamepadReport>) -> Result<(), XInputNormalizationError> {
        self.tracker.update(report)?;
        if !self.tracker.is_connected() { self.vibration = XInputVibration::default(); }
        Ok(())
    }

    /// Remove the controller and return the one native stop effect required
    /// when its motors were active. This separates physical-output teardown
    /// from slot state clearing so hot-unplug cannot strand a motor.
    /// # C: O(1)
    pub fn disconnect(&mut self) -> Option<NativeRumbleEffect> {
        let stop = self.disable_vibration();
        let _ = self.update(None);
        stop
    }

    /// Cache one Windows vibration request and return a native effect only
    /// when the requested state changes. The caller owns publication of the
    /// returned effect to the canonical EV_FF device; repeated requests do not
    /// create duplicate output events.
    /// # C: O(1)
    pub fn set_vibration(&mut self, vibration: Option<XInputVibration>) -> Result<Option<NativeRumbleEffect>, XInputRequestError> {
        let Some(vibration) = vibration else { return Err(XInputRequestError::BadArguments); };
        if !self.tracker.is_connected() { return Err(XInputRequestError::DeviceNotConnected); }
        if self.vibration == vibration { return Ok(None); }
        self.vibration = vibration;
        Ok(Some(NativeRumbleEffect { strong_magnitude: vibration.left_motor_speed, weak_magnitude: vibration.right_motor_speed }))
    }

    /// Stop both motors as part of controller disable or removal, emitting a
    /// zero effect only when a nonzero request was previously active.
    /// # C: O(1)
    pub fn disable_vibration(&mut self) -> Option<NativeRumbleEffect> {
        if self.vibration == XInputVibration::default() { return None; }
        self.vibration = XInputVibration::default();
        Some(NativeRumbleEffect::default())
    }

    /// Return the cached Windows state for the controller slot.
    /// # C: O(1)
    pub const fn state(&self) -> XInputState { self.tracker.state() }
}

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

    /// Return the ordinary XInput projection, which hides the Guide button.
    /// The extended XInput surface uses `state()` and preserves it. # C: O(1)
    pub const fn state_without_guide(&self) -> XInputState {
        XInputState { packet_number: self.state.packet_number,
            gamepad: XInputGamepad { buttons: self.state.gamepad.buttons & !GAMEPAD_GUIDE, ..self.state.gamepad } }
    }

    /// Return whether the cached controller state is connected.
    /// # C: O(1)
    pub const fn is_connected(&self) -> bool { self.state.packet_number != 0 }
}

const fn known_buttons() -> u16 {
    GAMEPAD_DPAD_UP | GAMEPAD_DPAD_DOWN | GAMEPAD_DPAD_LEFT | GAMEPAD_DPAD_RIGHT
        | GAMEPAD_START | GAMEPAD_BACK | GAMEPAD_LEFT_THUMB | GAMEPAD_RIGHT_THUMB
        | GAMEPAD_LEFT_SHOULDER | GAMEPAD_RIGHT_SHOULDER | GAMEPAD_GUIDE
        | GAMEPAD_A | GAMEPAD_B | GAMEPAD_X | GAMEPAD_Y
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
        assert_eq!(core::mem::size_of::<XInputVibration>(), 4);
        assert_eq!(core::mem::size_of::<NativeRumbleEffect>(), 4);
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

    #[test]
    fn guide_button_is_preserved_for_extended_and_hidden_for_ordinary_xinput() {
        let mut tracker = XInputStateTracker::default();
        let mut report = report();
        report.buttons |= GAMEPAD_GUIDE;
        tracker.update(Some(report)).unwrap();
        assert_ne!(tracker.state().gamepad.buttons & GAMEPAD_GUIDE, 0);
        assert_eq!(tracker.state_without_guide().gamepad.buttons & GAMEPAD_GUIDE, 0);
        assert_eq!(tracker.state_without_guide().packet_number, tracker.state().packet_number);
    }

    fn evdev_state() -> EvdevGamepadState {
        let mut state = EvdevGamepadState { key_bits: [0; EVDEV_KEY_WORDS], abs: [None; EVDEV_ABS_AXES] };
        for code in [BTN_DPAD_UP, BTN_DPAD_DOWN, BTN_DPAD_LEFT, BTN_DPAD_RIGHT, BTN_START, BTN_SELECT, BTN_MODE,
                     BTN_THUMBL, BTN_THUMBR, BTN_TL, BTN_TR, BTN_SOUTH, BTN_EAST, BTN_NORTH, BTN_WEST] {
            state.key_bits[code as usize / 64] |= 1u64 << (code as usize % 64);
        }
        for (code, value) in [(ABS_Z, 25), (ABS_RZ, 75), (ABS_X, -50), (ABS_Y, -25),
                              (ABS_RX, 50), (ABS_RY, 25)] {
            state.abs[code as usize] = Some(axis(value));
        }
        state
    }

    #[test]
    fn canonical_evdev_gamepad_maps_buttons_axes_and_linux_y_direction() {
        let report = evdev_report(&evdev_state()).unwrap();
        assert_eq!(report.buttons, GAMEPAD_DPAD_UP | GAMEPAD_DPAD_DOWN | GAMEPAD_DPAD_LEFT
            | GAMEPAD_DPAD_RIGHT | GAMEPAD_START | GAMEPAD_BACK | GAMEPAD_LEFT_THUMB
            | GAMEPAD_RIGHT_THUMB | GAMEPAD_LEFT_SHOULDER | GAMEPAD_RIGHT_SHOULDER
            | GAMEPAD_GUIDE | GAMEPAD_A | GAMEPAD_B | GAMEPAD_X | GAMEPAD_Y);
        assert_eq!(report.left_trigger.value, 25);
        assert_eq!(report.thumb_ly.value, 25);
        assert_eq!(report.thumb_ry.value, -25);
    }

    #[test]
    fn canonical_evdev_gamepad_ignores_unknown_keys_but_rejects_missing_axes() {
        let mut state = evdev_state();
        state.key_bits[0] = u64::MAX;
        assert!(evdev_report(&state).is_ok());
        state.abs[ABS_RZ as usize] = None;
        assert_eq!(evdev_report(&state), Err(XInputNormalizationError::MissingAxis(XInputAxis::RightTrigger)));
    }

    #[test]
    fn vibration_maps_motors_to_native_rumble_and_deduplicates_requests() {
        let mut controller = XInputController::default();
        controller.update(Some(report())).unwrap();
        let vibration = XInputVibration { left_motor_speed: 0x1234, right_motor_speed: 0xabcd };
        assert_eq!(controller.set_vibration(Some(vibration)), Ok(Some(NativeRumbleEffect { strong_magnitude: 0x1234, weak_magnitude: 0xabcd })));
        assert_eq!(controller.set_vibration(Some(vibration)), Ok(None));
        assert_eq!(controller.disable_vibration(), Some(NativeRumbleEffect::default()));
        assert_eq!(controller.disable_vibration(), None);
    }

    #[test]
    fn vibration_requests_fail_without_a_live_controller_and_null_input_is_bad_arguments() {
        let mut controller = XInputController::default();
        let vibration = XInputVibration { left_motor_speed: 1, right_motor_speed: 2 };
        assert_eq!(controller.set_vibration(Some(vibration)), Err(XInputRequestError::DeviceNotConnected));
        assert_eq!(controller.set_vibration(None), Err(XInputRequestError::BadArguments));
    }

    #[test]
    fn disconnect_stops_active_vibration_and_clears_cached_state() {
        let mut controller = XInputController::default();
        controller.update(Some(report())).unwrap();
        controller.set_vibration(Some(XInputVibration { left_motor_speed: 4, right_motor_speed: 5 })).unwrap();
        assert_eq!(controller.disconnect(), Some(NativeRumbleEffect::default()));
        assert_eq!(controller.state(), XInputState::default());
        assert_eq!(controller.disable_vibration(), None);
        controller.update(Some(report())).unwrap();
        assert_eq!(controller.set_vibration(Some(XInputVibration::default())), Ok(None));
    }
}
