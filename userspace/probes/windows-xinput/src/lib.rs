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
    let known = GAMEPAD_DPAD_UP | GAMEPAD_DPAD_DOWN | GAMEPAD_DPAD_LEFT | GAMEPAD_DPAD_RIGHT
        | GAMEPAD_START | GAMEPAD_BACK | GAMEPAD_LEFT_THUMB | GAMEPAD_RIGHT_THUMB
        | GAMEPAD_LEFT_SHOULDER | GAMEPAD_RIGHT_SHOULDER | GAMEPAD_A | GAMEPAD_B | GAMEPAD_X | GAMEPAD_Y;
    state.gamepad.buttons & !known == 0
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
}
