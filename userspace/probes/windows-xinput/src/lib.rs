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
}
