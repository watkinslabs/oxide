//! Canonical host-input to user32 message translation.

use syscall::nt::NtWindowMessage;

pub const WM_MOUSEMOVE: u32 = 0x0200;
pub const WM_LBUTTONDOWN: u32 = 0x0201;
pub const WM_LBUTTONUP: u32 = 0x0202;
pub const WM_RBUTTONDOWN: u32 = 0x0204;
pub const WM_RBUTTONUP: u32 = 0x0205;
pub const WM_MBUTTONDOWN: u32 = 0x0207;
pub const WM_MBUTTONUP: u32 = 0x0208;
pub const WM_MOUSEWHEEL: u32 = 0x020a;
pub const WM_KEYDOWN: u32 = 0x0100;
pub const WM_KEYUP: u32 = 0x0101;
pub const WM_SYSKEYDOWN: u32 = 0x0104;
pub const WM_SYSKEYUP: u32 = 0x0105;
pub const MK_LBUTTON: u16 = 0x0001;
pub const MK_RBUTTON: u16 = 0x0002;
pub const MK_SHIFT: u16 = 0x0004;
pub const MK_CONTROL: u16 = 0x0008;
pub const MK_MBUTTON: u16 = 0x0010;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MouseButton { Left, Right, Middle }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum HostInput {
    Move { x: i32, y: i32 },
    Button { button: MouseButton, pressed: bool },
    Wheel { delta: i16 },
    /// Linux EV_KEY value: 0 release, 1 press, 2 autorepeat.
    Key { virtual_key: u16, scan_code: u8, value: u8, extended: bool, alt: bool },
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct InputRoute { pub hit: Option<u64>, pub focus: Option<u64>, pub capture: Option<u64> }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum InputError { NoMouseTarget, NoFocusTarget, InvalidKeyState, InvalidVirtualKey }

/// Stateful translation boundary for host pointer events. Capture is selected
/// by the native window owner; this type only applies that selection and keeps
/// the Windows button-state bits coherent across messages.
pub struct InputTranslator { x: i32, y: i32, buttons: u16, keys: [u64; 4] }

impl InputTranslator {
    /// Start with the host cursor at the origin and no pressed buttons. # C: O(1)
    pub const fn new() -> Self { Self { x: 0, y: 0, buttons: 0, keys: [0; 4] } }

    /// Translate one host event to the exact message payload user32 consumes. # C: O(1)
    pub fn translate(&mut self, event: HostInput, route: InputRoute) -> Result<NtWindowMessage, InputError> {
        let hwnd = match event {
            HostInput::Wheel { .. } => route.focus.ok_or(InputError::NoFocusTarget)?,
            HostInput::Key { .. } => route.focus.ok_or(InputError::NoFocusTarget)?,
            _ => route.capture.or(route.hit).ok_or(InputError::NoMouseTarget)?,
        };
        let (message, wparam, key_lparam) = match event {
            HostInput::Move { x, y } => { self.x = x; self.y = y; (WM_MOUSEMOVE, self.buttons as u32, None) }
            HostInput::Button { button, pressed } => {
                let (message, bit) = button_message(button, pressed);
                if pressed { self.buttons |= bit; } else { self.buttons &= !bit; }
                (message, self.buttons as u32, None)
            }
            HostInput::Wheel { delta } => (WM_MOUSEWHEEL, self.buttons as u32 | ((delta as u16 as u32) << 16), None),
            HostInput::Key { virtual_key, scan_code, value, extended, alt } => {
                let (message, wparam, lparam) = self.translate_key(virtual_key, scan_code, value, extended, alt)?;
                (message, wparam, Some(lparam))
            }
        };
        Ok(NtWindowMessage { hwnd, message, padding: 0, wparam: wparam as u64, lparam: key_lparam.unwrap_or_else(|| mouse_lparam(self.x, self.y)) })
    }

    fn translate_key(&mut self, virtual_key: u16, scan_code: u8, value: u8, extended: bool, alt: bool) -> Result<(u32, u32, i64), InputError> {
        if virtual_key > 0xff { return Err(InputError::InvalidVirtualKey); }
        if value > 2 { return Err(InputError::InvalidKeyState); }
        let slot = virtual_key as usize / 64;
        let mask = 1u64 << (virtual_key as usize % 64);
        let was_down = self.keys[slot] & mask != 0;
        let lparam = self.key_lparam(was_down, scan_code, value, extended, alt);
        if value == 0 { self.keys[slot] &= !mask; } else { self.keys[slot] |= mask; }
        let message = if alt {
            if value == 0 { WM_SYSKEYUP } else { WM_SYSKEYDOWN }
        } else if value == 0 { WM_KEYUP } else { WM_KEYDOWN };
        Ok((message, virtual_key as u32, lparam))
    }

    fn key_lparam(&self, was_down: bool, scan_code: u8, value: u8, extended: bool, alt: bool) -> i64 {
        let mut bits = (scan_code as u32) << 16;
        if extended { bits |= 1 << 24; }
        if alt { bits |= 1 << 29; }
        if was_down || value == 2 { bits |= 1 << 30; }
        if value == 0 { bits |= 1 << 31; }
        bits as i32 as i64
    }

    /// Return the last host cursor position in screen coordinates. # C: O(1)
    pub const fn cursor(&self) -> (i32, i32) { (self.x, self.y) }

    /// Return the button mask carried by the next pointer message. # C: O(1)
    pub const fn buttons(&self) -> u16 { self.buttons }
}

fn button_message(button: MouseButton, pressed: bool) -> (u32, u16) {
    match (button, pressed) {
        (MouseButton::Left, true) => (WM_LBUTTONDOWN, MK_LBUTTON),
        (MouseButton::Left, false) => (WM_LBUTTONUP, MK_LBUTTON),
        (MouseButton::Right, true) => (WM_RBUTTONDOWN, MK_RBUTTON),
        (MouseButton::Right, false) => (WM_RBUTTONUP, MK_RBUTTON),
        (MouseButton::Middle, true) => (WM_MBUTTONDOWN, MK_MBUTTON),
        (MouseButton::Middle, false) => (WM_MBUTTONUP, MK_MBUTTON),
    }
}

/// Encode signed client coordinates in the two 16-bit mouse-message fields. # C: O(1)
pub const fn mouse_lparam(x: i32, y: i32) -> i64 { (((y as u16 as u32) << 16) | x as u16 as u32) as i64 }

#[cfg(test)]
mod tests {
    use super::*;

    fn route(hit: u64) -> InputRoute { InputRoute { hit: Some(hit), focus: Some(9), capture: None } }

    #[test]
    fn move_uses_hit_window_and_signed_coordinates() {
        let mut input = InputTranslator::new();
        assert_eq!(input.translate(HostInput::Move { x: -3, y: 0x1234 }, route(7)).unwrap(), NtWindowMessage { hwnd: 7, message: WM_MOUSEMOVE, padding: 0, wparam: 0, lparam: mouse_lparam(-3, 0x1234) });
        assert_eq!(input.cursor(), (-3, 0x1234));
    }

    #[test]
    fn capture_wins_over_hit_testing_for_move_and_buttons() {
        let mut input = InputTranslator::new();
        let route = InputRoute { hit: Some(7), focus: Some(9), capture: Some(11) };
        assert_eq!(input.translate(HostInput::Move { x: 20, y: 21 }, route).unwrap().hwnd, 11);
        assert_eq!(input.translate(HostInput::Button { button: MouseButton::Left, pressed: true }, route).unwrap().hwnd, 11);
    }

    #[test]
    fn button_transitions_are_not_dropped_and_carry_state_after_transition() {
        let mut input = InputTranslator::new();
        let down = input.translate(HostInput::Button { button: MouseButton::Left, pressed: true }, route(7)).unwrap();
        let both = input.translate(HostInput::Button { button: MouseButton::Right, pressed: true }, route(7)).unwrap();
        let up = input.translate(HostInput::Button { button: MouseButton::Left, pressed: false }, route(7)).unwrap();
        assert_eq!((down.message, down.wparam as u16), (WM_LBUTTONDOWN, MK_LBUTTON));
        assert_eq!((both.message, both.wparam as u16), (WM_RBUTTONDOWN, MK_LBUTTON | MK_RBUTTON));
        assert_eq!((up.message, up.wparam as u16), (WM_LBUTTONUP, MK_RBUTTON));
        assert_eq!(input.buttons(), MK_RBUTTON);
    }

    #[test]
    fn wheel_preserves_buttons_and_signed_delta_in_high_word() {
        let mut input = InputTranslator::new();
        input.translate(HostInput::Button { button: MouseButton::Middle, pressed: true }, route(7)).unwrap();
        let message = input.translate(HostInput::Wheel { delta: -120 }, route(7)).unwrap();
        assert_eq!(message.message, WM_MOUSEWHEEL);
        assert_eq!(message.wparam as u16, MK_MBUTTON);
        assert_eq!((message.wparam >> 16) as u16, (-120i16) as u16);
    }

    #[test]
    fn wheel_routes_to_keyboard_focus_instead_of_hit_or_capture() {
        let mut input = InputTranslator::new();
        let route = InputRoute { hit: Some(7), focus: Some(9), capture: Some(11) };
        let message = input.translate(HostInput::Wheel { delta: 120 }, route).unwrap();
        assert_eq!(message.hwnd, 9);
    }

    #[test]
    fn wheel_requires_keyboard_focus() {
        let mut input = InputTranslator::new();
        let route = InputRoute { hit: Some(7), focus: None, capture: Some(11) };
        assert_eq!(input.translate(HostInput::Wheel { delta: 120 }, route), Err(InputError::NoFocusTarget));
    }

    #[test]
    fn absent_hit_and_capture_is_a_hard_translation_error() {
        let mut input = InputTranslator::new();
        let route = InputRoute { hit: None, focus: Some(9), capture: None };
        assert_eq!(input.translate(HostInput::Move { x: 1, y: 2 }, route), Err(InputError::NoMouseTarget));
    }

    #[test]
    fn focus_does_not_steal_pointer_target() {
        let mut input = InputTranslator::new();
        let message = input.translate(HostInput::Move { x: 1, y: 2 }, route(7)).unwrap();
        assert_eq!(message.hwnd, 7);
        assert_ne!(message.hwnd, 9);
    }

    #[test]
    fn keyboard_press_repeat_release_preserves_windows_transition_bits() {
        let mut input = InputTranslator::new();
        let route = route(7);
        let down = input.translate(HostInput::Key { virtual_key: 0x41, scan_code: 0x1e, value: 1, extended: false, alt: false }, route).unwrap();
        assert_eq!((down.message, down.wparam, down.lparam), (WM_KEYDOWN, 0x41, 0x001e0000));
        let repeat = input.translate(HostInput::Key { virtual_key: 0x41, scan_code: 0x1e, value: 2, extended: false, alt: false }, route).unwrap();
        assert_eq!(repeat.lparam, 0x401e0000);
        let up = input.translate(HostInput::Key { virtual_key: 0x41, scan_code: 0x1e, value: 0, extended: false, alt: false }, route).unwrap();
        assert_eq!((up.message, up.lparam), (WM_KEYUP, -1071775744));
    }

    #[test]
    fn extended_alt_key_targets_focus_and_selects_system_messages() {
        let mut input = InputTranslator::new();
        let route = InputRoute { hit: Some(7), focus: Some(9), capture: Some(11) };
        let message = input.translate(HostInput::Key { virtual_key: 0x12, scan_code: 0x38, value: 1, extended: true, alt: true }, route).unwrap();
        assert_eq!(message.hwnd, 9);
        assert_eq!(message.message, WM_SYSKEYDOWN);
        assert_eq!(message.lparam, 0x21380000);
    }

    #[test]
    fn malformed_linux_key_values_and_virtual_keys_are_rejected() {
        let mut input = InputTranslator::new();
        let route = route(7);
        assert_eq!(input.translate(HostInput::Key { virtual_key: 0x41, scan_code: 0, value: 3, extended: false, alt: false }, route), Err(InputError::InvalidKeyState));
        assert_eq!(input.translate(HostInput::Key { virtual_key: 0x100, scan_code: 0, value: 1, extended: false, alt: false }, route), Err(InputError::InvalidVirtualKey));
    }
}
