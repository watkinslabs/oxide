//! XWayland backend for native Windows HWND presentation.
//!
//! The transport adapter is intentionally supplied by the shared syscall
//! protocol owner. This crate owns X11 objects and translation only.

mod ffi;
mod geometry;
mod keyboard;
mod protocol;
mod readiness;
mod x11;
mod caret;

pub use geometry::{decode_cardinals, decode_work_area, MonitorSnapshot, Rect};
pub use keyboard::{evdev_x11_scan, key_flags, key_lparam, keysym_to_vk, state_utf8, ModifierMasks, Modifiers, Scan};
pub use readiness::{parse_args, publish_then_notify, Options, UsageError, READY_TOKEN};
pub use protocol::{BridgeCommand, BridgeEvent, Frame, Inbound, InputEvent, NativeTransport, StreamTransport, TransportError};
pub use x11::{Backend, BackendError, Xid};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workarea_uses_current_desktop_and_rejects_short_data() {
        let values = [0u32, 0, 1920, 1040, 1920, 0, 1920, 1040];
        assert_eq!(decode_work_area(&values, 1), Some(Rect { left: 1920, top: 0, right: 3840, bottom: 1040 }));
        assert_eq!(decode_work_area(&values[..7], 1), None);
    }

    #[test]
    fn cardinal_properties_require_exactly_one_value() {
        assert_eq!(decode_cardinals(&[3]), Some(3));
        assert_eq!(decode_cardinals(&[]), None);
        assert_eq!(decode_cardinals(&[3, 4]), None);
    }

    #[test]
    fn frame_validation_rejects_overflow_and_bad_damage() {
        let pixels = vec![0u32; 16];
        assert!(Frame::new(4, 4, 4, pixels.clone(), Rect { left: 0, top: 0, right: 4, bottom: 4 }).is_ok());
        assert!(Frame::new(4, 4, 3, pixels.clone(), Rect { left: 0, top: 0, right: 4, bottom: 4 }).is_err());
        assert!(Frame::new(4, 4, 4, pixels, Rect { left: 3, top: 0, right: 5, bottom: 4 }).is_err());
    }

    #[test]
    fn event_decoder_rejects_unknown_and_decodes_close() {
        assert_eq!(x11::decode_event(&[255, 0, 0, 0]), None);
        let mut event = [0u8; 32];
        event[0] = ffi::CLIENT_MESSAGE;
        event[1] = 32;
        event[4..8].copy_from_slice(&9u32.to_ne_bytes());
        event[8..12].copy_from_slice(&7u32.to_ne_bytes());
        event[12..16].copy_from_slice(&11u32.to_ne_bytes());
        assert_eq!(x11::decode_event(&event), Some(BridgeEvent::Close { hwnd: 9 }));
    }

    #[test]
    fn key_event_wire_contains_real_vk_scan_and_flags() {
        let event = BridgeEvent::Input(InputEvent::Key { hwnd: 9, press: true, virtual_key: 0x41, scan_code: 0x1e, modifiers: keyboard::KEY_EXTENDED | keyboard::KEY_PREVIOUS });
        let (opcode, hwnd, payload, _) = protocol::encode_event(&event, 1).unwrap();
        assert_eq!(opcode, syscall::nt_compositor::Opcode::Key);
        assert_eq!(hwnd, 9);
        assert_eq!(syscall::nt_compositor::u32_at(&payload, 0), Ok(0x41));
        assert_eq!(syscall::nt_compositor::u32_at(&payload, 4), Ok(0x1e));
        assert_eq!(syscall::nt_compositor::u32_at(&payload, 8), Ok(1));
        assert_eq!(syscall::nt_compositor::u32_at(&payload, 12), Ok(keyboard::KEY_EXTENDED | keyboard::KEY_PREVIOUS));
        let invalid = BridgeEvent::Input(InputEvent::Key { hwnd: 9, press: true, virtual_key: 0, scan_code: 0x1e, modifiers: 0 });
        assert!(protocol::encode_event(&invalid, 1).is_err());
    }

    #[test]
    fn focus_event_wire_uses_shared_bool_opcode() {
        let event = BridgeEvent::Input(InputEvent::Focus { hwnd: 9, focused: true });
        let (opcode, hwnd, payload, _) = protocol::encode_event(&event, 1).unwrap();
        assert_eq!(opcode, syscall::nt_compositor::Opcode::Focus);
        assert_eq!(hwnd, 9);
        assert_eq!(payload, 1u32.to_le_bytes());
        assert!(protocol::encode_event(&BridgeEvent::Input(InputEvent::Focus { hwnd: 0, focused: true }), 1).is_err());
    }
}

#[cfg(test)]
#[path = "tests/xvfb_integration.rs"]
mod xvfb_integration;
