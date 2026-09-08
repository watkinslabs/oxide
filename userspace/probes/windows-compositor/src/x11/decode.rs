//! One X wire event's 32 bytes as a bridge event.
//!
//! Every field is read at the offset the protocol fixes for that event, and a
//! pointer event names the window the server delivered it to and the point in
//! that window's own coordinates: a control's press is the control's press.

use super::{ffi, BridgeEvent, InputEvent};
use crate::geometry::{MonitorSnapshot, Rect};

pub fn decode_event(raw: &[u8]) -> Option<BridgeEvent> {
    if raw.len() < 32 { return None; }
    let kind = raw[0] & 0x7f;
    let xid = |offset| u32::from_ne_bytes(raw[offset..offset + 4].try_into().ok().unwrap());
    match kind {
        ffi::CLIENT_MESSAGE => Some(BridgeEvent::Close { hwnd: xid(4) }),
        ffi::CONFIGURE_NOTIFY => Some(BridgeEvent::Configure { hwnd: xid(8), rect: Rect { left: i16::from_ne_bytes([raw[16], raw[17]]) as i32, top: i16::from_ne_bytes([raw[18], raw[19]]) as i32, right: i16::from_ne_bytes([raw[16], raw[17]]) as i32 + u16::from_ne_bytes([raw[20], raw[21]]) as i32, bottom: i16::from_ne_bytes([raw[18], raw[19]]) as i32 + u16::from_ne_bytes([raw[22], raw[23]]) as i32 } }),
        ffi::KEY_PRESS | ffi::KEY_RELEASE => Some(BridgeEvent::Input(InputEvent::Key { hwnd: xid(12), press: kind == ffi::KEY_PRESS, virtual_key: 0, scan_code: raw[1], modifiers: u16::from_ne_bytes([raw[28], raw[29]]) as u32 })),
        ffi::BUTTON_PRESS | ffi::BUTTON_RELEASE => Some(BridgeEvent::Input(InputEvent::Button { hwnd: xid(12), press: kind == ffi::BUTTON_PRESS, button: raw[1], x: i16::from_ne_bytes([raw[24], raw[25]]), y: i16::from_ne_bytes([raw[26], raw[27]]), state: u16::from_ne_bytes([raw[28], raw[29]]) })),
        ffi::MOTION_NOTIFY => Some(BridgeEvent::Input(InputEvent::Motion { hwnd: xid(12), x: i16::from_ne_bytes([raw[24], raw[25]]), y: i16::from_ne_bytes([raw[26], raw[27]]), state: u16::from_ne_bytes([raw[28], raw[29]]) })),
        // A pointer-boundary focus event reports where the pointer is, not who
        // owns the keyboard, and a grab's focus event reports the grab. Taking
        // either as an activation change deactivates a window whenever the
        // desktop grabs the keyboard, and reactivates it on release.
        ffi::FOCUS_IN | ffi::FOCUS_OUT => { if raw[1] == ffi::NOTIFY_POINTER || raw[8] == ffi::NOTIFY_GRAB || raw[8] == ffi::NOTIFY_UNGRAB { return None; } Some(BridgeEvent::Input(InputEvent::Focus { hwnd: xid(4), focused: kind == ffi::FOCUS_IN })) }
        ffi::PROPERTY_NOTIFY => Some(BridgeEvent::WorkArea(MonitorSnapshot { desktop: 0, monitor: Rect { left: 0, top: 0, right: 0, bottom: 0 }, work_area: Rect { left: 0, top: 0, right: 0, bottom: 0 } })),
        ffi::EXPOSE => Some(BridgeEvent::Damage { hwnd: xid(4), rect: Rect {
            left: u16::from_ne_bytes([raw[8], raw[9]]) as i32, top: u16::from_ne_bytes([raw[10], raw[11]]) as i32,
            right: u16::from_ne_bytes([raw[8], raw[9]]) as i32 + u16::from_ne_bytes([raw[12], raw[13]]) as i32,
            bottom: u16::from_ne_bytes([raw[10], raw[11]]) as i32 + u16::from_ne_bytes([raw[14], raw[15]]) as i32 } }),
        _ => None,
    }
}
