use crate::registry::{VirtioInputDev, DEVICES};
use crate::uapi::*;

pub const XINPUT_MAX_CONTROLLERS: u32 = 4;

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
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
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct XInputState { pub packet_number: u32, pub gamepad: XInputGamepad }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ControllerError { InvalidIndex, DeviceNotConnected }

const AXES: [u16; 6] = [ABS_Z, ABS_RZ, ABS_X, ABS_Y, ABS_RX, ABS_RY];

fn bit(bits: &[u8], code: u16) -> bool {
    bits.get(code as usize / 8).is_some_and(|v| v & (1 << (code % 8)) != 0)
}

fn axis(dev: &VirtioInputDev, code: u16) -> Option<(i32, i32, i32)> {
    let info = dev.abs_parameters(code)?;
    Some((dev.abs_value(code)?, info.min as i32, info.max as i32))
}

fn is_controller(dev: &VirtioInputDev) -> bool {
    bit(&dev.ev_bits, EV_ABS)
        && AXES.iter().all(|code| bit(&dev.abs_bits.bits, *code) && dev.abs_parameters(*code).is_some())
}

fn trigger(value: i32, min: i32, max: i32) -> Option<u8> {
    let value = i64::from(value) - i64::from(min);
    let span = i64::from(max) - i64::from(min);
    if span <= 0 || value < 0 || value > span { return None; }
    Some(((value * 255 + span / 2) / span) as u8)
}

fn thumb(value: i32, min: i32, max: i32) -> Option<i16> {
    let value = i64::from(value) - i64::from(min);
    let span = i64::from(max) - i64::from(min);
    if span <= 0 || value < 0 || value > span { return None; }
    Some((((value * 65_535 + span / 2) / span) - 32_768) as i16)
}

fn buttons(dev: &VirtioInputDev) -> u16 {
    let key = |code, mask| if bit(&dev.key_state.bits, code) { mask } else { 0 };
    key(BTN_DPAD_UP, 0x0001) | key(BTN_DPAD_DOWN, 0x0002)
        | key(BTN_DPAD_LEFT, 0x0004) | key(BTN_DPAD_RIGHT, 0x0008)
        | key(BTN_START, 0x0010) | key(BTN_SELECT, 0x0020)
        | key(BTN_THUMBL, 0x0040) | key(BTN_THUMBR, 0x0080)
        | key(BTN_TL, 0x0100) | key(BTN_TR, 0x0200)
        | key(BTN_SOUTH, 0x1000) | key(BTN_EAST, 0x2000)
        | key(BTN_NORTH, 0x4000) | key(BTN_WEST, 0x8000)
}

fn snapshot(dev: &VirtioInputDev) -> Option<XInputState> {
    if !dev.connected || dev.inhibited || !is_controller(dev) { return None; }
    let [lt, rt, lx, ly, rx, ry] = AXES.map(|code| axis(dev, code));
    let (ltv, ltm, ltx) = lt?;
    let (rtv, rtm, rtx) = rt?;
    let (lxv, lxm, lxx) = lx?;
    let (lyv, lym, lyx) = ly?;
    let (rxv, rxm, rxx) = rx?;
    let (ryv, rym, ryx) = ry?;
    Some(XInputState {
        packet_number: dev.controller_packet,
        gamepad: XInputGamepad {
            buttons: buttons(dev),
            left_trigger: trigger(ltv, ltm, ltx)?,
            right_trigger: trigger(rtv, rtm, rtx)?,
            thumb_lx: thumb(lxv, lxm, lxx)?,
            thumb_ly: thumb(lyv, lym, lyx)?.wrapping_neg(),
            thumb_rx: thumb(rxv, rxm, rxx)?,
            thumb_ry: thumb(ryv, rym, ryx)?.wrapping_neg(),
        },
    })
}

/// Read the bounded XInput controller slot from the canonical input registry.
/// Disconnected records retain their slot until removal, matching hotplug
/// semantics without creating a second controller registry.
/// # C: O(N_devices)
pub fn controller_state(index: u32) -> Result<XInputState, ControllerError> {
    if index >= XINPUT_MAX_CONTROLLERS { return Err(ControllerError::InvalidIndex); }
    let devices = DEVICES.lock();
    let mut slot = 0;
    for dev in devices.iter() {
        if !is_controller(dev) { continue; }
        if slot == index {
            return snapshot(dev).ok_or(ControllerError::DeviceNotConnected);
        }
        slot += 1;
    }
    Err(ControllerError::DeviceNotConnected)
}

impl VirtioInputDev {
    pub(crate) fn controller_event(&self, ev_type: u16, code: u16) -> bool {
        is_controller(self) && ((ev_type == EV_KEY) || (ev_type == EV_ABS && AXES.contains(&code)))
    }
}
