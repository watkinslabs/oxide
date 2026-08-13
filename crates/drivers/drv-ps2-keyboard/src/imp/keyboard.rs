//! i8042 keyboard publication through the canonical evdev input owner.

use core::sync::atomic::{AtomicU64, Ordering};

const PLATFORM_KEYBOARD_ID: u32 = 0x8042_0001;
const NO_EVDEV_ID: u64 = u64::MAX;
const BUS_I8042: u16 = 0x11;
const KEYBOARD_NAME: &[u8] = b"AT Translated Set 2 keyboard";

static EVDEV_ID: AtomicU64 = AtomicU64::new(NO_EVDEV_ID);

fn set_bit(bits: &mut [u8], bit: u16) {
    let byte = bit as usize / 8;
    if let Some(slot) = bits.get_mut(byte) { *slot |= 1 << (bit as usize % 8); }
}

/// Publish the first i8042 port as one canonical keyboard input device. # C: O(KEY_CNT)
pub(super) fn install_device() -> bool {
    let mut dev = input::VirtioInputDev::empty_platform_boxed(PLATFORM_KEYBOARD_ID);
    dev.ids.bustype = BUS_I8042;
    dev.name[..KEYBOARD_NAME.len()].copy_from_slice(KEYBOARD_NAME);
    dev.name_len = KEYBOARD_NAME.len();
    dev.name_present = true;
    set_bit(&mut dev.ev_bits, input::EV_KEY);
    for key in 1..input::KEY_CNT as u16 { set_bit(&mut dev.key_bits.bits, key); }
    let Some((_, id)) = input::install(dev) else { return false; };
    if !input::publish_evdev(id) {
        let _ = input::remove_device(input::InputDeviceKey::platform(PLATFORM_KEYBOARD_ID));
        return false;
    }
    EVDEV_ID.store(id as u64, Ordering::Release);
    true
}

/// Withdraw the first i8042 port from evdev before controller teardown. # C: O(N_devices)
pub(super) fn remove_device() {
    let id = EVDEV_ID.swap(NO_EVDEV_ID, Ordering::AcqRel);
    if id == NO_EVDEV_ID { return; }
    let _ = input::unpublish_evdev(id as u32);
    let _ = input::remove_device(input::InputDeviceKey::platform(PLATFORM_KEYBOARD_ID));
}

/// Report a decoded scancode through evdev as one synchronized input frame. # C: O(1)
pub(super) fn report_key(key: u16, pressed: bool) {
    let id = EVDEV_ID.load(Ordering::Acquire);
    if id == NO_EVDEV_ID { return; }
    let _ = input::push_evdev_event(id as u32, input::EV_KEY, key, i32::from(pressed));
    let _ = input::push_evdev_event(id as u32, input::EV_SYN, input::SYN_REPORT, 0);
}
