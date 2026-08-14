// PS/2 relative-mouse packet decoding and input-core delivery. The i8042
// controller routes auxiliary bytes here after status-byte classification.

use core::sync::atomic::{AtomicU64, Ordering};

use sync::{Spinlock, TaskList as DriverLockClass};

use crate::ps2_mouse::{Assembler, Packet, PacketMode};

const PLATFORM_MOUSE_ID: u32 = 0x8042_0002;
const NO_EVDEV_ID: u64 = u64::MAX;
const BUS_I8042: u16 = 0x11;
const MOUSE_NAME: &[u8] = b"PS/2 Generic Mouse";

static MOUSE_EVDEV_ID: AtomicU64 = AtomicU64::new(NO_EVDEV_ID);
static ASSEMBLER: Spinlock<Assembler, DriverLockClass> = Spinlock::new(Assembler::new(PacketMode::Bare));


fn set_bit(bits: &mut [u8], bit: u16) {
    let index = bit as usize / 8;
    if let Some(byte) = bits.get_mut(index) {
        *byte |= 1u8 << (bit as usize % 8);
    }
}

fn emit(packet: Packet, evdev_id: u32) {
    let _ = input::push_evdev_event(evdev_id, input::EV_REL, input::REL_X, i32::from(packet.dx));
    let _ = input::push_evdev_event(evdev_id, input::EV_REL, input::REL_Y, i32::from(packet.dy));
    let _ = input::push_evdev_event(evdev_id, input::EV_KEY, input::BTN_LEFT, i32::from(packet.left));
    let _ = input::push_evdev_event(evdev_id, input::EV_KEY, input::BTN_RIGHT, i32::from(packet.right));
    let _ = input::push_evdev_event(evdev_id, input::EV_KEY, input::BTN_MIDDLE, i32::from(packet.middle));
    if packet.wheel != 0 { let _ = input::push_evdev_event(evdev_id, input::EV_REL, input::REL_WHEEL, i32::from(packet.wheel)); }
    if packet.hwheel != 0 { let _ = input::push_evdev_event(evdev_id, input::EV_REL, REL_HWHEEL, i32::from(packet.hwheel)); }
    let _ = input::push_evdev_event(evdev_id, input::EV_KEY, BTN_SIDE, i32::from(packet.side));
    let _ = input::push_evdev_event(evdev_id, input::EV_KEY, BTN_EXTRA, i32::from(packet.extra));
    let _ = input::push_evdev_event(evdev_id, input::EV_SYN, input::SYN_REPORT, 0);
}

/// Install the second i8042 port as one canonical relative input device.
/// # C: O(KEY_CNT + ABS_CNT)
pub(super) fn install_device(mode: PacketMode) -> bool {
    *ASSEMBLER.lock() = Assembler::new(mode);
    let mut dev = input::VirtioInputDev::empty_platform_boxed(PLATFORM_MOUSE_ID);
    dev.ids.bustype = BUS_I8042;
    dev.name[..MOUSE_NAME.len()].copy_from_slice(MOUSE_NAME);
    dev.name_len = MOUSE_NAME.len();
    dev.name_present = true;
    set_bit(&mut dev.ev_bits, input::EV_KEY);
    set_bit(&mut dev.ev_bits, input::EV_REL);
    set_bit(&mut dev.key_bits.bits, input::BTN_LEFT);
    set_bit(&mut dev.key_bits.bits, input::BTN_RIGHT);
    set_bit(&mut dev.key_bits.bits, input::BTN_MIDDLE);
    set_bit(&mut dev.rel_bits.bits, input::REL_X);
    set_bit(&mut dev.rel_bits.bits, input::REL_Y);
    if mode != PacketMode::Bare { set_bit(&mut dev.rel_bits.bits, input::REL_WHEEL); }
    if mode == PacketMode::Explorer {
        set_bit(&mut dev.rel_bits.bits, REL_HWHEEL);
        set_bit(&mut dev.key_bits.bits, BTN_SIDE);
        set_bit(&mut dev.key_bits.bits, BTN_EXTRA);
    }
    let Some((_, evdev_id)) = input::install(dev) else { return false; };
    if !input::publish_evdev(evdev_id) {
        let _ = input::remove_device(input::InputDeviceKey::platform(PLATFORM_MOUSE_ID));
        return false;
    }
    MOUSE_EVDEV_ID.store(evdev_id as u64, Ordering::Release);
    true
}

const REL_HWHEEL: u16 = 0x06;
const BTN_SIDE: u16 = 0x113;
const BTN_EXTRA: u16 = 0x114;

/// Remove the canonical mouse object and invalidate IRQ delivery first.
/// # C: O(N_devices + KEY_CNT)
pub(super) fn remove_device() {
    let evdev_id = MOUSE_EVDEV_ID.swap(NO_EVDEV_ID, Ordering::AcqRel);
    ASSEMBLER.lock().clear();
    if evdev_id == NO_EVDEV_ID { return; }
    let evdev_id = evdev_id as u32;
    let _ = input::unpublish_evdev(evdev_id);
    let _ = input::remove_device(input::InputDeviceKey::platform(PLATFORM_MOUSE_ID));
}

/// Feed one status-classified auxiliary byte from either i8042 legacy IRQ.
/// # C: O(1)
pub(super) fn handle_aux_byte(byte: u8) {
    let evdev_id = MOUSE_EVDEV_ID.load(Ordering::Acquire);
    if evdev_id == NO_EVDEV_ID { return; }
    let packet = ASSEMBLER.lock().push(byte);
    if let Some(packet) = packet { emit(packet, evdev_id as u32); }
}
