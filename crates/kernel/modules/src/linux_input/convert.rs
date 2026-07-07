use super::types::*;
use input::{CapBitmap, VirtioInputAbsInfo, VirtioInputDev, VirtioInputDevIds};
use input::VirtioChildDeviceKey;

const BYTE_BITS: usize = 8;
const DEFAULT_REPEAT: [u32; 2] = input::DEFAULT_REPEAT;

pub(super) fn test_bit(bits: &[usize], bit: u16) -> bool {
    let bit = bit as usize;
    let word = bit / BITS_PER_LONG;
    let shift = bit % BITS_PER_LONG;
    bits.get(word).is_some_and(|slot| (*slot & (1usize << shift)) != 0)
}

pub(super) fn set_bit(bits: &mut [usize], bit: u16) {
    let bit = bit as usize;
    let word = bit / BITS_PER_LONG;
    let shift = bit % BITS_PER_LONG;
    if let Some(slot) = bits.get_mut(word) {
        *slot |= 1usize << shift;
    }
}

pub(super) fn clear_bit(bits: &mut [usize], bit: u16) {
    let bit = bit as usize;
    let word = bit / BITS_PER_LONG;
    let shift = bit % BITS_PER_LONG;
    if let Some(slot) = bits.get_mut(word) {
        *slot &= !(1usize << shift);
    }
}

pub(super) unsafe fn input_to_model(dev: *const LinuxInputDev) -> VirtioInputDev {
    // SAFETY: caller validates dev points at a live LinuxInputDev.
    let d = unsafe { &*dev };
    let mut model = VirtioInputDev {
        device_key: VirtioChildDeviceKey::from_raw(d.oxide_key),
        evdev_id: d.evdev_id,
        is_pointer: test_bit(&d.evbit, EV_REL) || test_bit(&d.evbit, EV_ABS),
        name: [0; INPUT_NAME_BYTES],
        name_len: 0,
        serial: [0; INPUT_SERIAL_BYTES],
        serial_len: 0,
        ids: VirtioInputDevIds {
            bustype: d.id.bustype,
            vendor: d.id.vendor,
            product: d.id.product,
            version: d.id.version,
        },
        ev_bits: [0; INPUT_EV_BITS],
        key_bits: CapBitmap::default(),
        rel_bits: CapBitmap::default(),
        abs_bits: CapBitmap::default(),
        led_bits: CapBitmap::default(),
        abs_info: [None; ABS_CNT],
        prop_bits: [0; INPUT_PROP_BYTES],
        repeat: DEFAULT_REPEAT,
    };
    model.name_len = unsafe { copy_cstr(d.name, &mut model.name) };
    model.serial_len = unsafe { copy_cstr(d.uniq, &mut model.serial) };
    copy_words_to_bytes(&d.evbit, EV_CNT, &mut model.ev_bits);
    copy_words_to_bytes(&d.keybit, KEY_CNT, &mut model.key_bits.bits);
    copy_words_to_bytes(&d.relbit, REL_CNT, &mut model.rel_bits.bits);
    copy_words_to_bytes(&d.absbit, ABS_CNT, &mut model.abs_bits.bits);
    copy_words_to_bytes(&d.ledbit, LED_CNT, &mut model.led_bits.bits);
    copy_words_to_bytes(&d.propbit, INPUT_PROP_CNT, &mut model.prop_bits);
    for axis in 0..ABS_CNT {
        if test_bit(&d.absbit, axis as u16) {
            let a = d.absinfo[axis];
            model.abs_info[axis] = Some(VirtioInputAbsInfo {
                min: a.minimum as u32,
                max: a.maximum as u32,
                fuzz: a.fuzz as u32,
                flat: a.flat as u32,
                res: a.resolution as u32,
            });
        }
    }
    model
}

unsafe fn copy_cstr(src: *const core::ffi::c_char, dst: &mut [u8]) -> usize {
    if src.is_null() { return 0; }
    let mut i = 0;
    while i < dst.len() {
        // SAFETY: Linux input strings are NUL-terminated C strings owned by the registering driver.
        let b = unsafe { *src.add(i) as u8 };
        if b == 0 { break; }
        dst[i] = b;
        i += 1;
    }
    i
}

fn copy_words_to_bytes(src: &[usize], bits: usize, dst: &mut [u8]) {
    for bit in 0..bits {
        let word = bit / BITS_PER_LONG;
        let shift = bit % BITS_PER_LONG;
        let Some(slot) = src.get(word) else { continue; };
        if (*slot & (1usize << shift)) == 0 { continue; }
        let byte = bit / BYTE_BITS;
        let bit_in_byte = bit % BYTE_BITS;
        if let Some(out) = dst.get_mut(byte) {
            *out |= 1u8 << bit_in_byte;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bit_helpers_round_trip() {
        let mut bits = [0usize; INPUT_KEY_WORDS];
        set_bit(&mut bits, 30);
        assert!(test_bit(&bits, 30));
        clear_bit(&mut bits, 30);
        assert!(!test_bit(&bits, 30));
    }
}
