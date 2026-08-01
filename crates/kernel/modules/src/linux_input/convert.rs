use super::types::*;
use input::{VirtioInputAbsInfo, VirtioInputDev, VirtioInputDevIds};
use input::VirtioChildDeviceKey;

const BYTE_BITS: usize = 8;
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

pub(super) unsafe fn input_to_model(dev: *const LinuxInputDev) -> alloc::boxed::Box<VirtioInputDev> {
    // SAFETY: caller validates dev points at a live LinuxInputDev.
    let d = unsafe { &*dev };
    let mut model = VirtioInputDev::empty_boxed(VirtioChildDeviceKey::from_raw(d.oxide_key));
    model.is_pointer = test_bit(&d.evbit, EV_REL) || test_bit(&d.evbit, EV_ABS);
    model.name_present = !d.name.is_null();
    model.phys_present = !d.phys.is_null();
    model.serial_present = !d.uniq.is_null();
    model.ids = VirtioInputDevIds {
        bustype: d.id.bustype,
        vendor: d.id.vendor,
        product: d.id.product,
        version: d.id.version,
    };
    // SAFETY: registered Linux input string pointers remain live for the device lifetime.
    model.name_len = unsafe { copy_cstr(d.name, &mut model.name) };
    // SAFETY: registered Linux input string pointers remain live for the device lifetime.
    model.phys_len = unsafe { copy_cstr(d.phys, &mut model.phys) };
    // SAFETY: registered Linux input string pointers remain live for the device lifetime.
    model.serial_len = unsafe { copy_cstr(d.uniq, &mut model.serial) };
    copy_words_to_bytes(&d.evbit, EV_CNT, &mut model.ev_bits);
    copy_words_to_bytes(&d.keybit, KEY_CNT, &mut model.key_bits.bits);
    copy_words_to_bytes(&d.relbit, REL_CNT, &mut model.rel_bits.bits);
    copy_words_to_bytes(&d.absbit, ABS_CNT, &mut model.abs_bits.bits);
    copy_words_to_bytes(&d.mscbit, MSC_CNT, &mut model.msc_bits.bits);
    copy_words_to_bytes(&d.ledbit, LED_CNT, &mut model.led_bits.bits);
    copy_words_to_bytes(&d.sndbit, SND_CNT, &mut model.snd_bits.bits);
    copy_words_to_bytes(&d.ffbit, FF_CNT, &mut model.ff_bits.bits);
    copy_words_to_bytes(&d.swbit, SW_CNT, &mut model.sw_bits.bits);
    copy_words_to_bytes(&d.propbit, INPUT_PROP_CNT, &mut model.prop_bits);
    let mut key_state = [0u8; KEY_CNT / BYTE_BITS];
    copy_words_to_bytes(&d.key, KEY_CNT, &mut key_state);
    let _ = model.seed_state_bits(EV_KEY, &key_state);
    let mut led_state = [0u8; LED_CNT / BYTE_BITS];
    copy_words_to_bytes(&d.led, LED_CNT, &mut led_state);
    let _ = model.seed_state_bits(EV_LED, &led_state);
    let mut sound_state = [0u8; SND_CNT / BYTE_BITS];
    copy_words_to_bytes(&d.snd, SND_CNT, &mut sound_state);
    let _ = model.seed_state_bits(EV_SND, &sound_state);
    let mut switch_state = [0u8; (SW_CNT + BYTE_BITS - 1) / BYTE_BITS];
    copy_words_to_bytes(&d.sw, SW_CNT, &mut switch_state);
    let _ = model.seed_state_bits(EV_SW, &switch_state);
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
            let _ = model.seed_abs_value(axis as u16, a.value);
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
        let _modules = crate::test_serial::claim();
        const TEST_KEY_CODE: u16 = 30;
        let mut bits = [0usize; INPUT_KEY_WORDS];
        set_bit(&mut bits, TEST_KEY_CODE);
        assert!(test_bit(&bits, TEST_KEY_CODE));
        clear_bit(&mut bits, TEST_KEY_CODE);
        assert!(!test_bit(&bits, TEST_KEY_CODE));
    }
}
