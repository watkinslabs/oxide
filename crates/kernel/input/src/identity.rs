use alloc::{string::String, vec::Vec};
use core::fmt::Write;

use crate::registry::VirtioInputDev;
use crate::uapi::{
    ABS_CNT, ABS_MAX, EV_ABS, EV_CNT, EV_FF, EV_KEY, EV_LED, EV_MAX, EV_MSC, EV_REL,
    EV_SND, EV_SW, EV_SYN, FF_CNT, FF_MAX, INPUT_PROP_CNT, KEY_CNT, KEY_MAX,
    KEY_MIN_INTERESTING, KEY_RESERVED, LED_CNT, LED_MAX, MSC_CNT, MSC_MAX, REL_CNT,
    REL_MAX, SND_CNT, SND_MAX, SW_CNT, SW_MAX,
};

fn bit_is_set(bits: &[u8], bit: usize) -> bool {
    bits.get(bit / 8).is_some_and(|byte| byte & (1u8 << (bit % 8)) != 0)
}

fn set_bit(bits: &mut [u8], bit: usize) {
    if let Some(byte) = bits.get_mut(bit / 8) {
        *byte |= 1u8 << (bit % 8);
    }
}

fn bound_bitmap(bits: &mut [u8], count: usize) {
    let full_bytes = count / 8;
    let tail_bits = count % 8;
    if tail_bits != 0 {
        if let Some(byte) = bits.get_mut(full_bytes) {
            *byte &= (1u8 << tail_bits) - 1;
        }
    }
    let clear_from = full_bytes + usize::from(tail_bits != 0);
    bits.get_mut(clear_from..).unwrap_or(&mut []).fill(0);
}

fn clear_unadvertised(ev_bits: &[u8], event_type: usize, bits: &mut [u8]) {
    if !bit_is_set(ev_bits, event_type) {
        bits.fill(0);
    }
}

fn mask_state(state: &mut [u8], capabilities: &[u8], count: usize) {
    bound_bitmap(state, count);
    for (state_byte, capability_byte) in state.iter_mut().zip(capabilities) {
        *state_byte &= *capability_byte;
    }
}

fn logical_len(bytes: &[u8], len: usize) -> usize {
    let len = len.min(bytes.len());
    bytes[..len].iter().position(|byte| *byte == 0).unwrap_or(len)
}

/// # C: O(capability bytes + MT slots)
pub(crate) fn normalize(dev: &mut VirtioInputDev) {
    bound_bitmap(&mut dev.ev_bits, EV_CNT);
    bound_bitmap(&mut dev.prop_bits, INPUT_PROP_CNT);
    bound_bitmap(&mut dev.key_bits.bits, KEY_CNT);
    bound_bitmap(&mut dev.rel_bits.bits, REL_CNT);
    bound_bitmap(&mut dev.abs_bits.bits, ABS_CNT);
    bound_bitmap(&mut dev.msc_bits.bits, MSC_CNT);
    bound_bitmap(&mut dev.led_bits.bits, LED_CNT);
    bound_bitmap(&mut dev.snd_bits.bits, SND_CNT);
    bound_bitmap(&mut dev.ff_bits.bits, FF_CNT);
    bound_bitmap(&mut dev.sw_bits.bits, SW_CNT);
    set_bit(&mut dev.ev_bits, EV_SYN as usize);
    dev.key_bits.bits[KEY_RESERVED as usize / 8] &= !(1u8 << (KEY_RESERVED % 8));
    clear_unadvertised(&dev.ev_bits, EV_KEY as usize, &mut dev.key_bits.bits);
    clear_unadvertised(&dev.ev_bits, EV_REL as usize, &mut dev.rel_bits.bits);
    clear_unadvertised(&dev.ev_bits, EV_ABS as usize, &mut dev.abs_bits.bits);
    clear_unadvertised(&dev.ev_bits, EV_MSC as usize, &mut dev.msc_bits.bits);
    clear_unadvertised(&dev.ev_bits, EV_LED as usize, &mut dev.led_bits.bits);
    clear_unadvertised(&dev.ev_bits, EV_SND as usize, &mut dev.snd_bits.bits);
    clear_unadvertised(&dev.ev_bits, EV_FF as usize, &mut dev.ff_bits.bits);
    clear_unadvertised(&dev.ev_bits, EV_SW as usize, &mut dev.sw_bits.bits);
    mask_state(&mut dev.key_state.bits, &dev.key_bits.bits, KEY_CNT);
    mask_state(&mut dev.switch_state.bits, &dev.sw_bits.bits, SW_CNT);
    mask_state(&mut dev.led_state.bits, &dev.led_bits.bits, LED_CNT);
    mask_state(&mut dev.sound_state.bits, &dev.snd_bits.bits, SND_CNT);
    dev.name_len = logical_len(&dev.name, dev.name_len);
    dev.phys_len = logical_len(&dev.phys, dev.phys_len);
    dev.serial_len = logical_len(&dev.serial, dev.serial_len);
    dev.is_pointer = bit_is_set(&dev.ev_bits, EV_REL as usize)
        || bit_is_set(&dev.ev_bits, EV_ABS as usize);
    dev.configure_absolute();
}

/// Native-word bitmap text used by input sysfs attributes.
/// # C: O(bits.len())
pub fn format_bitmap(bits: &[u8]) -> String {
    const WORD_BYTES: usize = core::mem::size_of::<u64>();
    let mut out = String::new();
    for chunk in bits.chunks(WORD_BYTES).rev() {
        let mut word = 0u64;
        for (shift, byte) in chunk.iter().enumerate() {
            word |= u64::from(*byte) << (shift * 8);
        }
        if out.is_empty() && word == 0 { continue; }
        if !out.is_empty() { out.push(' '); }
        let _ = write!(out, "{word:x}");
    }
    if out.is_empty() { out.push('0'); }
    out
}

fn push_modalias_bits(out: &mut String, name: char, bits: &[u8], first: usize, count: usize) {
    out.push(name);
    for bit in first..count {
        if bit_is_set(bits, bit) {
            let _ = write!(out, "{bit:X},");
        }
    }
}

/// Input modalias derived from canonical identity and capabilities.
/// # C: O(capability bits)
pub fn modalias(dev: &VirtioInputDev) -> String {
    let mut out = alloc::format!(
        "input:b{:04X}v{:04X}p{:04X}e{:04X}-",
        dev.ids.bustype, dev.ids.vendor, dev.ids.product, dev.ids.version,
    );
    push_modalias_bits(&mut out, 'e', &dev.ev_bits, 0, EV_MAX as usize);
    push_modalias_bits(
        &mut out, 'k', &dev.key_bits.bits, KEY_MIN_INTERESTING, KEY_MAX as usize,
    );
    push_modalias_bits(&mut out, 'r', &dev.rel_bits.bits, 0, REL_MAX as usize);
    push_modalias_bits(&mut out, 'a', &dev.abs_bits.bits, 0, ABS_MAX as usize);
    push_modalias_bits(&mut out, 'm', &dev.msc_bits.bits, 0, MSC_MAX as usize);
    push_modalias_bits(&mut out, 'l', &dev.led_bits.bits, 0, LED_MAX as usize);
    push_modalias_bits(&mut out, 's', &dev.snd_bits.bits, 0, SND_MAX as usize);
    push_modalias_bits(&mut out, 'f', &dev.ff_bits.bits, 0, FF_MAX as usize);
    push_modalias_bits(&mut out, 'w', &dev.sw_bits.bits, 0, SW_MAX as usize);
    out
}

fn quoted_env(name: &str, bytes: &[u8], present: bool) -> Option<Vec<u8>> {
    present.then(|| {
        let mut value = Vec::with_capacity(name.len() + bytes.len() + 3);
        value.extend_from_slice(name.as_bytes());
        value.extend_from_slice(b"=\"");
        value.extend_from_slice(bytes);
        value.push(b'"');
        value
    })
}

/// Input uevent environment from one retained canonical snapshot.
/// # C: O(capability bits)
pub fn uevent_env_for(dev: &VirtioInputDev) -> Vec<Vec<u8>> {
    let mut env = alloc::vec![alloc::format!(
        "PRODUCT={:x}/{:x}/{:x}/{:x}",
        dev.ids.bustype, dev.ids.vendor, dev.ids.product, dev.ids.version,
    ).into_bytes()];
    if let Some(value) = quoted_env("NAME", &dev.name[..dev.name_len], dev.name_present) {
        env.push(value);
    }
    if let Some(value) = quoted_env("PHYS", &dev.phys[..dev.phys_len], dev.phys_present) {
        env.push(value);
    }
    if let Some(value) = quoted_env("UNIQ", &dev.serial[..dev.serial_len], dev.serial_present) {
        env.push(value);
    }
    env.push(alloc::format!("PROP={}", format_bitmap(&dev.prop_bits)).into_bytes());
    env.push(alloc::format!("EV={}", format_bitmap(&dev.ev_bits)).into_bytes());
    let caps = [
        (EV_KEY as usize, "KEY", &dev.key_bits.bits[..]),
        (EV_REL as usize, "REL", &dev.rel_bits.bits[..]),
        (EV_ABS as usize, "ABS", &dev.abs_bits.bits[..]),
        (EV_MSC as usize, "MSC", &dev.msc_bits.bits[..]),
        (EV_LED as usize, "LED", &dev.led_bits.bits[..]),
        (EV_SND as usize, "SND", &dev.snd_bits.bits[..]),
        (EV_FF as usize, "FF", &dev.ff_bits.bits[..]),
        (EV_SW as usize, "SW", &dev.sw_bits.bits[..]),
    ];
    for (event_type, name, bits) in caps {
        if bit_is_set(&dev.ev_bits, event_type) {
            env.push(alloc::format!("{name}={}", format_bitmap(bits)).into_bytes());
        }
    }
    env.push(alloc::format!("MODALIAS={}", modalias(&dev)).into_bytes());
    env
}

/// Input uevent environment from the current evdev identity.
/// # C: O(N_devices + capability bits)
pub fn uevent_env(evdev_id: u32) -> Vec<Vec<u8>> {
    crate::registry::device(evdev_id)
        .as_ref()
        .map(uevent_env_for)
        .unwrap_or_default()
}
