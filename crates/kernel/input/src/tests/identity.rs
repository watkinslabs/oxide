use super::*;

const NORMALIZE_DEVICE_KEY: u32 = 0x0060_0000;
const MODALIAS_DEVICE_KEY: u32 = 0x0080_0000;
const UEEVENT_DEVICE_KEY: u32 = 0x00a0_0000;
const EV_KEY_REL_MASK: u8 = (1 << crate::EV_KEY) | (1 << crate::EV_REL);
const TEST_REL_MASK: u8 = 0x03;
const OUT_OF_RANGE_MASK: u8 = u8::MAX;
const FF_TEST_CODE: u16 = 5;
const EXPECTED_EV_ENV: &[u8] = b"EV=200007";

#[test]
fn install_applies_linux_capability_normalization_once() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    crate::registry::clear_devices_for_tests();
    let device_key = key(NORMALIZE_DEVICE_KEY);
    let mut dev = VirtioInputDev::empty_boxed(device_key);
    dev.ev_bits[0] = EV_KEY_REL_MASK;
    advertise(&mut dev.ev_bits, crate::EV_FF);
    advertise(&mut dev.key_bits.bits, crate::KEY_RESERVED);
    advertise(&mut dev.key_bits.bits, TEST_KEY_CODE);
    dev.rel_bits.bits[0] = TEST_REL_MASK;
    dev.rel_bits.bits[crate::REL_CNT.div_ceil(u8::BITS as usize)] = OUT_OF_RANGE_MASK;
    dev.abs_bits.bits[0] = OUT_OF_RANGE_MASK;
    advertise(&mut dev.ff_bits.bits, FF_TEST_CODE);
    let (input_id, evdev_id) = install(dev).expect("install normalized model");

    let dev = device(evdev_id).expect("normalized canonical record");
    assert_ne!(dev.ev_bits[0] & 1, 0, "EV_SYN is mandatory");
    assert_eq!(dev.key_bits.bits[0] & 1, 0, "KEY_RESERVED is cleared");
    assert_ne!(
        dev.key_bits.bits[(TEST_KEY_CODE / u8::BITS as u16) as usize]
            & (1 << (TEST_KEY_CODE % u8::BITS as u16)),
        0,
    );
    assert_eq!(dev.rel_bits.bits[0], TEST_REL_MASK);
    assert_eq!(
        dev.rel_bits.bits[crate::REL_CNT.div_ceil(u8::BITS as usize)],
        0,
        "REL is bounded to REL_CNT",
    );
    assert!(dev.abs_bits.bits.iter().all(|byte| *byte == 0));
    assert_eq!(dev.input_id, input_id);
    assert_eq!(dev.evdev_id, evdev_id);
    assert_ne!(
        dev.ff_bits.bits[(FF_TEST_CODE / u8::BITS as u16) as usize]
            & (1 << (FF_TEST_CODE % u8::BITS as u16)),
        0,
        "generic input core preserves EV_FF",
    );
    assert!(crate::uevent_env(evdev_id)
        .iter()
        .any(|entry| entry.as_slice() == EXPECTED_EV_ENV));
    assert!(crate::uevent_env(evdev_id)
        .iter()
        .any(|entry| entry.starts_with(b"MODALIAS=input:")));
    assert_eq!(remove_device(device_key), Some(evdev_id));
}

#[test]
fn modalias_excludes_linux_max_sentinel_codes() {
    let mut dev = VirtioInputDev::empty_boxed(key(MODALIAS_DEVICE_KEY));
    advertise(&mut dev.ev_bits, crate::EV_MAX);
    advertise(&mut dev.key_bits.bits, crate::KEY_MAX);
    advertise(&mut dev.rel_bits.bits, crate::REL_MAX);
    let alias = crate::modalias(&dev);
    assert!(!alias.contains("e1F,"));
    assert!(!alias.contains("k2FF,"));
    assert!(!alias.contains("rF,"));
}

#[test]
fn uevent_identity_preserves_non_utf8_bytes_exactly() {
    let _serial = TEST_MUTEX.lock().unwrap_or_else(|err| err.into_inner());
    crate::registry::clear_devices_for_tests();
    let device_key = key(UEEVENT_DEVICE_KEY);
    let mut dev = VirtioInputDev::empty_boxed(device_key);
    let name = b"input-\x80-name";
    let phys = b"virtio\xfe/input0";
    let uniq = b"seat-\xff";
    dev.name[..name.len()].copy_from_slice(name);
    dev.name_len = name.len();
    dev.name_present = true;
    dev.phys[..phys.len()].copy_from_slice(phys);
    dev.phys_len = phys.len();
    dev.phys_present = true;
    dev.serial[..uniq.len()].copy_from_slice(uniq);
    dev.serial_len = uniq.len();
    dev.serial_present = true;
    let (_, evdev_id) = install(dev).expect("install byte identity model");

    let env = crate::uevent_env(evdev_id);
    assert!(env.iter().any(|entry| entry.as_slice() == b"NAME=\"input-\x80-name\""));
    assert!(env.iter().any(|entry| entry.as_slice() == b"PHYS=\"virtio\xfe/input0\""));
    assert!(env.iter().any(|entry| entry.as_slice() == b"UNIQ=\"seat-\xff\""));
    assert_eq!(remove_device(device_key), Some(evdev_id));
}
