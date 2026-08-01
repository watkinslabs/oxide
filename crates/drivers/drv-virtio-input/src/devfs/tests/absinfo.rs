// EVIOCGABS contract for an absolute pointer.
//
// A compositor places an absolute pointer on the screen by mapping the axis
// value onto the screen extent using the axis minimum and maximum it read
// here. Every failure in this file is silent at runtime: the pointer still
// moves, no call returns an error, and the cursor simply lands somewhere
// other than where the user pointed.

use super::*;
use crate::devfs::handle_evdev_ioctl;

const ABSOLUTE_DEVICE_ID: u32 = 5;
const AXIS_VALUE: i32 = 0x0000_1234;
const AXIS_MIN: u32 = 0x0000_0007;
const AXIS_MAX: u32 = 0x0000_7fff;
const AXIS_FUZZ: u32 = 0x0000_0011;
const AXIS_FLAT: u32 = 0x0000_0022;
const AXIS_RES: u32 = 0x0000_0033;
/// An axis the model never advertises, used to prove range decoding.
const UNADVERTISED_AXIS: u16 = 0x0a;
const BITS_PER_BYTE: u16 = u8::BITS as u16;

fn set_bit(bits: &mut [u8], bit: u16) {
    bits[(bit / BITS_PER_BYTE) as usize] |= 1 << (bit % BITS_PER_BYTE);
}

fn install_absolute_pointer(axes: &[u16]) -> u32 {
    let mut model = test_dev(ABSOLUTE_DEVICE_ID);
    let key = model.device_key;
    let _ = crate::remove_device(key);
    set_bit(&mut model.ev_bits, crate::EV_ABS);
    for axis in axes.iter().copied() {
        set_bit(&mut model.abs_bits.bits, axis);
        model.abs_info[axis as usize] = Some(input::VirtioInputAbsInfo {
            min: AXIS_MIN,
            max: AXIS_MAX,
            fuzz: AXIS_FUZZ,
            flat: AXIS_FLAT,
            res: AXIS_RES,
        });
        assert!(model.seed_abs_value(axis, AXIS_VALUE));
    }
    let (_, id) = crate::install(model).expect("install absolute pointer");
    id
}

fn read_absinfo(file: &alloc::sync::Arc<vfs::File>, axis: u16) -> (Option<i64>, [u8; crate::EVDEV_ABSINFO_BYTES]) {
    let mut out = [0u8; crate::EVDEV_ABSINFO_BYTES];
    let request = evio_read(
        crate::EVIOCGABS_BASE_NR as u32 + axis as u32,
        crate::EVDEV_ABSINFO_BYTES,
    );
    let rv = handle_evdev_ioctl(file, request, out.as_mut_ptr() as u64);
    (rv, out)
}

fn field(bytes: &[u8; crate::EVDEV_ABSINFO_BYTES], off: usize) -> u32 {
    u32::from_le_bytes(bytes[off..off + core::mem::size_of::<u32>()].try_into().expect("word"))
}

/// The answer is `struct input_absinfo`: the CURRENT value first, then the
/// static minimum, maximum, fuzz, flat, and resolution. Distinct values per
/// field, so any rotation or omission fails.
#[test]
fn eviocgabs_answers_input_absinfo_field_order() {
    let _serial = super::serialize();
    let id = install_absolute_pointer(&[input::ABS_X]);
    let file = test_file(id);

    // Success is any non-negative answer: this file pins the payload layout,
    // not the success-return convention shared with the other EVIOCG* reads.
    let (rv, out) = read_absinfo(&file, input::ABS_X);
    assert!(matches!(rv, Some(rv) if rv >= 0), "{rv:?}");
    assert_eq!(field(&out, crate::EVDEV_ABSINFO_VALUE_OFF), AXIS_VALUE as u32);
    assert_eq!(field(&out, crate::EVDEV_ABSINFO_MIN_OFF), AXIS_MIN);
    assert_eq!(field(&out, crate::EVDEV_ABSINFO_MAX_OFF), AXIS_MAX);
    assert_eq!(field(&out, crate::EVDEV_ABSINFO_FUZZ_OFF), AXIS_FUZZ);
    assert_eq!(field(&out, crate::EVDEV_ABSINFO_FLAT_OFF), AXIS_FLAT);
    assert_eq!(field(&out, crate::EVDEV_ABSINFO_RES_OFF), AXIS_RES);

    input::clear_devices_for_tests();
}

/// The axis is carried in the ioctl number, not in an argument, so each axis
/// must answer for itself. An absolute device carries one array entry per
/// axis, so an axis it never advertised is answered from the zeroed entry —
/// success with an empty range, not a refusal. Refusal is reserved for a
/// device that has no array at all (`eviocgabs_refuses_a_device_with_no_axes`).
#[test]
fn eviocgabs_decodes_the_axis_from_the_request_number() {
    let _serial = super::serialize();
    let id = install_absolute_pointer(&[input::ABS_X, input::ABS_Y]);
    let file = test_file(id);

    for axis in [input::ABS_X, input::ABS_Y] {
        let (rv, out) = read_absinfo(&file, axis);
        assert!(matches!(rv, Some(rv) if rv >= 0), "axis {axis}: {rv:?}");
        assert_eq!(field(&out, crate::EVDEV_ABSINFO_MAX_OFF), AXIS_MAX, "axis {axis}");
    }

    let (rv, out) = read_absinfo(&file, UNADVERTISED_AXIS);
    assert!(matches!(rv, Some(rv) if rv >= 0), "{rv:?}");
    for off in [
        crate::EVDEV_ABSINFO_VALUE_OFF,
        crate::EVDEV_ABSINFO_MIN_OFF,
        crate::EVDEV_ABSINFO_MAX_OFF,
        crate::EVDEV_ABSINFO_FUZZ_OFF,
        crate::EVDEV_ABSINFO_FLAT_OFF,
        crate::EVDEV_ABSINFO_RES_OFF,
    ] {
        assert_eq!(field(&out, off), 0, "offset {off}");
    }

    input::clear_devices_for_tests();
}

/// A device with no absolute capability has no per-axis array behind the
/// request, so every axis number is refused — udev probes this on the
/// keyboard and the relative pointer at every boot.
#[test]
fn eviocgabs_refuses_a_device_with_no_axes() {
    let _serial = super::serialize();
    let model = test_dev(ABSOLUTE_DEVICE_ID);
    let key = model.device_key;
    let _ = crate::remove_device(key);
    let (_, id) = crate::install(model).expect("install relative device");
    let file = test_file(id);

    for axis in [input::ABS_X, UNADVERTISED_AXIS] {
        let (rv, _) = read_absinfo(&file, axis);
        assert_eq!(
            rv,
            Some(-(syscall::errno::Errno::Einval.as_i32() as i64)),
            "axis {axis}",
        );
    }

    input::clear_devices_for_tests();
}
