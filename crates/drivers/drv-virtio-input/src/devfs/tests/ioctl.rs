use vfs::{OpenFlags, VfsError, POLL_IN};

use super::*;
use crate::devfs::handle_evdev_ioctl;

fn accept_test_output(
    _device_key: input::VirtioChildDeviceKey,
    _output: &input::OutputBatch,
) {
}

#[test]
fn evdev_clockid_ioctl_accepts_supported_clocks() {
    const UNSUPPORTED_CLOCK_ID: i32 = 6;

    let file = test_file(0);
    let mut monotonic = crate::EVDEV_CLOCK_MONOTONIC;
    let mut realtime = crate::EVDEV_CLOCK_REALTIME;
    let mut boottime = crate::EVDEV_CLOCK_BOOTTIME;
    let mut invalid = UNSUPPORTED_CLOCK_ID;
    assert_eq!(
        handle_evdev_ioctl(&file, crate::EVIOCSCLOCKID, (&mut monotonic as *mut i32) as u64),
        Some(0)
    );
    assert_eq!(
        handle_evdev_ioctl(&file, crate::EVIOCSCLOCKID, (&mut realtime as *mut i32) as u64),
        Some(0)
    );
    assert_eq!(
        handle_evdev_ioctl(&file, crate::EVIOCSCLOCKID, (&mut boottime as *mut i32) as u64),
        Some(0)
    );
    assert_eq!(
        handle_evdev_ioctl(&file, crate::EVIOCSCLOCKID, (&mut invalid as *mut i32) as u64),
        Some(-(syscall::errno::Errno::Einval.as_i32() as i64))
    );
    assert_eq!(
        handle_evdev_ioctl(&file, crate::EVIOCSCLOCKID, 0),
        Some(-(syscall::errno::Errno::Efault.as_i32() as i64))
    );
}

#[test]
fn evdev_repeat_ioctl_round_trips_real_device_state() {
    const REQUESTED_ID: u32 = 4;
    const REQUESTED_REPEAT: [u32; input::REP_CNT] = [300, 45];

    let key = test_dev(REQUESTED_ID).device_key;
    let _ = crate::remove_device(key);
    let (_, id) = crate::install(test_dev(REQUESTED_ID)).expect("install repeat model");
    let file = test_file(id);
    let mut repeat = REQUESTED_REPEAT;

    assert_eq!(
        handle_evdev_ioctl(&file, crate::EVIOCSREP, repeat.as_mut_ptr() as u64),
        Some(0)
    );
    repeat = [0, 0];
    assert_eq!(
        handle_evdev_ioctl(&file, crate::EVIOCGREP, repeat.as_mut_ptr() as u64),
        Some(crate::EVDEV_REPEAT_BYTES as i64)
    );
    assert_eq!(repeat, REQUESTED_REPEAT);
    assert_eq!(
        handle_evdev_ioctl(&file, crate::EVIOCSREP, 0),
        Some(-(syscall::errno::Errno::Efault.as_i32() as i64))
    );
    assert_eq!(crate::remove_device(key), Some(id));
}

#[test]
fn evdev_identity_and_capability_ioctls_project_canonical_model() {
    const REQUESTED_ID: u32 = 5;
    const KEY_CODE: u16 = 30;
    const LED_CODE: u16 = 2;
    const SOUND_CODE: u16 = 3;
    const SWITCH_CODE: u16 = 6;
    const MSC_MASK: u8 = 0x10;
    const LED_MASK: u8 = 0x04;
    const SOUND_MASK: u8 = 0x08;
    const FORCE_FEEDBACK_MASK: u8 = 0x20;
    const SWITCH_MASK: u8 = 0x40;

    let key = test_dev(REQUESTED_ID).device_key;
    let _ = crate::remove_device(key);
    let mut model = test_dev(REQUESTED_ID);
    let phys = b"virtio5/input0";
    model.phys[..phys.len()].copy_from_slice(phys);
    model.phys_len = phys.len();
    model.phys_present = true;
    for event_type in [
        crate::EV_KEY,
        crate::EV_MSC,
        crate::EV_LED,
        crate::EV_SND,
        crate::EV_FF,
        crate::EV_SW,
    ] {
        model.ev_bits[(event_type / u8::BITS as u16) as usize] |=
            1 << (event_type % u8::BITS as u16);
    }
    model.key_bits.bits[(KEY_CODE / u8::BITS as u16) as usize] |=
        1 << (KEY_CODE % u8::BITS as u16);
    model.msc_bits.bits[0] = MSC_MASK;
    model.led_bits.bits[0] = LED_MASK;
    model.snd_bits.bits[0] = SOUND_MASK;
    model.ff_bits.bits[0] = FORCE_FEEDBACK_MASK;
    model.sw_bits.bits[0] = SWITCH_MASK;
    let (_, id) = crate::install(model).expect("install ioctl model");
    let file = test_file(id);

    let mut phys_out = [0u8; crate::EVDEV_STR_BYTES];
    let phys_req = evio_read(crate::EVIOCGPHYS_NR as u32, phys_out.len());
    assert_eq!(
        handle_evdev_ioctl(&file, phys_req, phys_out.as_mut_ptr() as u64),
        Some((phys.len() + 1) as i64),
    );
    assert_eq!(&phys_out[..phys.len() + 1], b"virtio5/input0\0");

    let mut properties = [0u8; crate::EVDEV_STATE_BYTES];
    let prop_request = evio_read(crate::EVIOCGPROP_NR as u32, properties.len());
    assert_eq!(
        handle_evdev_ioctl(&file, prop_request, properties.as_mut_ptr() as u64),
        Some(input::INPUT_PROP_CNT.div_ceil(u8::BITS as usize) as i64),
    );

    for (event_type, expected, expected_len) in [
        (crate::EV_MSC, MSC_MASK, input::MSC_CNT.div_ceil(u8::BITS as usize)),
        (crate::EV_LED, LED_MASK, input::LED_CNT.div_ceil(u8::BITS as usize)),
        (crate::EV_SND, SOUND_MASK, input::SND_CNT.div_ceil(u8::BITS as usize)),
        (
            crate::EV_FF,
            FORCE_FEEDBACK_MASK,
            input::FF_CNT.div_ceil(u8::BITS as usize),
        ),
        (crate::EV_SW, SWITCH_MASK, input::SW_CNT.div_ceil(u8::BITS as usize)),
    ] {
        let mut bits = [0u8; crate::EVDEV_STATE_BYTES];
        let request = evio_read(
            crate::EVIOCGBIT_BASE_NR as u32 + u32::from(event_type),
            bits.len(),
        );
        assert_eq!(
            handle_evdev_ioctl(&file, request, bits.as_mut_ptr() as u64),
            Some(expected_len as i64),
        );
        assert_eq!(bits[0], expected, "event type {event_type}");
    }

    for (event_type, code) in [
        (crate::EV_KEY, KEY_CODE),
        (crate::EV_LED, LED_CODE),
        (crate::EV_SND, SOUND_CODE),
        (crate::EV_SW, SWITCH_CODE),
    ] {
        assert!(input::push_evdev_event(id, event_type, code, 1));
    }
    for (nr, byte, expected, expected_len) in [
        (
            crate::EVIOCGKEY_NR,
            KEY_CODE as usize / u8::BITS as usize,
            1 << (KEY_CODE % u8::BITS as u16),
            input::KEY_CNT.div_ceil(u8::BITS as usize),
        ),
        (crate::EVIOCGLED_NR, 0, LED_MASK, input::LED_CNT.div_ceil(u8::BITS as usize)),
        (crate::EVIOCGSND_NR, 0, SOUND_MASK, input::SND_CNT.div_ceil(u8::BITS as usize)),
        (crate::EVIOCGSW_NR, 0, SWITCH_MASK, input::SW_CNT.div_ceil(u8::BITS as usize)),
    ] {
        let mut state = [0u8; crate::EVDEV_STATE_BYTES];
        let request = evio_read(nr as u32, state.len());
        assert_eq!(
            handle_evdev_ioctl(&file, request, state.as_mut_ptr() as u64),
            Some(expected_len as i64),
        );
        assert_eq!(state[byte], expected, "state ioctl {nr:#x}");
    }

    assert_eq!(crate::remove_device(key), Some(id));
}

#[test]
fn evdev_force_feedback_ioctl_is_not_absinfo_alias() {
    // EVIOCSFF's number sits one past the absinfo range, so it must not be
    // decoded as an axis query. A device with no force-feedback engine refuses
    // effect upload and erase with ENOSYS, and reports zero effect slots.
    let file = test_file(0);
    let mut effect = [0u8; crate::EVDEV_FF_EFFECT_BYTES];
    assert_eq!(
        handle_evdev_ioctl(&file, crate::EVIOCSFF, effect.as_mut_ptr() as u64),
        Some(-(syscall::errno::Errno::Enosys.as_i32() as i64))
    );
    let mut id = 0i32;
    assert_eq!(
        handle_evdev_ioctl(&file, crate::EVIOCRMFF, (&mut id as *mut i32) as u64),
        Some(-(syscall::errno::Errno::Enosys.as_i32() as i64))
    );
    let mut effects = -1i32;
    assert_eq!(
        handle_evdev_ioctl(&file, crate::EVIOCGEFFECTS, (&mut effects as *mut i32) as u64),
        Some(0)
    );
    assert_eq!(effects, 0);
}

#[test]
fn evdev_grab_is_per_open_file_description() {
    const EVDEV_ID: u32 = 1;
    const KEY_CODE: u16 = 30;

    let owner = test_file(EVDEV_ID);
    let other = test_file(EVDEV_ID);
    assert_eq!(handle_evdev_ioctl(&owner, crate::EVIOCGRAB, 1), Some(0));
    assert_eq!(
        handle_evdev_ioctl(&other, crate::EVIOCGRAB, 1),
        Some(-(syscall::errno::Errno::Ebusy.as_i32() as i64))
    );
    crate::evdev_queue::push_packet(EVDEV_ID, &[
        input::InputValue { ev_type: crate::EV_KEY, code: KEY_CODE, value: 1 },
        input::InputValue { ev_type: crate::EV_SYN, code: crate::SYN_REPORT, value: 0 },
    ]);
    assert_eq!(owner.poll() & POLL_IN, POLL_IN);
    assert_eq!(other.poll() & POLL_IN, 0);

    let mut buf = [0u8; crate::evdev_queue::INPUT_EVENT_BYTES];
    assert_eq!(other.read(&mut buf).err(), Some(VfsError::Eagain));
    assert_eq!(owner.read(&mut buf).unwrap(), buf.len());
    assert_eq!(handle_evdev_ioctl(&owner, crate::EVIOCGRAB, 0), Some(0));
}

#[test]
fn evdev_grab_is_released_on_last_close() {
    const EVDEV_ID: u32 = 2;

    let owner = test_file(EVDEV_ID);
    let other = test_file(EVDEV_ID);
    assert_eq!(handle_evdev_ioctl(&owner, crate::EVIOCGRAB, 1), Some(0));
    drop(owner);
    assert_eq!(handle_evdev_ioctl(&other, crate::EVIOCGRAB, 1), Some(0));
    assert_eq!(handle_evdev_ioctl(&other, crate::EVIOCGRAB, 0), Some(0));
}

#[test]
fn evdev_revoke_disables_current_open_file() {
    const EVDEV_ID: u32 = 3;

    let file = test_file(EVDEV_ID);
    assert_eq!(
        handle_evdev_ioctl(&file, crate::EVIOCREVOKE, 1),
        Some(-(syscall::errno::Errno::Einval.as_i32() as i64)),
    );
    assert_eq!(handle_evdev_ioctl(&file, crate::EVIOCREVOKE, 0), Some(0));
    assert_eq!(file.poll() & vfs::POLL_HUP, vfs::POLL_HUP);
    let mut buf = [0u8; crate::evdev_queue::INPUT_EVENT_BYTES];
    assert_eq!(file.read(&mut buf).err(), Some(VfsError::Enodev));
}

#[test]
fn evdev_write_commits_output_through_exact_canonical_identity() {
    const DEVICE_KEY_RAW: u32 = 0x7000_0020;
    const LED_CODE: u16 = 2;
    const LED_VALUE: i32 = 1;

    let key = virtio::VirtioChildDeviceKey::from_raw(DEVICE_KEY_RAW);
    let _ = crate::remove_device(key);
    input::set_output_hook(accept_test_output);
    let mut model = crate::VirtioInputDev::empty(key);
    model.ev_bits[(crate::EV_LED / u8::BITS as u16) as usize] |=
        1 << (crate::EV_LED % u8::BITS as u16);
    model.led_bits.bits[(LED_CODE / u8::BITS as u16) as usize] |=
        1 << (LED_CODE % u8::BITS as u16);
    let (_, id) = crate::install(model).expect("output model");
    let file = test_file_with_flags(id, OpenFlags::O_RDWR | OpenFlags::O_NONBLOCK);
    let record = output_record(crate::EV_LED, LED_CODE, LED_VALUE);

    assert_eq!(file.write(&record), Ok(record.len()));
    let state = input::device(id).expect("canonical output state");
    assert_ne!(
        state.state_bits(crate::EV_LED).expect("LED state")
            [(LED_CODE / u8::BITS as u16) as usize]
            & (1 << (LED_CODE % u8::BITS as u16)),
        0,
    );
    assert_eq!(
        file.write(&record[..record.len() - 1]),
        Err(VfsError::Einval),
    );
    assert_eq!(crate::remove_device(key), Some(id));
    assert_eq!(file.write(&record), Err(VfsError::Enodev));
    input::clear_devices_for_tests();
}
