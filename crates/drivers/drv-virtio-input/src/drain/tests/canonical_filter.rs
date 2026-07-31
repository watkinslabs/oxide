use super::*;

const DEVICE_KEY_RAW: u32 = 0x0030_0000;
const REL_CODE: u16 = 0;
const REL_VALUE: i32 = 1;

#[test]
fn native_and_kpi_events_share_canonical_inhibit_filter() {
    let _guard = TEST_LOCK.lock();
    let device_key = key(DEVICE_KEY_RAW);
    let mut model = input::VirtioInputDev::empty_boxed(device_key);
    model.ev_bits[(crate::EV_REL / u8::BITS as u16) as usize] |=
        1 << (crate::EV_REL % u8::BITS as u16);
    model.rel_bits.bits[(REL_CODE / u8::BITS as u16) as usize] |=
        1 << (REL_CODE % u8::BITS as u16);
    let (input_id, evdev_id) = input::install(model).expect("input model");
    let event = input::VirtioInputEvent {
        ty: crate::EV_REL,
        code: REL_CODE,
        value: REL_VALUE as u32,
    };

    assert!(input::set_inhibited_by_identity(
        device_key, input_id, evdev_id, true,
    ).is_some());
    assert!(!super::super::ring::deliver_event(evdev_id, event));
    assert!(!input::push_evdev_event(
        evdev_id,
        event.ty,
        event.code,
        event.value as i32,
    ));
    assert!(input::set_inhibited_by_identity(
        device_key, input_id, evdev_id, false,
    ).is_some());
    assert!(super::super::ring::deliver_event(evdev_id, event));
    assert!(input::push_evdev_event(
        evdev_id,
        event.ty,
        event.code,
        event.value as i32,
    ));

    assert_eq!(input::remove_device(device_key), Some(evdev_id));
}
