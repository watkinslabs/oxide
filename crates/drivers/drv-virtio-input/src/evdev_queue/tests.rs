use super::*;

const TEST_CLOCK_NS: u64 = 4_000_005_000;
const TEST_KEY_CODE: u16 = 30;
const TEST_KEY_VALUE: i32 = 1;

fn value(ev_type: u16, code: u16, value: i32) -> input::InputValue {
    input::InputValue { ev_type, code, value }
}

fn times() -> EventTimes {
    EventTimes {
        monotonic: TEST_CLOCK_NS,
        realtime: TEST_CLOCK_NS,
        boottime: TEST_CLOCK_NS,
    }
}

fn record_type(bytes: &[u8], index: usize) -> u16 {
    let start = index * INPUT_EVENT_BYTES + EVENT_TYPE_OFF;
    u16::from_le_bytes(
        bytes[start..start + core::mem::size_of::<u16>()]
            .try_into()
            .expect("event type"),
    )
}

fn record_code(bytes: &[u8], index: usize) -> u16 {
    let start = index * INPUT_EVENT_BYTES + EVENT_CODE_OFF;
    u16::from_le_bytes(
        bytes[start..start + core::mem::size_of::<u16>()]
            .try_into()
            .expect("event code"),
    )
}

#[test]
fn packet_values_share_one_timestamp_and_become_ready_together() {
    let queue = EvdevClientQueue::new();
    let packet = [
        value(crate::EV_KEY, TEST_KEY_CODE, TEST_KEY_VALUE),
        value(crate::EV_SYN, crate::SYN_REPORT, 0),
    ];

    queue.push_packet(&packet, times());
    let mut bytes = [0; INPUT_EVENT_BYTES * 2];
    assert_eq!(queue.try_pop_bytes(&mut bytes), Some(bytes.len()));
    for index in 0..packet.len() {
        let sec = u64::from_le_bytes(
            bytes[index * INPUT_EVENT_BYTES + TV_SEC_OFF
                ..index * INPUT_EVENT_BYTES + TV_USEC_OFF]
                .try_into()
                .expect("seconds"),
        );
        let usec = u64::from_le_bytes(
            bytes[index * INPUT_EVENT_BYTES + TV_USEC_OFF
                ..index * INPUT_EVENT_BYTES + EVENT_TYPE_OFF]
                .try_into()
                .expect("microseconds"),
        );
        assert_eq!((sec, usec), (4, 5));
    }
}

#[test]
fn incomplete_packet_is_never_exposed() {
    let queue = EvdevClientQueue::new();
    queue.push_packet(
        &[value(crate::EV_KEY, TEST_KEY_CODE, TEST_KEY_VALUE)],
        times(),
    );

    let mut bytes = [0; INPUT_EVENT_BYTES];
    assert_eq!(queue.try_pop_bytes(&mut bytes), None);
}

#[test]
fn overflow_keeps_dropped_marker_and_completed_packet_tail() {
    const REL_CODE: u16 = 0;
    const REL_VALUE: i32 = 1;
    const PACKET_VALUES: usize = QUEUE_CAP + 1;

    let queue = EvdevClientQueue::new();
    let mut packet = alloc::vec![
        value(crate::EV_REL, REL_CODE, REL_VALUE);
        PACKET_VALUES
    ];
    packet[PACKET_VALUES - 1] = value(crate::EV_SYN, crate::SYN_REPORT, 0);
    queue.push_packet(&packet, times());

    let mut bytes = alloc::vec![0; INPUT_EVENT_BYTES * QUEUE_CAP];
    assert_eq!(queue.try_pop_bytes(&mut bytes), Some(bytes.len()));
    assert_eq!(record_type(&bytes, 0), crate::EV_SYN);
    assert_eq!(record_code(&bytes, 0), crate::SYN_DROPPED);
    assert_eq!(record_type(&bytes, QUEUE_CAP - 1), crate::EV_SYN);
    assert_eq!(record_code(&bytes, QUEUE_CAP - 1), crate::SYN_REPORT);
}

const KEY_ADMITTED: u16 = 30;
const KEY_WITHHELD: u16 = 48;
const REL_X: u16 = 0;
const KEY_MASK_BYTES: usize = crate::evdev_mask::MASK_MAX_BYTES;
const TYPE_MASK_BYTES: usize = crate::evdev_mask::MASK_WORD_BYTES;

fn key_mask(code: u16) -> [u8; KEY_MASK_BYTES] {
    let mut bits = [0u8; KEY_MASK_BYTES];
    bits[usize::from(code) / u8::BITS as usize] |= 1 << (code % u8::BITS as u16);
    bits
}

#[test]
fn a_code_mask_withholds_unlisted_codes_from_the_queue() {
    let queue = EvdevClientQueue::new();
    assert!(queue.mask_set(u32::from(crate::EV_KEY), &key_mask(KEY_ADMITTED)));

    queue.push_packet(
        &[
            value(crate::EV_KEY, KEY_WITHHELD, TEST_KEY_VALUE),
            value(crate::EV_SYN, crate::SYN_REPORT, 0),
        ],
        times(),
    );
    assert!(queue.is_empty(), "a fully withheld packet queues nothing at all");

    queue.push_packet(
        &[
            value(crate::EV_KEY, KEY_ADMITTED, TEST_KEY_VALUE),
            value(crate::EV_SYN, crate::SYN_REPORT, 0),
        ],
        times(),
    );
    let mut bytes = [0; INPUT_EVENT_BYTES * 2];
    assert_eq!(queue.try_pop_bytes(&mut bytes), Some(bytes.len()));
    assert_eq!(record_code(&bytes, 0), KEY_ADMITTED);
}

#[test]
fn a_partly_withheld_packet_keeps_its_admitted_values_and_its_report() {
    let queue = EvdevClientQueue::new();
    assert!(queue.mask_set(u32::from(crate::EV_KEY), &key_mask(KEY_ADMITTED)));

    queue.push_packet(
        &[
            value(crate::EV_KEY, KEY_WITHHELD, TEST_KEY_VALUE),
            value(crate::EV_KEY, KEY_ADMITTED, TEST_KEY_VALUE),
            value(crate::EV_SYN, crate::SYN_REPORT, 0),
        ],
        times(),
    );
    let mut bytes = [0; INPUT_EVENT_BYTES * 3];
    assert_eq!(queue.try_pop_bytes(&mut bytes), Some(INPUT_EVENT_BYTES * 2));
    assert_eq!(record_code(&bytes, 0), KEY_ADMITTED);
    assert_eq!(record_type(&bytes, 1), crate::EV_SYN);
    assert_eq!(record_code(&bytes, 1), crate::SYN_REPORT);
}

#[test]
fn the_type_mask_withholds_a_whole_type_from_the_queue() {
    let mut types = [0u8; TYPE_MASK_BYTES];
    types[usize::from(crate::EV_REL) / u8::BITS as usize] |=
        1 << (crate::EV_REL % u8::BITS as u16);
    let queue = EvdevClientQueue::new();
    assert!(queue.mask_set(u32::from(crate::EV_SYN), &types));

    queue.push_packet(
        &[
            value(crate::EV_KEY, KEY_ADMITTED, TEST_KEY_VALUE),
            value(crate::EV_SYN, crate::SYN_REPORT, 0),
        ],
        times(),
    );
    assert!(queue.is_empty());

    queue.push_packet(
        &[
            value(crate::EV_REL, REL_X, TEST_KEY_VALUE),
            value(crate::EV_SYN, crate::SYN_REPORT, 0),
        ],
        times(),
    );
    let mut bytes = [0; INPUT_EVENT_BYTES * 2];
    assert_eq!(queue.try_pop_bytes(&mut bytes), Some(bytes.len()));
    assert_eq!(record_type(&bytes, 0), crate::EV_REL);
}

#[test]
fn a_queue_with_no_masks_delivers_every_value() {
    let queue = EvdevClientQueue::new();
    queue.push_packet(
        &[
            value(crate::EV_KEY, KEY_WITHHELD, TEST_KEY_VALUE),
            value(crate::EV_SYN, crate::SYN_REPORT, 0),
        ],
        times(),
    );
    let mut bytes = [0; INPUT_EVENT_BYTES * 2];
    assert_eq!(queue.try_pop_bytes(&mut bytes), Some(bytes.len()));
    assert_eq!(record_code(&bytes, 0), KEY_WITHHELD);
}
