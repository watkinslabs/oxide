use alloc::sync::Arc;

use vfs::{Dentry, File, OpenFlags, POLL_ERR, POLL_HUP, POLL_IN};

use crate::devfs::fileops::make_evdev_inode_for;
use crate::devfs::shared::{evdev_open, publish_endpoint, test_endpoint, unpublish_exact};
use crate::evdev_queue::{EventTimes, INPUT_EVENT_BYTES};

const EVENT_TYPE_OFF: usize = core::mem::size_of::<u64>() * 2;
const EVENT_CODE_OFF: usize = EVENT_TYPE_OFF + core::mem::size_of::<u16>();
const EVENT_VALUE_OFF: usize = EVENT_CODE_OFF + core::mem::size_of::<u16>();
const TEST_CLOCK_NS: u64 = 1_000_002_000;
const KEY_CODE: u16 = 30;
const REPLACEMENT_KEY_CODE: u16 = 31;
const KEY_VALUE: i32 = 1;
const PACKET_EVENT_COUNT: usize = 2;
const KEY_STATE_BYTE: usize = KEY_CODE as usize / u8::BITS as usize;
const KEY_STATE_MASK: u8 = 1 << (KEY_CODE % u8::BITS as u16);

/// Publish `endpoint` for its event index. `open(2)` resolves the live device
/// by NUMBER, so an endpoint that is not the published one for its index is not
/// openable at all — the Linux `chrdev_open` contract.
fn publish(endpoint: &Arc<crate::devfs::shared::EvdevEndpoint>) {
    assert!(publish_endpoint(Arc::clone(endpoint)), "publish endpoint for its event index");
}

fn open(endpoint: Arc<crate::devfs::shared::EvdevEndpoint>) -> Arc<File> {
    let inode = make_evdev_inode_for(endpoint);
    let file = File::new(
        inode.clone(),
        Dentry::new_anon(inode),
        OpenFlags::O_RDONLY | OpenFlags::O_NONBLOCK,
    );
    file.open_hook().expect("open exact evdev endpoint");
    file
}

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

fn record(bytes: &[u8], index: usize) -> (u16, u16, i32) {
    let start = index * INPUT_EVENT_BYTES;
    (
        u16::from_le_bytes(
            bytes[start + EVENT_TYPE_OFF..start + EVENT_CODE_OFF]
                .try_into()
                .unwrap(),
        ),
        u16::from_le_bytes(
            bytes[start + EVENT_CODE_OFF..start + EVENT_VALUE_OFF]
                .try_into()
                .unwrap(),
        ),
        i32::from_le_bytes(
            bytes[start + EVENT_VALUE_OFF..start + INPUT_EVENT_BYTES]
                .try_into()
                .unwrap(),
        ),
    )
}

#[test]
fn state_reconciliation_flushes_only_querying_client() {
    let _serial = super::serialize();
    const EVDEV_ID: u32 = 6;
    const INPUT_ID: u32 = 60;

    let endpoint = test_endpoint(EVDEV_ID, INPUT_ID);
    publish(&endpoint);
    let first = open(Arc::clone(&endpoint));
    let second = open(Arc::clone(&endpoint));

    endpoint.push_packet(&[
        value(crate::EV_KEY, KEY_CODE, KEY_VALUE),
        value(crate::EV_SYN, crate::SYN_REPORT, 0),
    ], times());

    let mut state = [0u8; crate::EVDEV_STATE_BYTES];
    let mut truth = [0u8; crate::EVDEV_STATE_BYTES];
    truth[KEY_STATE_BYTE] = KEY_STATE_MASK;
    assert_eq!(
        evdev_open(&first).unwrap().copy_state_and_flush(crate::EV_KEY, &truth, &mut state),
        state.len(),
    );
    assert_eq!(state[KEY_STATE_BYTE], KEY_STATE_MASK);

    let mut first_bytes = [0u8; INPUT_EVENT_BYTES];
    assert_eq!(first.read(&mut first_bytes).err(), Some(vfs::VfsError::Eagain));

    let mut second_bytes = [0u8; INPUT_EVENT_BYTES * PACKET_EVENT_COUNT];
    assert_eq!(
        second.read(&mut second_bytes).unwrap(),
        INPUT_EVENT_BYTES * PACKET_EVENT_COUNT,
    );
    assert_eq!(
        record(&second_bytes, 0),
        (crate::EV_KEY, KEY_CODE, KEY_VALUE),
    );
    assert_eq!(record(&second_bytes, 1), (crate::EV_SYN, 0, 0));
    assert!(unpublish_exact(&endpoint));
}

#[test]
fn reused_event_number_cannot_retarget_old_open_file() {
    let _serial = super::serialize();
    const EVDEV_ID: u32 = 7;
    const OLD_INPUT_ID: u32 = 70;
    const REPLACEMENT_INPUT_ID: u32 = 71;

    let old_endpoint = test_endpoint(EVDEV_ID, OLD_INPUT_ID);
    publish(&old_endpoint);
    let old_generation = old_endpoint.identity().generation;
    let old_file = open(Arc::clone(&old_endpoint));
    let old_subs = old_file.poll_subscribers().expect("old client poll source");
    let before_disconnect = old_subs.generation();
    old_endpoint.push_packet(&[
        value(crate::EV_KEY, KEY_CODE, KEY_VALUE),
        value(crate::EV_SYN, crate::SYN_REPORT, 0),
    ], times());
    assert!(unpublish_exact(&old_endpoint));

    let replacement = test_endpoint(EVDEV_ID, REPLACEMENT_INPUT_ID);
    publish(&replacement);
    assert_ne!(replacement.identity().generation, old_generation);
    let replacement_file = open(Arc::clone(&replacement));
    replacement.push_packet(&[
        value(crate::EV_KEY, REPLACEMENT_KEY_CODE, KEY_VALUE),
        value(crate::EV_SYN, crate::SYN_REPORT, 0),
    ], times());

    assert!(old_subs.generation() > before_disconnect);
    assert_eq!(old_file.poll() & (POLL_HUP | POLL_ERR | POLL_IN), POLL_HUP | POLL_ERR | POLL_IN);
    let mut old_bytes = [0u8; INPUT_EVENT_BYTES * PACKET_EVENT_COUNT];
    assert_eq!(old_file.read(&mut old_bytes).err(), Some(vfs::VfsError::Enodev));

    let mut replacement_bytes = [0u8; INPUT_EVENT_BYTES * PACKET_EVENT_COUNT];
    assert_eq!(
        replacement_file.read(&mut replacement_bytes).unwrap(),
        INPUT_EVENT_BYTES * PACKET_EVENT_COUNT,
    );
    assert_eq!(
        record(&replacement_bytes, 0),
        (crate::EV_KEY, REPLACEMENT_KEY_CODE, KEY_VALUE),
    );
    assert!(unpublish_exact(&replacement));
}
