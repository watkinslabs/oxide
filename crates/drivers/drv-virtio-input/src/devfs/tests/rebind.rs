// Driver unbind/rebind of one evdev child, end to end through the model.
//
// A rebind republishes `/dev/input/eventN` under the same name and the same
// device number. Two Linux contracts have to hold at once:
//   * `open(2)` resolves the live device by NUMBER, so ANY node addressing that
//     event index — including the inode the previous binding minted — attaches
//     to the NEW device.
//   * an ALREADY-OPEN file description keeps the endpoint it attached to and
//     goes on reporting `ENODEV`; it is never retargeted at the replacement.

use alloc::sync::Arc;

use vfs::{Dentry, File, OpenFlags, VfsError};

use crate::devfs::{register_node, unregister_node};
use crate::devfs::shared::EVDEV_DEVICES;
use crate::evdev_queue::{EventTimes, INPUT_EVENT_BYTES, MAX_EVDEV};

const REBIND_KEY_CODE: u16 = 30;
const REBIND_KEY_VALUE: i32 = 1;
const REBIND_CLOCK_NS: u64 = 2_000_004_000;
const PACKET_EVENT_COUNT: usize = 2;

fn times() -> EventTimes {
    EventTimes { monotonic: REBIND_CLOCK_NS, realtime: REBIND_CLOCK_NS, boottime: REBIND_CLOCK_NS }
}

/// The `/dev` node inode the devtmpfs hook would mint for the CURRENT
/// registration of `id`, straight from the published model device's factory.
fn published_node(id: u32) -> vfs::InodeRef {
    let dev = EVDEV_DEVICES.lock()[id as usize].clone().expect("published model device");
    let factory = dev.node_factory.clone().expect("evdev node factory");
    factory()
}

fn try_open_node(inode: vfs::InodeRef) -> Result<Arc<File>, VfsError> {
    let file = File::new(
        inode.clone(),
        Dentry::new_anon(inode),
        OpenFlags::O_RDONLY | OpenFlags::O_NONBLOCK,
    );
    file.open_hook()?;
    Ok(file)
}

fn open_node(inode: vfs::InodeRef) -> Arc<File> {
    try_open_node(inode).expect("open published evdev node")
}

fn push_current(id: u32) {
    let endpoint = crate::devfs::current_endpoint(id).expect("current endpoint");
    endpoint.push_packet(
        &[
            input::InputValue { ev_type: crate::EV_KEY, code: REBIND_KEY_CODE, value: REBIND_KEY_VALUE },
            input::InputValue { ev_type: crate::EV_SYN, code: crate::SYN_REPORT, value: 0 },
        ],
        times(),
    );
}

#[test]
fn a_rebound_child_publishes_a_node_addressing_the_new_endpoint() {
    let _serial = super::serialize();
    let id = (MAX_EVDEV - 7) as u32;
    let _ = unregister_node(id);

    assert!(register_node(id, None), "first binding publishes the node");
    let first_node = published_node(id);
    let first_generation = crate::devfs::current_endpoint(id)
        .expect("first endpoint").identity().generation;

    assert!(unregister_node(id), "unbind removes the node");
    assert!(register_node(id, None), "rebind republishes the node");
    let second_node = published_node(id);
    let second_generation = crate::devfs::current_endpoint(id)
        .expect("second endpoint").identity().generation;

    assert_ne!(first_generation, second_generation, "rebind mints a new endpoint");
    assert_eq!(first_node.ino(), second_node.ino(), "the event number is reused");
    assert!(!Arc::ptr_eq(&first_node, &second_node), "and the node is a new inode");

    // The republished node opens and delivers; the previous one is dead.
    let live = open_node(second_node);
    push_current(id);
    let mut bytes = [0u8; INPUT_EVENT_BYTES * PACKET_EVENT_COUNT];
    assert_eq!(live.read(&mut bytes).unwrap(), INPUT_EVENT_BYTES * PACKET_EVENT_COUNT);
    // A node addresses its device by NUMBER (Linux `chrdev_open`), so even the
    // inode minted for the previous binding opens onto the LIVE device — a node
    // cached, bind-mounted, or cloned before the rebind still works.
    let via_old_node = open_node(first_node);
    push_current(id);
    assert_eq!(via_old_node.read(&mut bytes).unwrap(), INPUT_EVENT_BYTES * PACKET_EVENT_COUNT);

    assert!(unregister_node(id));
}

#[test]
fn a_file_opened_before_the_unbind_keeps_reporting_enodev_after_the_rebind() {
    let _serial = super::serialize();
    let id = (MAX_EVDEV - 8) as u32;
    let _ = unregister_node(id);

    assert!(register_node(id, None));
    let before = open_node(published_node(id));
    let mut bytes = [0u8; INPUT_EVENT_BYTES * PACKET_EVENT_COUNT];
    push_current(id);
    assert_eq!(before.read(&mut bytes).unwrap(), INPUT_EVENT_BYTES * PACKET_EVENT_COUNT);

    assert!(unregister_node(id));
    assert!(register_node(id, None), "rebind");

    // The pre-unbind description is bound to the dead endpoint forever: a
    // replacement device never inherits it.
    push_current(id);
    assert_eq!(before.read(&mut bytes).err(), Some(VfsError::Enodev));

    let after = open_node(published_node(id));
    push_current(id);
    assert_eq!(after.read(&mut bytes).unwrap(), INPUT_EVENT_BYTES * PACKET_EVENT_COUNT);

    assert!(unregister_node(id));
}
