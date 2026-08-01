// Hosted devfs test manifest.
//
// These tests share the process-global evdev tables: `MAX_EVDEV` is 8, so every
// test that publishes, opens, or removes an event index competes for the same
// slots. `open(2)` now resolves the live device by NUMBER (Linux `chrdev_open`),
// which makes that sharing observable — a sibling test unpublishing an index
// between another's publish and its open would fail the open. Serialise them.

mod common;

use common::*;

/// Own the input device table for the duration of one test. The table is the
/// `registry`'s, so the lock is too — a second one here would exclude nothing.
/// # C: O(MAX_INPUT_DEVICES)
pub(crate) fn serialize() -> crate::registry::DeviceTableOwner {
    crate::registry::own_device_table()
}

mod absinfo;
mod ioctl;
mod mask;
mod lifetime;
mod publication;
mod rebind;
mod identity;
