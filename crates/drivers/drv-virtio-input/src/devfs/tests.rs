// Hosted devfs test manifest.
//
// These tests share the process-global evdev tables: `MAX_EVDEV` is 8, so every
// test that publishes, opens, or removes an event index competes for the same
// slots. `open(2)` now resolves the live device by NUMBER (Linux `chrdev_open`),
// which makes that sharing observable — a sibling test unpublishing an index
// between another's publish and its open would fail the open. Serialise them.

mod common;

use common::*;

static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Hold the evdev-table lock for the duration of one test. # C: O(1)
pub(crate) fn serialize() -> std::sync::MutexGuard<'static, ()> {
    TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

mod absinfo;
mod ioctl;
mod mask;
mod lifetime;
mod publication;
mod rebind;
mod identity;
