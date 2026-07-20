//! Hosted bus-test synchronization for process-global driver callbacks.

extern crate std;

use std::sync::{Mutex, MutexGuard};

/// `drv` owns one process-global device-publication callback.  Tests that
/// replace it must not overlap a device registration in another test.
static DEVICE_HOOK_SERIAL: Mutex<()> = Mutex::new(());

/// Exclusively own the test-only device-publication callback state. # C: O(1)
pub(crate) fn device_hook_serial() -> MutexGuard<'static, ()> {
    DEVICE_HOOK_SERIAL.lock().expect("device hook test lock poisoned")
}
