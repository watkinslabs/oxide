//! zram-control initialization and lifecycle contracts.

use alloc::sync::Arc;

use crate::{by_index, hot_add, hot_remove, init, DEFAULT_DEVICE_INDEX, DEFAULT_DEVICE_NAME, DEFAULT_NUM_DEVICES};

/// Linux's default module initialization publishes `zram0` once, while later
/// control ABI additions continue from the next available ID.
#[test]
fn init_publishes_default_zram0_once_and_reserves_hot_add_id() {
    init().expect("first zram initialization");
    let first = by_index(DEFAULT_DEVICE_INDEX).expect("default zram0");
    init().expect("idempotent zram initialization");
    let second = by_index(DEFAULT_DEVICE_INDEX).expect("retained default zram0");
    assert!(Arc::ptr_eq(&first, &second));
    assert!(block::registry::by_name(DEFAULT_DEVICE_NAME).is_some());

    let index = hot_add().expect("zram hot-add after default");
    assert!(index >= DEFAULT_NUM_DEVICES);
    hot_remove(index).expect("remove added zram device");
}
