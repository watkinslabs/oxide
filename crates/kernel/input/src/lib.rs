#![no_std]
extern crate alloc;
#[cfg(test)]
extern crate std;

// Module manifest:
// - `absolute`: absolute-axis filtering and multi-touch slot state.
// - `identity`: normalized capabilities, modalias, and uevent rendering.
// - `packet`: synchronization-frame assembly.
// - `registry`: canonical device identities, publication, and hook boundary.
// - `repeat`: software key autorepeat lifecycle.
// - `state`: event validation and canonical dynamic state.
// - `types`: virtio wire and evdev ABI records.
// - `uapi`: Linux input constants and bitmap limits.

mod absolute;
mod identity;
mod packet;
mod registry;
mod repeat;
mod state;
mod types;
mod uapi;

pub use identity::{format_bitmap, modalias, uevent_env, uevent_env_for};
pub use registry::{
    abs_snapshot_by_identity, apply_output_by_identity, clear_devices_for_tests, count,
    device, devices_snapshot, evdev_id_for_device, inhibited_by_identity, install,
    is_pointer, name_of, publish_evdev, push_evdev_event, remove_device,
    repeat_by_identity, set_evdev_hooks, set_inhibited_by_identity, set_output_hook,
    set_repeat_by_identity, unpublish_evdev, AbsSnapshot, CapBitmap, EvdevHooks,
    VirtioInputDev,
};
pub use packet::InputValue;
pub use state::with_state_bits_by_identity;
pub use state::{OutputBatch, OutputEvent};
pub use types::{InputEvent, VirtioInputAbsInfo, VirtioInputDevIds, VirtioInputEvent};
pub use uapi::{
    ABS_CNT, ABS_MAX, ABS_MT_FIRST, ABS_MT_LAST, ABS_MT_SLOT, ABS_MT_TRACKING_ID,
    EVENT_MINOR_BASE, EV_ABS, EV_CNT, EV_FF, EV_KEY, EV_LED, EV_MAX, EV_MSC, EV_PWR,
    EV_REL, EV_REP, EV_SND,
    EV_SW, EV_SYN, FF_CNT, FF_MAX, INPUT_PROP_CNT, INPUT_PROP_MAX, KEY_CNT, KEY_MAX,
    INPUT_MAJOR, INPUT_NAME_BYTES, KEY_RESERVED, LED_CNT, LED_MAX, MSC_CNT, MSC_MAX,
    REL_CNT, REL_MAX, REP_CNT, REP_DELAY,
    REP_PERIOD, SND_CNT, SND_MAX, SW_CNT, SW_MAX, SYN_CONFIG, SYN_MT_REPORT,
    SYN_REPORT,
};
pub use virtio::VirtioChildDeviceKey;

pub const MAX_INPUT_DEVICES: usize = 8;
/// Red Hat virtio PCI vendor ID used by the synthetic virtio-input model.
pub use virtio::resources::VIRTIO_VENDOR_ID as VIRTIO_PCI_VENDOR_ID;
pub type RepeatSettings = [u32; REP_CNT];
pub const DEFAULT_REPEAT: RepeatSettings = [250, 33];

#[cfg(test)]
mod tests;
