use crate::registry::{dispatch_values, matches_identity, release_state, DEVICES, OUTPUT_HOOK};
use crate::{InputDeviceKey, RepeatSettings, VirtioInputAbsInfo};
use crate::state::OutputBatch;

/// One absolute-axis snapshot from an exact canonical input record.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AbsSnapshot { pub value: i32, pub parameters: VirtioInputAbsInfo }

/// Read inhibited state only for the exact installed Linux input object. # C: O(N_devices)
pub fn inhibited_by_identity(device_key: impl Into<InputDeviceKey>, input_id: u32, evdev_id: u32) -> Option<bool> {
    let device_key = device_key.into();
    DEVICES.lock().iter().find(|dev| matches_identity(dev, device_key, input_id, evdev_id)).map(|dev| dev.inhibited)
}

/// Read repeat parameters for the exact installed Linux input object. # C: O(N_devices)
pub fn repeat_by_identity(device_key: impl Into<InputDeviceKey>, input_id: u32, evdev_id: u32) -> Option<RepeatSettings> {
    let device_key = device_key.into();
    DEVICES.lock().iter().find(|dev| matches_identity(dev, device_key, input_id, evdev_id)).map(|dev| dev.repeat)
}

/// Replace repeat parameters for the exact installed Linux input object. # C: O(N_devices)
pub fn set_repeat_by_identity(device_key: impl Into<InputDeviceKey>, input_id: u32, evdev_id: u32, repeat: RepeatSettings) -> bool {
    let device_key = device_key.into();
    let mut devices = DEVICES.lock();
    let Some(dev) = devices.iter_mut().find(|dev| matches_identity(dev, device_key, input_id, evdev_id)) else { return false; };
    dev.repeat = repeat;
    true
}

/// Snapshot one absolute axis for the exact installed Linux input object. # C: O(N_devices)
pub fn abs_snapshot_by_identity(device_key: impl Into<InputDeviceKey>, input_id: u32, evdev_id: u32, axis: u16) -> Option<AbsSnapshot> {
    let device_key = device_key.into();
    let devices = DEVICES.lock();
    let dev = devices.iter().find(|dev| matches_identity(dev, device_key, input_id, evdev_id))?;
    let (value, parameters) = dev.abs_snapshot(axis)?;
    Some(AbsSnapshot { value, parameters })
}

/// Commit userspace LED, sound, and repeat output after releasing canonical state. # C: O(N_devices + output events)
pub fn apply_output_by_identity(device_key: impl Into<InputDeviceKey>, input_id: u32, evdev_id: u32, requested: &OutputBatch) -> Option<OutputBatch> {
    let device_key = device_key.into();
    let hook = (*OUTPUT_HOOK.lock())?;
    let accepted = {
        let mut devices = DEVICES.lock();
        let dev = devices.iter_mut().find(|dev| matches_identity(dev, device_key, input_id, evdev_id))?;
        OutputBatch { events: requested.events.iter().filter_map(|event| dev.apply_output_event(event)).collect() }
    };
    if !accepted.events.is_empty() { if let Some(key) = device_key.virtio() { hook(key, &accepted); } }
    Some(accepted)
}

/// Apply Linux input inhibit/uninhibit to the exact installed object. # C: O(N_devices + KEY_CNT)
pub fn set_inhibited_by_identity(device_key: impl Into<InputDeviceKey>, input_id: u32, evdev_id: u32, inhibited: bool) -> Option<OutputBatch> {
    let device_key = device_key.into();
    let (packet, is_pointer, output) = {
        let mut devs = DEVICES.lock();
        let dev = devs.iter_mut().find(|dev| matches_identity(dev, device_key, input_id, evdev_id))?;
        if dev.inhibited == inhibited { return Some(OutputBatch::default()); }
        if inhibited { let packet = release_state(dev, true); let output = dev.inhibit_output_batch(); dev.inhibited = true; (packet, dev.is_pointer, output) }
        else { dev.inhibited = false; (None, dev.is_pointer, dev.uninhibit_output_batch()) }
    };
    if let Some(values) = packet { dispatch_values(evdev_id, is_pointer, &values); }
    if let (Some(hook), Some(key)) = (*OUTPUT_HOOK.lock(), device_key.virtio()) { hook(key, &output); }
    Some(output)
}

/// Return whether the exact event endpoint is a pointer. # C: O(N_devices)
pub fn is_pointer(evdev_id: u32) -> bool {
    DEVICES.lock().iter().find(|dev| dev.evdev_id == evdev_id).is_some_and(|dev| dev.is_pointer)
}
