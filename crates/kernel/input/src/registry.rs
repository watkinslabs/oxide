use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use sync::{Spinlock, TaskList as DriverLockClass};

use crate::absolute::MtState;
use crate::packet::InputValue;
use crate::state::OutputBatch;
use crate::uapi::{
    ABS_CNT, CAP_BITMAP_BYTES, INPUT_EV_STORAGE_BYTES, INPUT_NAME_BYTES, INPUT_PHYS_BYTES,
    INPUT_PROP_STORAGE_BYTES, INPUT_SERIAL_BYTES,
};
use crate::{
    types::{VirtioInputAbsInfo, VirtioInputDevIds}, DEFAULT_REPEAT, MAX_INPUT_DEVICES,
    RepeatSettings,
};

const UNASSIGNED_ID: u32 = u32::MAX;

pub type RegisterEvdevFn = fn(u32) -> bool;
pub type UnregisterEvdevFn = fn(u32) -> bool;
pub type PushEvdevPacketFn = fn(u32, bool, &[InputValue]);
pub type PushOutputFn = fn(virtio::VirtioChildDeviceKey, &OutputBatch);

#[derive(Copy, Clone)]
pub struct EvdevHooks {
    pub register: Option<RegisterEvdevFn>,
    pub unregister: Option<UnregisterEvdevFn>,
    pub push_packet: Option<PushEvdevPacketFn>,
}

const NO_EVDEV_HOOKS: EvdevHooks = EvdevHooks {
    register: None,
    unregister: None,
    push_packet: None,
};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AbsSnapshot {
    pub value: i32,
    pub parameters: VirtioInputAbsInfo,
}

#[derive(Clone, Debug)]
pub struct CapBitmap {
    pub bits: [u8; CAP_BITMAP_BYTES],
}

impl Default for CapBitmap {
    fn default() -> Self {
        Self { bits: [0u8; CAP_BITMAP_BYTES] }
    }
}

#[derive(Clone)]
pub struct VirtioInputDev {
    pub device_key: virtio::VirtioChildDeviceKey,
    pub input_id: u32,
    pub evdev_id: u32,
    pub is_pointer: bool,
    pub name: [u8; INPUT_NAME_BYTES],
    pub name_len: usize,
    pub name_present: bool,
    pub phys: [u8; INPUT_PHYS_BYTES],
    pub phys_len: usize,
    pub phys_present: bool,
    pub serial: [u8; INPUT_SERIAL_BYTES],
    pub serial_len: usize,
    pub serial_present: bool,
    pub ids: VirtioInputDevIds,
    pub ev_bits: [u8; INPUT_EV_STORAGE_BYTES],
    pub key_bits: CapBitmap,
    pub rel_bits: CapBitmap,
    pub abs_bits: CapBitmap,
    pub msc_bits: CapBitmap,
    pub led_bits: CapBitmap,
    pub snd_bits: CapBitmap,
    pub ff_bits: CapBitmap,
    pub sw_bits: CapBitmap,
    pub abs_info: [Option<VirtioInputAbsInfo>; ABS_CNT],
    pub prop_bits: [u8; INPUT_PROP_STORAGE_BYTES],
    pub repeat: RepeatSettings,
    pub(crate) inhibited: bool,
    pub(crate) key_state: CapBitmap,
    pub(crate) switch_state: CapBitmap,
    pub(crate) led_state: CapBitmap,
    pub(crate) sound_state: CapBitmap,
    pub(crate) repeat_key: Option<u16>,
    pub(crate) repeat_timer: Option<timer::TimerId>,
    pub(crate) pending_values: Vec<InputValue>,
    pub(crate) abs_values: [i32; ABS_CNT],
    pub(crate) mt_state: Option<MtState>,
}

impl VirtioInputDev {
    /// # C: O(KEY_CNT + ABS_CNT)
    pub fn empty(device_key: virtio::VirtioChildDeviceKey) -> Self {
        Self {
            device_key,
            input_id: UNASSIGNED_ID,
            evdev_id: UNASSIGNED_ID,
            is_pointer: false,
            name: [0; INPUT_NAME_BYTES],
            name_len: 0,
            name_present: false,
            phys: [0; INPUT_PHYS_BYTES],
            phys_len: 0,
            phys_present: false,
            serial: [0; INPUT_SERIAL_BYTES],
            serial_len: 0,
            serial_present: false,
            ids: VirtioInputDevIds::default(),
            ev_bits: [0; INPUT_EV_STORAGE_BYTES],
            key_bits: CapBitmap::default(),
            rel_bits: CapBitmap::default(),
            abs_bits: CapBitmap::default(),
            msc_bits: CapBitmap::default(),
            led_bits: CapBitmap::default(),
            snd_bits: CapBitmap::default(),
            ff_bits: CapBitmap::default(),
            sw_bits: CapBitmap::default(),
            abs_info: [None; ABS_CNT],
            prop_bits: [0; INPUT_PROP_STORAGE_BYTES],
            repeat: DEFAULT_REPEAT,
            inhibited: false,
            key_state: CapBitmap::default(),
            switch_state: CapBitmap::default(),
            led_state: CapBitmap::default(),
            sound_state: CapBitmap::default(),
            repeat_key: None,
            repeat_timer: None,
            pending_values: Vec::new(),
            abs_values: [0; ABS_CNT],
            mt_state: None,
        }
    }
}

pub(crate) static DEVICES: Spinlock<Vec<VirtioInputDev>, DriverLockClass> = Spinlock::new(Vec::new());
static EVDEV_HOOKS: Spinlock<EvdevHooks, DriverLockClass> = Spinlock::new(NO_EVDEV_HOOKS);
static OUTPUT_HOOK: Spinlock<Option<PushOutputFn>, DriverLockClass> = Spinlock::new(None);
static NEXT_INPUT_ID: AtomicU32 = AtomicU32::new(0);

/// # C: O(1)
pub fn set_evdev_hooks(hooks: EvdevHooks) {
    *EVDEV_HOOKS.lock() = hooks;
}

/// Install the one device-output transport sink. The sink must take durable
/// ownership of every batch before returning and retry transient queue pressure.
/// # C: O(1)
pub fn set_output_hook(hook: PushOutputFn) {
    *OUTPUT_HOOK.lock() = Some(hook);
}

/// # C: O(register callback)
pub fn publish_evdev(id: u32) -> bool {
    let register = EVDEV_HOOKS.lock().register;
    match register {
        Some(register) => register(id),
        None => true,
    }
}

/// # C: O(unregister callback)
pub fn unpublish_evdev(id: u32) -> bool {
    let unregister = EVDEV_HOOKS.lock().unregister;
    match unregister {
        Some(unregister) => unregister(id),
        None => true,
    }
}

/// Filter and dispatch one input event from canonical device state.
/// # C: O(N_devices)
pub fn push_evdev_event(id: u32, ev_type: u16, code: u16, value: i32) -> bool {
    let packet = {
        let mut devs = DEVICES.lock();
        let Some(dev) = devs.iter_mut().find(|dev| dev.evdev_id == id) else {
            return false;
        };
        let Some(accepted) = dev.accept_event(ev_type, code, value) else {
            return false;
        };
        dev.stage_accepted(ev_type, code, accepted).map(|values| {
            crate::repeat::accepted_packet(dev, &values);
            (dev.is_pointer, values)
        })
    };
    if let Some((is_pointer, values)) = packet {
        dispatch_values(id, is_pointer, &values);
    }
    true
}

/// # C: O(packet callback)
pub(crate) fn dispatch_values(
    id: u32,
    is_pointer: bool,
    values: &[InputValue],
) {
    let push = EVDEV_HOOKS.lock().push_packet;
    if let Some(push) = push {
        push(id, is_pointer, values);
    }
}

fn release_state(dev: &mut VirtioInputDev, release_mt: bool) -> Option<Vec<InputValue>> {
    if release_mt {
        dev.release_mt_to_pending();
    }
    dev.release_keys_to_pending();
    crate::repeat::cancel(dev);
    dev.flush_synthetic_report()
}

fn lowest_free_evdev_id(devs: &[VirtioInputDev]) -> Option<u32> {
    for id in 0..MAX_INPUT_DEVICES as u32 {
        if devs.iter().all(|d| d.evdev_id != id) {
            return Some(id);
        }
    }
    None
}

/// Atomically allocate Linux inputN/eventN identities and publish one model.
/// inputN is monotonic and never recycled; eventN is a bounded evdev minor.
/// # C: O(N_devices)
pub fn install(mut dev: VirtioInputDev) -> Option<(u32, u32)> {
    let mut devices = DEVICES.lock();
    if devices.iter().any(|present| present.device_key == dev.device_key) {
        return None;
    }
    let evdev_id = lowest_free_evdev_id(&devices)?;
    let input_id = NEXT_INPUT_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
        .ok()?;
    dev.input_id = input_id;
    dev.evdev_id = evdev_id;
    crate::identity::normalize(&mut dev);
    devices.push(dev);
    Some((input_id, evdev_id))
}

/// # C: O(1)
pub fn count() -> usize {
    DEVICES.lock().len()
}

/// # C: O(N_devices + cloned device state)
pub fn devices_snapshot() -> Vec<VirtioInputDev> {
    DEVICES.lock().clone()
}

/// # C: O(N_devices + KEY_CNT + pending packet)
pub fn remove_device(device_key: virtio::VirtioChildDeviceKey) -> Option<u32> {
    let (evdev_id, is_pointer, packet) = {
        let mut devices = DEVICES.lock();
        let idx = devices.iter().position(|dev| dev.device_key == device_key)?;
        let packet = release_state(&mut devices[idx], false);
        let is_pointer = devices[idx].is_pointer;
        let evdev_id = devices.remove(idx).evdev_id;
        (evdev_id, is_pointer, packet)
    };
    if let Some(values) = packet {
        dispatch_values(evdev_id, is_pointer, &values);
    }
    Some(evdev_id)
}

/// # C: O(N_devices)
pub fn evdev_id_for_device(device_key: virtio::VirtioChildDeviceKey) -> Option<u32> {
    DEVICES
        .lock()
        .iter()
        .find(|d| d.device_key == device_key)
        .map(|d| d.evdev_id)
}

/// # C: O(N_devices)
pub fn name_of(evdev_id: u32) -> Option<[u8; INPUT_NAME_BYTES]> {
    DEVICES.lock().iter().find(|d| d.evdev_id == evdev_id).map(|d| d.name)
}

/// # C: O(N_devices + cloned device state)
pub fn device(evdev_id: u32) -> Option<VirtioInputDev> {
    DEVICES.lock().iter().find(|d| d.evdev_id == evdev_id).cloned()
}

fn matches_identity(
    dev: &VirtioInputDev,
    device_key: virtio::VirtioChildDeviceKey,
    input_id: u32,
    evdev_id: u32,
) -> bool {
    dev.device_key == device_key && dev.input_id == input_id && dev.evdev_id == evdev_id
}

/// Read inhibited state only for the exact installed Linux input object.
/// # C: O(N_devices)
pub fn inhibited_by_identity(
    device_key: virtio::VirtioChildDeviceKey,
    input_id: u32,
    evdev_id: u32,
) -> Option<bool> {
    DEVICES.lock().iter()
        .find(|dev| matches_identity(dev, device_key, input_id, evdev_id))
        .map(|dev| dev.inhibited)
}

/// Read repeat parameters for the exact installed Linux input object.
/// # C: O(N_devices)
pub fn repeat_by_identity(
    device_key: virtio::VirtioChildDeviceKey,
    input_id: u32,
    evdev_id: u32,
) -> Option<RepeatSettings> {
    DEVICES.lock().iter()
        .find(|dev| matches_identity(dev, device_key, input_id, evdev_id))
        .map(|dev| dev.repeat)
}

/// Replace repeat parameters for the exact installed Linux input object.
/// # C: O(N_devices)
pub fn set_repeat_by_identity(
    device_key: virtio::VirtioChildDeviceKey,
    input_id: u32,
    evdev_id: u32,
    repeat: RepeatSettings,
) -> bool {
    let mut devices = DEVICES.lock();
    let Some(dev) = devices.iter_mut()
        .find(|dev| matches_identity(dev, device_key, input_id, evdev_id))
    else {
        return false;
    };
    dev.repeat = repeat;
    true
}

/// Snapshot one absolute axis for the exact installed Linux input object.
/// Value and parameters are read in one canonical-state transaction.
/// # C: O(N_devices)
pub fn abs_snapshot_by_identity(
    device_key: virtio::VirtioChildDeviceKey,
    input_id: u32,
    evdev_id: u32,
    axis: u16,
) -> Option<AbsSnapshot> {
    let devices = DEVICES.lock();
    let dev = devices.iter()
        .find(|dev| matches_identity(dev, device_key, input_id, evdev_id))?;
    Some(AbsSnapshot {
        value: dev.abs_value(axis)?,
        parameters: dev.abs_parameters(axis)?,
    })
}

/// Commit userspace LED, sound, and repeat output to canonical state and
/// submit exactly the accepted output batch after releasing the device lock.
/// # C: O(N_devices + output events)
pub fn apply_output_by_identity(
    device_key: virtio::VirtioChildDeviceKey,
    input_id: u32,
    evdev_id: u32,
    requested: &OutputBatch,
) -> Option<OutputBatch> {
    let hook = (*OUTPUT_HOOK.lock())?;
    let accepted = {
        let mut devices = DEVICES.lock();
        let dev = devices.iter_mut()
            .find(|dev| matches_identity(dev, device_key, input_id, evdev_id))?;
        OutputBatch {
            events: requested.events.iter()
                .filter_map(|event| dev.apply_output_event(event))
                .collect(),
        }
    };
    if !accepted.events.is_empty() {
        hook(device_key, &accepted);
    }
    Some(accepted)
}

/// Apply Linux input inhibit/uninhibit to the exact installed object.
/// Inhibit releases tracked keys and emits one synchronization event before
/// filtering subsequent events; virtio-input has no open/close callback.
/// # C: O(N_devices + KEY_CNT)
pub fn set_inhibited_by_identity(
    device_key: virtio::VirtioChildDeviceKey,
    input_id: u32,
    evdev_id: u32,
    inhibited: bool,
) -> Option<OutputBatch> {
    let (packet, is_pointer, output) = {
        let mut devs = DEVICES.lock();
        let Some(dev) = devs.iter_mut()
            .find(|dev| matches_identity(dev, device_key, input_id, evdev_id))
        else {
            return None;
        };
        if dev.inhibited == inhibited {
            return Some(OutputBatch::default());
        }
        if inhibited {
            let packet = release_state(dev, true);
            let output = dev.inhibit_output_batch();
            dev.inhibited = true;
            (packet, dev.is_pointer, output)
        } else {
            dev.inhibited = false;
            (None, dev.is_pointer, dev.uninhibit_output_batch())
        }
    };
    if let Some(values) = packet {
        dispatch_values(evdev_id, is_pointer, &values);
    }
    let hook = *OUTPUT_HOOK.lock();
    if let Some(hook) = hook { hook(device_key, &output); }
    Some(output)
}

/// # C: O(N_devices)
pub fn is_pointer(evdev_id: u32) -> bool {
    DEVICES
        .lock()
        .iter()
        .find(|d| d.evdev_id == evdev_id)
        .is_some_and(|d| d.is_pointer)
}

/// # C: O(N_devices)
#[doc(hidden)]
pub fn clear_devices_for_tests() {
    {
        let mut devices = DEVICES.lock();
        for dev in devices.iter_mut() {
            crate::repeat::cancel(dev);
        }
        devices.clear();
    }
    *EVDEV_HOOKS.lock() = NO_EVDEV_HOOKS;
    *OUTPUT_HOOK.lock() = None;
    NEXT_INPUT_ID.store(0, Ordering::Relaxed);
}
