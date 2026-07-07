use alloc::vec::Vec;
use alloc::string::String;

use sync::{Spinlock, TaskList as DriverLockClass};

use crate::{types::{VirtioInputAbsInfo, VirtioInputDevIds}, DEFAULT_REPEAT, MAX_INPUT_DEVICES};

const CAP_BITMAP_BYTES: usize = 96;

pub type RegisterEvdevFn = fn(u32, Option<(&'static str, String)>) -> bool;
pub type UnregisterEvdevFn = fn(u32) -> bool;
pub type PushEvdevEventFn = fn(u32, u16, u16, i32);

#[derive(Copy, Clone)]
pub struct EvdevHooks {
    pub register: Option<RegisterEvdevFn>,
    pub unregister: Option<UnregisterEvdevFn>,
    pub push_event: Option<PushEvdevEventFn>,
}

const NO_EVDEV_HOOKS: EvdevHooks = EvdevHooks {
    register: None,
    unregister: None,
    push_event: None,
};

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
    pub evdev_id: u32,
    pub is_pointer: bool,
    pub name: [u8; 128],
    pub name_len: usize,
    pub serial: [u8; 128],
    pub serial_len: usize,
    pub ids: VirtioInputDevIds,
    pub ev_bits: [u8; 32],
    pub key_bits: CapBitmap,
    pub rel_bits: CapBitmap,
    pub abs_bits: CapBitmap,
    pub led_bits: CapBitmap,
    pub abs_info: [Option<VirtioInputAbsInfo>; 64],
    pub prop_bits: [u8; 4],
    pub repeat: [u32; 2],
}

impl VirtioInputDev {
    pub fn empty(device_key: virtio::VirtioChildDeviceKey, evdev_id: u32) -> Self {
        Self {
            device_key,
            evdev_id,
            is_pointer: false,
            name: [0; 128],
            name_len: 0,
            serial: [0; 128],
            serial_len: 0,
            ids: VirtioInputDevIds::default(),
            ev_bits: [0; 32],
            key_bits: CapBitmap::default(),
            rel_bits: CapBitmap::default(),
            abs_bits: CapBitmap::default(),
            led_bits: CapBitmap::default(),
            abs_info: [None; 64],
            prop_bits: [0; 4],
            repeat: DEFAULT_REPEAT,
        }
    }
}

static DEVICES: Spinlock<Vec<VirtioInputDev>, DriverLockClass> = Spinlock::new(Vec::new());
static EVDEV_HOOKS: Spinlock<EvdevHooks, DriverLockClass> = Spinlock::new(NO_EVDEV_HOOKS);

pub fn set_evdev_hooks(hooks: EvdevHooks) {
    *EVDEV_HOOKS.lock() = hooks;
}

pub fn publish_evdev(id: u32, parent: Option<(&'static str, String)>) -> bool {
    match EVDEV_HOOKS.lock().register {
        Some(register) => register(id, parent),
        None => true,
    }
}

pub fn unpublish_evdev(id: u32) -> bool {
    match EVDEV_HOOKS.lock().unregister {
        Some(unregister) => unregister(id),
        None => true,
    }
}

pub fn push_evdev_event(id: u32, ev_type: u16, code: u16, value: i32) {
    if let Some(push) = EVDEV_HOOKS.lock().push_event {
        push(id, ev_type, code, value);
    }
}

pub fn next_free_evdev_id() -> Option<u32> {
    let devs = DEVICES.lock();
    lowest_free_evdev_id(&devs)
}

fn lowest_free_evdev_id(devs: &[VirtioInputDev]) -> Option<u32> {
    for id in 0..MAX_INPUT_DEVICES as u32 {
        if devs.iter().all(|d| d.evdev_id != id) {
            return Some(id);
        }
    }
    None
}

pub fn install(dev: VirtioInputDev) {
    DEVICES.lock().push(dev);
}

pub fn count() -> usize {
    DEVICES.lock().len()
}

pub fn devices_snapshot() -> Vec<VirtioInputDev> {
    DEVICES.lock().clone()
}

pub fn remove_device(device_key: virtio::VirtioChildDeviceKey) -> Option<u32> {
    let evdev_id = {
        let mut g = DEVICES.lock();
        let idx = g.iter().position(|d| d.device_key == device_key)?;
        g.remove(idx).evdev_id
    };
    Some(evdev_id)
}

pub fn evdev_id_for_device(device_key: virtio::VirtioChildDeviceKey) -> Option<u32> {
    DEVICES
        .lock()
        .iter()
        .find(|d| d.device_key == device_key)
        .map(|d| d.evdev_id)
}

pub fn name_of(evdev_id: u32) -> Option<[u8; 128]> {
    DEVICES.lock().iter().find(|d| d.evdev_id == evdev_id).map(|d| d.name)
}

pub fn device(evdev_id: u32) -> Option<VirtioInputDev> {
    DEVICES.lock().iter().find(|d| d.evdev_id == evdev_id).cloned()
}

pub fn repeat(evdev_id: u32) -> Option<[u32; 2]> {
    DEVICES.lock().iter().find(|d| d.evdev_id == evdev_id).map(|d| d.repeat)
}

pub fn set_repeat(evdev_id: u32, repeat: [u32; 2]) -> bool {
    let mut devs = DEVICES.lock();
    let Some(dev) = devs.iter_mut().find(|d| d.evdev_id == evdev_id) else {
        return false;
    };
    dev.repeat = repeat;
    true
}

pub fn is_pointer(evdev_id: u32) -> bool {
    DEVICES
        .lock()
        .iter()
        .find(|d| d.evdev_id == evdev_id)
        .is_some_and(|d| d.is_pointer)
}

#[doc(hidden)]
pub fn clear_devices_for_tests() {
    DEVICES.lock().clear();
}
