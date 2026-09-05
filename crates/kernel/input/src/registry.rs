use alloc::boxed::Box;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use sync::{Spinlock, TaskList as DriverLockClass};

use crate::absolute::MtState;
use crate::packet::InputValue;
use crate::raw::RawInputEvent;
use crate::state::OutputBatch;
use crate::uapi::{
    ABS_CNT, CAP_BITMAP_BYTES, INPUT_EV_STORAGE_BYTES, INPUT_NAME_BYTES, INPUT_PHYS_BYTES,
    INPUT_PROP_STORAGE_BYTES, INPUT_SERIAL_BYTES, KEY_RELEASED, KEY_REPEAT,
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
pub type NativeKeyHook = fn(u16, bool, bool) -> bool;
pub type NativeRelHook = fn(u16, i32) -> bool;
pub type NativeMouseHook = fn(u16, u16, i32) -> bool;

/// Stable owner identity for one input device. Input devices are not all
/// virtio children: platform controllers and transport devices share the same
/// canonical input registry while keeping their driver-model provenance.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum InputDeviceKey {
    Virtio(virtio::VirtioChildDeviceKey),
    Platform(u32),
}

impl From<virtio::VirtioChildDeviceKey> for InputDeviceKey {
    fn from(key: virtio::VirtioChildDeviceKey) -> Self { Self::Virtio(key) }
}

impl InputDeviceKey {
    /// Construct an identity for a platform-owned input endpoint.
    pub const fn platform(id: u32) -> Self { Self::Platform(id) }

    /// Return the transport key only when this input endpoint is virtio-backed.
    pub const fn virtio(self) -> Option<virtio::VirtioChildDeviceKey> {
        match self { Self::Virtio(key) => Some(key), Self::Platform(_) => None }
    }
}

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
    pub device_key: InputDeviceKey,
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
    pub(crate) connected: bool,
    pub(crate) controller_packet: u32,
    pub(crate) controller_dirty: bool,
    pub(crate) raw_events: alloc::collections::VecDeque<RawInputEvent>,
    pub(crate) raw_dropped: u64,
}

impl VirtioInputDev {
    /// Build one empty record directly in its heap home. Every kernel caller
    /// uses this: the record is kilobytes wide, and the bind path that builds
    /// one is already several frames deep inside a syscall, so materializing
    /// it on the stack overflows the kernel stack.
    /// # C: O(KEY_CNT + ABS_CNT)
    pub fn empty_boxed(device_key: virtio::VirtioChildDeviceKey) -> Box<Self> {
        Self::empty_boxed_with_key(device_key.into())
    }

    /// Build a platform-owned input device in its heap home.
    /// # C: O(KEY_CNT + ABS_CNT)
    pub fn empty_platform_boxed(platform_id: u32) -> Box<Self> {
        Self::empty_boxed_with_key(InputDeviceKey::platform(platform_id))
    }

    fn empty_boxed_with_key(device_key: InputDeviceKey) -> Box<Self> {
        let mut dev = Box::<Self>::new_uninit();
        // SAFETY: `empty_inline` initializes every `VirtioInputDev` field,
        // and `write` publishes that complete value before `assume_init`.
        unsafe {
            dev.as_mut_ptr().write(Self::empty_inline(device_key));
            dev.assume_init()
        }
    }

    /// Private: the only caller is `empty_boxed`, which moves the result
    /// straight to the heap. Nothing else may put a record on a stack.
    /// # C: O(KEY_CNT + ABS_CNT)
    fn empty_inline(device_key: InputDeviceKey) -> Self {
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
            connected: true,
            controller_packet: 0,
            controller_dirty: false,
            raw_events: alloc::collections::VecDeque::new(),
            raw_dropped: 0,
        }
    }

}

/// Device records are kilobytes wide, so the registry owns them through a
/// pointer and never stores them inline: a `Vec<VirtioInputDev>` would put a
/// whole record in every caller's stack frame on the way in and out.
pub(crate) static DEVICES: Spinlock<Vec<Box<VirtioInputDev>>, DriverLockClass> =
    Spinlock::new(Vec::new());
static EVDEV_HOOKS: Spinlock<EvdevHooks, DriverLockClass> = Spinlock::new(NO_EVDEV_HOOKS);
static NATIVE_KEY_HOOK: Spinlock<Option<NativeKeyHook>, DriverLockClass> = Spinlock::new(None);
static NATIVE_REL_HOOK: Spinlock<Option<NativeRelHook>, DriverLockClass> = Spinlock::new(None);
static NATIVE_MOUSE_HOOK: Spinlock<Option<NativeMouseHook>, DriverLockClass> = Spinlock::new(None);
pub(crate) static OUTPUT_HOOK: Spinlock<Option<PushOutputFn>, DriverLockClass> = Spinlock::new(None);
static NEXT_INPUT_ID: AtomicU32 = AtomicU32::new(0);

/// # C: O(1)
pub fn set_evdev_hooks(hooks: EvdevHooks) {
    *EVDEV_HOOKS.lock() = hooks;
}

/// Install the optional NT foreground keyboard sink. # C: O(1)
pub fn set_native_key_hook(hook: Option<NativeKeyHook>) {
    *NATIVE_KEY_HOOK.lock() = hook;
}

/// Install the optional NT relative-pointer sink. # C: O(1)
pub fn set_native_rel_hook(hook: Option<NativeRelHook>) {
    *NATIVE_REL_HOOK.lock() = hook;
}

/// Install the optional native pointer transition sink. # C: O(1)
pub fn set_native_mouse_hook(hook: Option<NativeMouseHook>) {
    *NATIVE_MOUSE_HOOK.lock() = hook;
}

/// Offer one accepted physical pointer transition to the native sink. # C: O(1)
pub fn dispatch_native_mouse_event(ev_type: u16, code: u16, value: i32) -> bool {
    let hook = *NATIVE_MOUSE_HOOK.lock();
    hook.is_some_and(|hook| hook(ev_type, code, value))
}

/// Offer one accepted relative input event to the native sink. # C: O(1)
pub fn dispatch_native_rel_event(code: u16, value: i32) -> bool {
    let hook = *NATIVE_REL_HOOK.lock();
    hook.is_some_and(|hook| hook(code, value))
}

/// Offer one accepted physical key transition to the native sink. # C: O(1)
pub fn dispatch_native_key_event(key: u16, pressed: bool, repeat: bool) -> bool {
    let hook = *NATIVE_KEY_HOOK.lock();
    hook.is_some_and(|hook| hook(key, pressed, repeat))
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
    let (packet, native_key, native_rel, native_mouse) = {
        let mut devs = DEVICES.lock();
        let Some(dev) = devs.iter_mut().find(|dev| dev.evdev_id == id) else {
            return false;
        };
        if !dev.connected { return false; }
        let controller_event = dev.controller_event(ev_type, code);
        let Some(accepted) = dev.accept_event(ev_type, code, value) else {
            return false;
        };
        if controller_event { dev.controller_dirty = true; }
        if ev_type == crate::EV_SYN && code == crate::SYN_REPORT && dev.controller_dirty {
            let next = dev.controller_packet.wrapping_add(1);
            dev.controller_packet = if next == 0 { 1 } else { next };
            dev.controller_dirty = false;
        }
        let _ = dev.publish_raw(ev_type, code, accepted.value);
        let native_key = (ev_type == crate::EV_KEY && code < crate::BTN_LEFT)
            .then_some((code, accepted.value));
        let native_rel = (ev_type == crate::EV_REL).then_some((code, accepted.value));
        let native_mouse = ((ev_type == crate::EV_KEY && code >= crate::BTN_LEFT) || ev_type == crate::EV_REL)
            .then_some((ev_type, code, accepted.value));
        dev.stage_accepted(ev_type, code, accepted).map(|values| {
            crate::repeat::accepted_packet(dev, &values);
            (dev.is_pointer, values)
        }).map_or((None, native_key, native_rel, native_mouse), |packet| (Some(packet), native_key, native_rel, native_mouse))
    };
    if let Some((key, state)) = native_key {
        let _ = dispatch_native_key_event(key, state != KEY_RELEASED, state == KEY_REPEAT);
    }
    if let Some((code, value)) = native_rel {
        let _ = dispatch_native_rel_event(code, value);
    }
    if let Some((ev_type, code, value)) = native_mouse {
        let _ = dispatch_native_mouse_event(ev_type, code, value);
    }
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

/// # C: O(pending input state)
pub(crate) fn release_state(dev: &mut VirtioInputDev, release_mt: bool) -> Option<Vec<InputValue>> {
    if release_mt {
        dev.release_mt_to_pending();
    }
    dev.release_keys_to_pending();
    crate::repeat::cancel(dev);
    dev.flush_synthetic_report()
}

fn lowest_free_evdev_id(devs: &[Box<VirtioInputDev>]) -> Option<u32> {
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
pub fn install(mut dev: Box<VirtioInputDev>) -> Option<(u32, u32)> {
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

/// Register one input model and its evdev endpoint as one unwindable action.
/// A failed endpoint publication removes the just-installed model, leaving its
/// evdev minor available for the next device. # C: O(N_devices + callback)
pub fn install_and_publish(dev: Box<VirtioInputDev>) -> Option<(u32, u32)> {
    let key = dev.device_key;
    let ids = install(dev)?;
    if publish_evdev(ids.1) { return Some(ids); }
    let _ = remove_device(key);
    None
}

/// # C: O(1)
pub fn count() -> usize {
    DEVICES.lock().len()
}

/// # C: O(N_devices + cloned device state)
pub fn devices_snapshot() -> Vec<Box<VirtioInputDev>> {
    DEVICES.lock().clone()
}

/// Release tracked key/MT state through the still-attached handler and cancel
/// autorepeat, leaving the canonical record installed. Linux runs this while
/// evdev clients and the driver-model object are both still live, so the
/// release report reaches readers and sysfs teardown can still project the
/// object. Idempotent.
/// # C: O(N_devices + KEY_CNT + pending packet)
pub fn disconnect_device(device_key: impl Into<InputDeviceKey>) -> Option<u32> {
    let device_key = device_key.into();
    let (evdev_id, is_pointer, packet) = {
        let mut devices = DEVICES.lock();
        let dev = devices.iter_mut().find(|dev| dev.device_key == device_key)?;
        dev.connected = false;
        dev.controller_packet = 0;
        dev.controller_dirty = false;
        let packet = release_state(dev, false);
        dev.raw_events.clear();
        (dev.evdev_id, dev.is_pointer, packet)
    };
    if let Some(values) = packet {
        dispatch_values(evdev_id, is_pointer, &values);
    }
    Some(evdev_id)
}

/// Drop the canonical record. Callers that also own a driver-model node must
/// tear that node down first: sysfs projection, the remove uevent, and cached
/// path invalidation all read this record, so removing it first silently skips
/// them and leaves stale `inputN` paths behind.
/// # C: O(N_devices + KEY_CNT + pending packet)
pub fn remove_device(device_key: impl Into<InputDeviceKey>) -> Option<u32> {
    let device_key = device_key.into();
    let evdev_id = disconnect_device(device_key)?;
    let mut devices = DEVICES.lock();
    let idx = devices.iter().position(|dev| dev.device_key == device_key)?;
    devices.remove(idx);
    Some(evdev_id)
}

/// # C: O(N_devices)
pub fn evdev_id_for_device(device_key: impl Into<InputDeviceKey>) -> Option<u32> {
    let device_key = device_key.into();
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
pub fn device(evdev_id: u32) -> Option<Box<VirtioInputDev>> {
    DEVICES.lock().iter().find(|d| d.evdev_id == evdev_id).cloned()
}

/// Remove up to `limit` raw events from one still-live canonical input device.
/// # C: O(limit)
pub fn take_raw_input(evdev_id: u32, limit: usize) -> Option<Vec<RawInputEvent>> {
    DEVICES.lock().iter_mut().find(|dev| dev.evdev_id == evdev_id).map(|dev| dev.take_raw(limit))
}

/// Return the number of raw events discarded after one device queue filled.
/// # C: O(N_devices)
pub fn raw_input_dropped(evdev_id: u32) -> Option<u64> {
    DEVICES.lock().iter().find(|dev| dev.evdev_id == evdev_id).map(|dev| dev.raw_dropped)
}

/// # C: O(1)
pub(crate) fn matches_identity(
    dev: &VirtioInputDev,
    device_key: InputDeviceKey,
    input_id: u32,
    evdev_id: u32,
) -> bool {
    dev.device_key == device_key && dev.input_id == input_id && dev.evdev_id == evdev_id
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
