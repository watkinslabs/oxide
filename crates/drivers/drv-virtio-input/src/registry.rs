use alloc::vec::Vec;

use sync::{Spinlock, TaskList as DriverLockClass};

use crate::{
    types::{VirtioInputAbsInfo, VirtioInputDevIds},
    DEFAULT_REPEAT, EV_ABS, EV_KEY, EV_LED, EV_REL, MAX_INPUT_DEVICES, VIRTIO_INPUT_CFG_ABS_INFO,
    VIRTIO_INPUT_CFG_EV_BITS, VIRTIO_INPUT_CFG_ID_DEVIDS, VIRTIO_INPUT_CFG_ID_NAME,
    VIRTIO_INPUT_CFG_ID_SERIAL, VIRTIO_INPUT_CFG_PROP_BITS,
};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    NoDevice,
    FeaturesNotOk,
    BringUpFail,
    Inval,
    Busy,
}

pub type KResult<T> = core::result::Result<T, Error>;

#[derive(Clone, Debug)]
pub struct CapBitmap {
    pub bits: [u8; 96],
}

impl Default for CapBitmap {
    fn default() -> Self {
        Self { bits: [0u8; 96] }
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

static DEVICES: Spinlock<Vec<VirtioInputDev>, DriverLockClass> = Spinlock::new(Vec::new());

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

unsafe fn cfg_select(cfg_va: u64, select: u8, subsel: u8) -> u8 {
    unsafe {
        core::ptr::write_volatile(cfg_va as *mut u8, select);
        core::ptr::write_volatile((cfg_va + 1) as *mut u8, subsel);
        core::ptr::read_volatile((cfg_va + 2) as *const u8)
    }
}

unsafe fn cfg_payload(cfg_va: u64, dst: &mut [u8]) -> usize {
    let size = unsafe { core::ptr::read_volatile((cfg_va + 2) as *const u8) } as usize;
    let n = size.min(dst.len()).min(128);
    for (i, slot) in dst.iter_mut().take(n).enumerate() {
        *slot = unsafe { core::ptr::read_volatile((cfg_va + 8 + i as u64) as *const u8) };
    }
    n
}

pub fn install_device(
    device_key: virtio::VirtioChildDeviceKey,
    resources: virtio::VirtioResources,
) -> Option<u32> {
    let cfg_va = resources.device_cfg_va;
    if cfg_va == 0 {
        return None;
    }
    let evdev_id = {
        let g = DEVICES.lock();
        if g.iter().any(|d| d.device_key == device_key) {
            return None;
        }
        lowest_free_evdev_id(&g)?
    };
    let mut dev = VirtioInputDev {
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
    };
    unsafe {
        let _ = cfg_select(cfg_va, VIRTIO_INPUT_CFG_ID_NAME, 0);
        dev.name_len = cfg_payload(cfg_va, &mut dev.name);
        let _ = cfg_select(cfg_va, VIRTIO_INPUT_CFG_ID_SERIAL, 0);
        dev.serial_len = cfg_payload(cfg_va, &mut dev.serial);
        let n = cfg_select(cfg_va, VIRTIO_INPUT_CFG_ID_DEVIDS, 0);
        if n >= 8 {
            let rd16 = |o: u64| {
                (core::ptr::read_volatile((cfg_va + 8 + o) as *const u8) as u16)
                    | ((core::ptr::read_volatile((cfg_va + 9 + o) as *const u8) as u16) << 8)
            };
            dev.ids = VirtioInputDevIds {
                bustype: rd16(0),
                vendor: rd16(2),
                product: rd16(4),
                version: rd16(6),
            };
        }
        let _ = cfg_select(cfg_va, VIRTIO_INPUT_CFG_PROP_BITS, 0);
        let _ = cfg_payload(cfg_va, &mut dev.prop_bits);
        let mut abs_sz = 0u8;
        for ty in 0u8..32 {
            let sz = cfg_select(cfg_va, VIRTIO_INPUT_CFG_EV_BITS, ty);
            if sz == 0 {
                continue;
            }
            dev.ev_bits[(ty / 8) as usize] |= 1 << (ty % 8);
            match ty as u16 {
                EV_KEY => {
                    let _ = cfg_payload(cfg_va, &mut dev.key_bits.bits);
                }
                EV_REL => {
                    let _ = cfg_payload(cfg_va, &mut dev.rel_bits.bits);
                }
                EV_ABS => {
                    abs_sz = sz;
                    let _ = cfg_payload(cfg_va, &mut dev.abs_bits.bits);
                }
                EV_LED => {
                    let _ = cfg_payload(cfg_va, &mut dev.led_bits.bits);
                }
                _ => {}
            }
        }
        if abs_sz > 0 {
            for axis in 0..64u8 {
                if dev.abs_bits.bits[(axis / 8) as usize] & (1 << (axis % 8)) == 0 {
                    continue;
                }
                let m = cfg_select(cfg_va, VIRTIO_INPUT_CFG_ABS_INFO, axis);
                if m >= 20 {
                    let rd32 = |o: u64| {
                        let mut v = 0u32;
                        for b in 0..4 {
                            v |= (core::ptr::read_volatile((cfg_va + 8 + o + b) as *const u8) as u32)
                                << (b * 8);
                        }
                        v
                    };
                    dev.abs_info[axis as usize] = Some(VirtioInputAbsInfo {
                        min: rd32(0),
                        max: rd32(4),
                        fuzz: rd32(8),
                        flat: rd32(12),
                        res: rd32(16),
                    });
                }
            }
        }
        dev.is_pointer = (dev.ev_bits[(EV_REL / 8) as usize] & (1 << (EV_REL % 8))) != 0
            || (dev.ev_bits[(EV_ABS / 8) as usize] & (1 << (EV_ABS % 8))) != 0;
    }
    install(dev);
    Some(evdev_id)
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

#[cfg(test)]
pub(crate) fn clear_devices_for_tests() {
    DEVICES.lock().clear();
}
