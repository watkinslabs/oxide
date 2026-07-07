use crate::{
    DEFAULT_REPEAT, EV_ABS, EV_KEY, EV_LED, EV_REL, VIRTIO_INPUT_CFG_ABS_INFO,
    VIRTIO_INPUT_CFG_EV_BITS, VIRTIO_INPUT_CFG_ID_DEVIDS, VIRTIO_INPUT_CFG_ID_NAME,
    VIRTIO_INPUT_CFG_ID_SERIAL, VIRTIO_INPUT_CFG_PROP_BITS,
};
use input::{CapBitmap, VirtioInputAbsInfo, VirtioInputDev, VirtioInputDevIds};

const INPUT_CFG_SELECT_OFF: u64 = 0;
const INPUT_CFG_SUBSEL_OFF: u64 = 1;
const INPUT_CFG_SIZE_OFF: u64 = 2;
const INPUT_CFG_PAYLOAD_OFF: u64 = 8;
const INPUT_CFG_PAYLOAD_MAX: usize = 128;
const INPUT_DEVIDS_BYTES: u8 = 8;
const INPUT_EV_TYPE_COUNT: u8 = 32;
const INPUT_ABS_AXIS_COUNT: u8 = 64;
const INPUT_ABS_INFO_BYTES: u8 = 20;
const INPUT_ABS_INFO_MIN_OFF: u64 = 0;
const INPUT_ABS_INFO_MAX_OFF: u64 = 4;
const INPUT_ABS_INFO_FUZZ_OFF: u64 = 8;
const INPUT_ABS_INFO_FLAT_OFF: u64 = 12;
const INPUT_ABS_INFO_RES_OFF: u64 = 16;
const INPUT_DEVIDS_VENDOR_OFF: u64 = 2;
const INPUT_DEVIDS_PRODUCT_OFF: u64 = 4;
const INPUT_DEVIDS_VERSION_OFF: u64 = 6;
const INPUT_U32_BYTES: usize = 4;
const INPUT_LE16_HIGH_BYTE_OFF: u64 = 1;
const INPUT_BYTE_BITS: u16 = 8;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    NoDevice,
    FeaturesNotOk,
    BringUpFail,
    Inval,
    Busy,
}

pub type KResult<T> = core::result::Result<T, Error>;
#[cfg(any(target_os = "oxide-kernel", test))]
pub type ModelParent = Option<(&'static str, alloc::string::String)>;

unsafe fn cfg_select(cfg_va: u64, select: u8, subsel: u8) -> u8 {
    unsafe {
        core::ptr::write_volatile((cfg_va + INPUT_CFG_SELECT_OFF) as *mut u8, select);
        core::ptr::write_volatile((cfg_va + INPUT_CFG_SUBSEL_OFF) as *mut u8, subsel);
        core::ptr::read_volatile((cfg_va + INPUT_CFG_SIZE_OFF) as *const u8)
    }
}

unsafe fn cfg_payload(cfg_va: u64, dst: &mut [u8]) -> usize {
    let size = unsafe { core::ptr::read_volatile((cfg_va + INPUT_CFG_SIZE_OFF) as *const u8) } as usize;
    let n = size.min(dst.len()).min(INPUT_CFG_PAYLOAD_MAX);
    for (i, slot) in dst.iter_mut().take(n).enumerate() {
        *slot = unsafe {
            core::ptr::read_volatile((cfg_va + INPUT_CFG_PAYLOAD_OFF + i as u64) as *const u8)
        };
    }
    n
}

pub(crate) trait InputConfigAccess {
    fn select(&mut self, select: u8, subsel: u8) -> u8;
    fn payload(&mut self, dst: &mut [u8]) -> usize;
    fn payload_u8(&mut self, off: u64) -> u8;
}

struct MmioInputConfig {
    cfg_va: u64,
}

impl InputConfigAccess for MmioInputConfig {
    fn select(&mut self, select: u8, subsel: u8) -> u8 {
        unsafe { cfg_select(self.cfg_va, select, subsel) }
    }

    fn payload(&mut self, dst: &mut [u8]) -> usize {
        unsafe { cfg_payload(self.cfg_va, dst) }
    }

    fn payload_u8(&mut self, off: u64) -> u8 {
        unsafe { core::ptr::read_volatile((self.cfg_va + INPUT_CFG_PAYLOAD_OFF + off) as *const u8) }
    }
}

fn set_cap_bit(bits: &mut [u8], bit: u16) {
    let byte = (bit / INPUT_BYTE_BITS) as usize;
    let shift = bit % INPUT_BYTE_BITS;
    if let Some(slot) = bits.get_mut(byte) {
        *slot |= 1u8 << shift;
    }
}

fn cap_bit_is_set(bits: &[u8], bit: u16) -> bool {
    let byte = (bit / INPUT_BYTE_BITS) as usize;
    let shift = bit % INPUT_BYTE_BITS;
    bits.get(byte).map(|slot| (*slot & (1u8 << shift)) != 0).unwrap_or(false)
}

pub fn install_device(
    device_key: virtio::VirtioChildDeviceKey,
    resources: virtio::VirtioResources,
) -> Option<u32> {
    let cfg_va = resources.device_cfg_va;
    if cfg_va == 0 {
        return None;
    }
    let mut cfg = MmioInputConfig { cfg_va };
    install_device_with_config(device_key, &mut cfg)
}

/// # C: install virtio-input state and publish the owned input model node
#[cfg(any(target_os = "oxide-kernel", test))]
pub fn install_device_with_parent(
    device_key: virtio::VirtioChildDeviceKey,
    resources: virtio::VirtioResources,
    parent: ModelParent,
) -> Option<u32> {
    let cfg_va = resources.device_cfg_va;
    if cfg_va == 0 {
        return None;
    }
    let mut cfg = MmioInputConfig { cfg_va };
    install_device_with_config_and_parent(device_key, &mut cfg, parent)
}

#[cfg(test)]
pub(crate) fn install_device_with_config_for_tests<C: InputConfigAccess>(
    device_key: virtio::VirtioChildDeviceKey,
    cfg: &mut C,
) -> Option<u32> {
    install_device_with_config(device_key, cfg)
}

#[cfg(test)]
pub(crate) fn install_device_with_config_and_parent_for_tests<C: InputConfigAccess>(
    device_key: virtio::VirtioChildDeviceKey,
    cfg: &mut C,
    parent: ModelParent,
) -> Option<u32> {
    install_device_with_config_and_parent(device_key, cfg, parent)
}

#[cfg(any(target_os = "oxide-kernel", test))]
fn install_device_with_config_and_parent<C: InputConfigAccess>(
    device_key: virtio::VirtioChildDeviceKey,
    cfg: &mut C,
    parent: ModelParent,
) -> Option<u32> {
    let evdev_id = install_device_with_config(device_key, cfg)?;
    if crate::devfs::register_node(evdev_id, parent) {
        Some(evdev_id)
    } else {
        let _ = input::remove_device(device_key);
        None
    }
}

fn install_device_with_config<C: InputConfigAccess>(
    device_key: virtio::VirtioChildDeviceKey,
    cfg: &mut C,
) -> Option<u32> {
    if input::evdev_id_for_device(device_key).is_some() { return None; }
    let evdev_id = input::next_free_evdev_id()?;
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
    {
        let _ = cfg.select(VIRTIO_INPUT_CFG_ID_NAME, 0);
        dev.name_len = cfg.payload(&mut dev.name);
        let _ = cfg.select(VIRTIO_INPUT_CFG_ID_SERIAL, 0);
        dev.serial_len = cfg.payload(&mut dev.serial);
        let n = cfg.select(VIRTIO_INPUT_CFG_ID_DEVIDS, 0);
        if n >= INPUT_DEVIDS_BYTES {
            let mut rd16 = |o: u64| {
                (cfg.payload_u8(o) as u16)
                    | ((cfg.payload_u8(o + INPUT_LE16_HIGH_BYTE_OFF) as u16) << INPUT_BYTE_BITS)
            };
            dev.ids = VirtioInputDevIds {
                bustype: rd16(0),
                vendor: rd16(INPUT_DEVIDS_VENDOR_OFF),
                product: rd16(INPUT_DEVIDS_PRODUCT_OFF),
                version: rd16(INPUT_DEVIDS_VERSION_OFF),
            };
        }
        let _ = cfg.select(VIRTIO_INPUT_CFG_PROP_BITS, 0);
        let _ = cfg.payload(&mut dev.prop_bits);
        let mut abs_sz = 0u8;
        for ty in 0u8..INPUT_EV_TYPE_COUNT {
            let sz = cfg.select(VIRTIO_INPUT_CFG_EV_BITS, ty);
            if sz == 0 {
                continue;
            }
            set_cap_bit(&mut dev.ev_bits, ty as u16);
            match ty as u16 {
                EV_KEY => {
                    let _ = cfg.payload(&mut dev.key_bits.bits);
                }
                EV_REL => {
                    let _ = cfg.payload(&mut dev.rel_bits.bits);
                }
                EV_ABS => {
                    abs_sz = sz;
                    let _ = cfg.payload(&mut dev.abs_bits.bits);
                }
                EV_LED => {
                    let _ = cfg.payload(&mut dev.led_bits.bits);
                }
                _ => {}
            }
        }
        if abs_sz > 0 {
            for axis in 0..INPUT_ABS_AXIS_COUNT {
                if !cap_bit_is_set(&dev.abs_bits.bits, axis as u16) {
                    continue;
                }
                let m = cfg.select(VIRTIO_INPUT_CFG_ABS_INFO, axis);
                if m >= INPUT_ABS_INFO_BYTES {
                    let mut rd32 = |o: u64| {
                        let mut v = 0u32;
                        for b in 0..INPUT_U32_BYTES {
                            let shift = (b as u32) * INPUT_BYTE_BITS as u32;
                            v |= (cfg.payload_u8(o + b as u64) as u32) << shift;
                        }
                        v
                    };
                    dev.abs_info[axis as usize] = Some(VirtioInputAbsInfo {
                        min: rd32(INPUT_ABS_INFO_MIN_OFF),
                        max: rd32(INPUT_ABS_INFO_MAX_OFF),
                        fuzz: rd32(INPUT_ABS_INFO_FUZZ_OFF),
                        flat: rd32(INPUT_ABS_INFO_FLAT_OFF),
                        res: rd32(INPUT_ABS_INFO_RES_OFF),
                    });
                }
            }
        }
        dev.is_pointer = cap_bit_is_set(&dev.ev_bits, EV_REL)
            || cap_bit_is_set(&dev.ev_bits, EV_ABS);
    }
    input::install(dev);
    Some(evdev_id)
}

/// # C: remove the owned input model node and clear virtio-input state
#[cfg(any(target_os = "oxide-kernel", test))]
pub fn remove_device_with_node(device_key: virtio::VirtioChildDeviceKey) -> Option<u32> {
    let evdev_id = input::evdev_id_for_device(device_key)?;
    let _ = crate::devfs::unregister_node(evdev_id);
    input::remove_device(device_key)
}

#[cfg(test)]
pub(crate) fn clear_devices_for_tests() {
    input::clear_devices_for_tests();
}
