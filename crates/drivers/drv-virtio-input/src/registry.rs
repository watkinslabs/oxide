use crate::{
    EV_ABS, EV_KEY, EV_LED, EV_MSC, EV_REL, EV_REP, EV_SND, EV_SW, VIRTIO_INPUT_CFG_ABS_INFO,
    VIRTIO_INPUT_CFG_EV_BITS, VIRTIO_INPUT_CFG_ID_DEVIDS, VIRTIO_INPUT_CFG_ID_NAME,
    VIRTIO_INPUT_CFG_ID_SERIAL, VIRTIO_INPUT_CFG_PROP_BITS,
};
#[cfg(any(target_os = "oxide-kernel", test))]
use alloc::sync::Arc;
use input::{VirtioInputAbsInfo, VirtioInputDev, VirtioInputDevIds};

const INPUT_CFG_SELECT_OFF: u64 = 0;
const INPUT_CFG_SUBSEL_OFF: u64 = 1;
const INPUT_CFG_SIZE_OFF: u64 = 2;
const INPUT_CFG_PAYLOAD_OFF: u64 = 8;
const INPUT_CFG_PAYLOAD_MAX: usize = 128;
const INPUT_DEVIDS_BYTES: u8 = core::mem::size_of::<VirtioInputDevIds>() as u8;
const INPUT_ABS_AXIS_COUNT: u8 = input::ABS_CNT as u8;
const INPUT_ABS_INFO_BYTES: u8 = core::mem::size_of::<VirtioInputAbsInfo>() as u8;
const INPUT_ABS_INFO_MIN_OFF: u64 = 0;
const INPUT_ABS_INFO_MAX_OFF: u64 = 4;
const INPUT_ABS_INFO_FUZZ_OFF: u64 = 8;
const INPUT_ABS_INFO_FLAT_OFF: u64 = 12;
const INPUT_ABS_INFO_RES_OFF: u64 = 16;
const INPUT_DEVIDS_VENDOR_OFF: u64 = 2;
const INPUT_DEVIDS_PRODUCT_OFF: u64 = 4;
const INPUT_DEVIDS_VERSION_OFF: u64 = 6;
const INPUT_DEVIDS_BUSTYPE_OFF: u64 = 0;
const INPUT_U32_BYTES: usize = core::mem::size_of::<u32>();
const INPUT_LE16_HIGH_BYTE_OFF: u64 = core::mem::size_of::<u8>() as u64;
const INPUT_BYTE_BITS: u16 = u8::BITS as u16;
const VIRTIO_BUS_NAME: &str = "virtio";
const INPUT_PHYS_FUNCTION: &str = "input0";
pub(crate) const BUS_VIRTUAL: u16 = 0x0006;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    NoDevice,
    FeaturesNotOk,
    BringUpFail,
    Inval,
    Busy,
}

pub type KResult<T> = core::result::Result<T, Error>;

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
    install_device_with_config(device_key, &mut cfg, None)
}

/// Prepare canonical input state without publishing an externally openable
/// event node. The transport queue owner publishes only after q0/q1 install.
#[cfg(any(target_os = "oxide-kernel", test))]
pub fn prepare_device_with_parent(
    device_key: virtio::VirtioChildDeviceKey,
    resources: virtio::VirtioResources,
    parent: Option<&Arc<drv::Device>>,
) -> Option<u32> {
    let cfg_va = resources.device_cfg_va;
    if cfg_va == 0 {
        return None;
    }
    let mut cfg = MmioInputConfig { cfg_va };
    prepare_device_with_config_and_parent(device_key, &mut cfg, parent)
}

#[cfg(test)]
pub(crate) fn install_device_with_config_for_tests<C: InputConfigAccess>(
    device_key: virtio::VirtioChildDeviceKey,
    cfg: &mut C,
) -> Option<u32> {
    install_device_with_config(device_key, cfg, None)
}

#[cfg(test)]
pub(crate) fn prepare_device_with_config_and_parent_for_tests<C: InputConfigAccess>(
    device_key: virtio::VirtioChildDeviceKey,
    cfg: &mut C,
    parent: Option<&Arc<drv::Device>>,
) -> Option<u32> {
    prepare_device_with_config_and_parent(device_key, cfg, parent)
}

#[cfg(any(target_os = "oxide-kernel", test))]
fn prepare_device_with_config_and_parent<C: InputConfigAccess>(
    device_key: virtio::VirtioChildDeviceKey,
    cfg: &mut C,
    parent: Option<&Arc<drv::Device>>,
) -> Option<u32> {
    let phys = parent
        .filter(|dev| dev.bus == VIRTIO_BUS_NAME)
        .map(|dev| alloc::format!("{}/{INPUT_PHYS_FUNCTION}", dev.addr));
    install_device_with_config(device_key, cfg, phys.as_deref())
}

/// Publish the prepared event node against the exact live transport parent.
#[cfg(any(target_os = "oxide-kernel", test))]
pub fn publish_device_node(
    evdev_id: u32,
    parent: Option<&Arc<drv::Device>>,
) -> bool {
    crate::devfs::register_node(evdev_id, parent)
}

fn install_device_with_config<C: InputConfigAccess>(
    device_key: virtio::VirtioChildDeviceKey,
    cfg: &mut C,
    phys: Option<&str>,
) -> Option<u32> {
    if input::evdev_id_for_device(device_key).is_some() { return None; }
    let mut dev = VirtioInputDev::empty_boxed(device_key);
    dev.name_present = true;
    dev.phys_present = phys.is_some();
    dev.serial_present = true;
    // Linux virtio-input defaults to BUS_VIRTUAL when DEVIDS is absent or
    // shorter than the complete four-field payload.
    dev.ids.bustype = BUS_VIRTUAL;
    if let Some(phys) = phys {
        dev.phys_len = phys.len().min(dev.phys.len());
        dev.phys[..dev.phys_len].copy_from_slice(&phys.as_bytes()[..dev.phys_len]);
    }
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
                bustype: rd16(INPUT_DEVIDS_BUSTYPE_OFF),
                vendor: rd16(INPUT_DEVIDS_VENDOR_OFF),
                product: rd16(INPUT_DEVIDS_PRODUCT_OFF),
                version: rd16(INPUT_DEVIDS_VERSION_OFF),
            };
        }
        let _ = cfg.select(VIRTIO_INPUT_CFG_PROP_BITS, 0);
        let _ = cfg.payload(&mut dev.prop_bits);
        let mut abs_sz = 0u8;
        for ty in [
            EV_KEY as u8,
            EV_REL as u8,
            EV_ABS as u8,
            EV_MSC as u8,
            EV_SW as u8,
            EV_LED as u8,
            EV_SND as u8,
        ] {
            let sz = cfg.select(VIRTIO_INPUT_CFG_EV_BITS, ty);
            if sz == 0 {
                continue;
            }
            match ty as u16 {
                EV_KEY => {
                    set_cap_bit(&mut dev.ev_bits, ty as u16);
                    let _ = cfg.payload(&mut dev.key_bits.bits);
                }
                EV_REL => {
                    set_cap_bit(&mut dev.ev_bits, ty as u16);
                    let _ = cfg.payload(&mut dev.rel_bits.bits);
                }
                EV_ABS => {
                    set_cap_bit(&mut dev.ev_bits, ty as u16);
                    abs_sz = sz;
                    let _ = cfg.payload(&mut dev.abs_bits.bits);
                }
                EV_MSC => {
                    set_cap_bit(&mut dev.ev_bits, ty as u16);
                    let _ = cfg.payload(&mut dev.msc_bits.bits);
                }
                EV_LED => {
                    set_cap_bit(&mut dev.ev_bits, ty as u16);
                    let _ = cfg.payload(&mut dev.led_bits.bits);
                }
                EV_SND => {
                    set_cap_bit(&mut dev.ev_bits, ty as u16);
                    let _ = cfg.payload(&mut dev.snd_bits.bits);
                }
                EV_SW => {
                    set_cap_bit(&mut dev.ev_bits, ty as u16);
                    let _ = cfg.payload(&mut dev.sw_bits.bits);
                }
                _ => {}
            }
        }
        if cfg.select(VIRTIO_INPUT_CFG_EV_BITS, EV_REP as u8) > 0 {
            set_cap_bit(&mut dev.ev_bits, EV_REP);
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
    let (_, evdev_id) = input::install(dev)?;
    Some(evdev_id)
}

/// # C: remove the owned input model node and clear virtio-input state
#[cfg(any(target_os = "oxide-kernel", test))]
pub fn remove_device_with_node(device_key: virtio::VirtioChildDeviceKey) -> Option<u32> {
    let evdev_id = input::evdev_id_for_device(device_key)?;
    // Linux order: release tracked state through the live handler, tear the
    // driver-model objects down (which emits the remove uevents and drops the
    // cached `inputN`/`eventN`/class paths), and only then drop the canonical
    // record those teardown steps read.
    input::disconnect_device(device_key)?;
    let _ = crate::devfs::unregister_node(evdev_id);
    input::remove_device(device_key)
}

#[cfg(test)]
pub(crate) fn clear_devices_for_tests() {
    for evdev_id in 0..crate::MAX_INPUT_DEVICES as u32 {
        let _ = crate::devfs::unregister_node(evdev_id);
    }
    input::clear_devices_for_tests();
}

// The input device table is process-global and has MAX_INPUT_DEVICES slots:
// the `input::` canonical records, the devfs `eventN` nodes and the evdev
// endpoint publications are one table reached through three modules. Hosted
// tests published into it from `tests`, `devfs::tests`, `procfs` and `drain`
// while only `tests` took a lock, and the ones that picked slot numbers by
// hand collided outright (two different devices both claimed `5`). So one
// test's clear landed inside another's measurement window and one test's
// publish stole another's slot.
//
// The lock belongs to the table. Every test that touches it takes THIS one —
// a second lock elsewhere would exclude nothing, which is how this got here.
#[cfg(test)]
static DEVICE_TABLE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Exclusive hosted ownership of the input device table for a test's whole
/// body. The table is empty on entry and on exit, so neither a failed test nor
/// a test that forgets to clean up can taint the next owner.
#[cfg(test)]
#[must_use = "the table is only owned while the guard lives"]
pub(crate) struct DeviceTableOwner {
    _guard: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
impl Drop for DeviceTableOwner {
    fn drop(&mut self) { clear_devices_for_tests(); }
}

/// # C: O(MAX_INPUT_DEVICES)
#[cfg(test)]
pub(crate) fn own_device_table() -> DeviceTableOwner {
    let guard = match DEVICE_TABLE.lock() {
        Ok(guard) => guard,
        Err(poisoned) => { DEVICE_TABLE.clear_poison(); poisoned.into_inner() }
    };
    clear_devices_for_tests();
    DeviceTableOwner { _guard: guard }
}
