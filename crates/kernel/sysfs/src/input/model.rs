use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::Ino;

pub(super) const INO_VIRT_INPUT: Ino = crate::ids::INPUT_VIRT;
pub(super) const INO_CLASS_INPUT: Ino = crate::ids::INPUT_CLASS;
pub(super) const INO_INPUT_DIR: Ino = crate::ids::INPUT_DIR;
pub(super) const INO_INPUT_ATTR: Ino = crate::ids::INPUT_ATTR;
pub(super) const INO_INPUT_LINK: Ino = crate::ids::INPUT_LINK;

const EVENT_NAME_PREFIX: &str = "event";
const INPUT_DEVNAME_PREFIX: &str = "input/";
const INPUT_NAME_PREFIX: &str = "input";

#[derive(Clone)]
pub(super) struct InputDevInfo {
    pub(super) device: Arc<drv::Device>,
    pub(super) addr: String,
    pub(super) dev_t: (u32, u32),
    pub(super) devname: String,
    pub(super) model: Box<input::VirtioInputDev>,
}

#[derive(Clone)]
pub(super) struct InputIdentity {
    device: Arc<drv::Device>,
    addr: String,
    device_key: input::VirtioChildDeviceKey,
    input_id: u32,
    evdev_id: u32,
}

impl InputDevInfo {
    /// Stable identity retained by projected sysfs inodes. # C: O(path length)
    pub(super) fn identity(&self) -> InputIdentity {
        InputIdentity {
            device: Arc::clone(&self.device),
            addr: self.addr.clone(),
            device_key: self.model.device_key,
            input_id: self.model.input_id,
            evdev_id: self.model.evdev_id,
        }
    }

    /// Live inputN path retained as the direct parent of the driver-owned
    /// event path. # C: O(parent depth * N_devices)
    pub(super) fn sysfs_parent_canon(&self) -> Option<String> {
        let event = self.sysfs_event_canon()?;
        let (parent, event_name) = event.rsplit_once('/')?;
        if event_name != self.addr {
            return None;
        }
        let parent_name = parent.rsplit('/').next()?;
        if parent_name != alloc::format!("{INPUT_NAME_PREFIX}{}", self.model.input_id) {
            return None;
        }
        Some(String::from(parent))
    }

    /// Live eventN path from the exact driver-model object. No alternate
    /// topology is reconstructed by sysfs. # C: O(parent depth * N_devices)
    pub(super) fn sysfs_event_canon(&self) -> Option<String> {
        drv::device_canon_exact(&self.device)
    }
}

/// Join each published evdev driver node to its canonical input record.
/// Orphaned/mismatched records are not projected into a fabricated path.
/// # C: O(N_devices²)
pub(super) fn input_devs() -> Vec<InputDevInfo> {
    let mut projected = Vec::new();
    for device in drv::devices() {
        if device.bus != "input" {
            continue;
        }
        if let Some(info) = project_device(device) {
            projected.push(info);
        }
    }
    projected
}

/// Validate and join one driver-model input node to its canonical record.
/// # C: O(N_devices + cloned device state)
fn project_device(device: Arc<drv::Device>) -> Option<InputDevInfo> {
    let dev_t @ (major, minor) = device.dev_t?;
    if major != input::INPUT_MAJOR {
        return None;
    }
    let devname = device.devname.clone()?;
    let evdev_id = minor.checked_sub(input::EVENT_MINOR_BASE)?;
    let event_name = alloc::format!("{EVENT_NAME_PREFIX}{evdev_id}");
    if device.addr != event_name
        || devname.strip_prefix(INPUT_DEVNAME_PREFIX) != Some(event_name.as_str())
    {
        return None;
    }
    let model = input::device(evdev_id)?;
    if model.evdev_id != evdev_id {
        return None;
    }
    let info = InputDevInfo {
        addr: device.addr.clone(),
        device,
        dev_t,
        devname,
        model,
    };
    info.sysfs_parent_canon()?;
    Some(info)
}

/// Canonical model join by eventN address. # C: O(N_devices²)
pub(super) fn input_by_addr(addr: &str) -> Option<InputDevInfo> {
    input_devs().into_iter().find(|dev| dev.addr == addr)
}

/// Revalidate a retained sysfs inode against its original Linux input object.
/// # C: O(N_devices²)
pub(super) fn input_by_identity(identity: &InputIdentity) -> Option<InputDevInfo> {
    let info = input_by_addr(&identity.addr)?;
    if !Arc::ptr_eq(&info.device, &identity.device)
        || info.model.device_key != identity.device_key
        || info.model.input_id != identity.input_id
        || info.model.evdev_id != identity.evdev_id
    {
        return None;
    }
    Some(info)
}

pub(super) fn parent_name(info: &InputDevInfo) -> String {
    alloc::format!("input{}", info.model.input_id)
}

pub(super) fn parent_device_target(info: &InputDevInfo) -> Option<Vec<u8>> {
    let parent_canon = info.sysfs_parent_canon()?;
    let device_canon = drv::device_parent_canon_exact(&info.device)?;
    Some(alloc::format!(
        "{}{}",
        crate::bus::ups_prefix(&parent_canon),
        device_canon,
    ).into_bytes())
}
