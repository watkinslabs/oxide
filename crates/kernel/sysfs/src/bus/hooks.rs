extern crate alloc;
use alloc::vec::Vec;

use super::device::{dev_uevent_env, find_dev};
use super::dirs::{make_bus_devices_inode, make_bus_drivers_inode, make_devices_root_inode};
use super::ids::dev_root_canon;
use super::index::{dev_devpath, make_sys_dev_index_inode, DevIndexKind};

/// Register dynamic bus/devices directories in the sysfs tree. # C: O(1)
pub fn init() {
    crate::register("/sys/bus/pci/devices",    make_bus_devices_inode("pci"));
    crate::register("/sys/bus/pci/drivers",    make_bus_drivers_inode("pci"));
    crate::register("/sys/bus/virtio/devices", make_bus_devices_inode("virtio"));
    crate::register("/sys/bus/virtio/drivers", make_bus_drivers_inode("virtio"));
    crate::register("/sys/bus/platform/devices", make_bus_devices_inode("platform"));
    crate::register("/sys/bus/platform/drivers", make_bus_drivers_inode("platform"));
    crate::register("/sys/devices/pci0000:00", make_devices_root_inode("pci"));
    crate::register("/sys/devices/virtio",     make_devices_root_inode("virtio"));
    crate::register("/sys/devices/platform",   make_devices_root_inode("platform"));
    crate::register("/sys/dev/char",           make_sys_dev_index_inode(DevIndexKind::Char));
    crate::register("/sys/dev/block",          make_sys_dev_index_inode(DevIndexKind::Block));
}

// --- drv-hook callbacks the kernel wires via drv::set_*_hook --------------
// The tree is dynamic (read from the drv registry on access), so these
// hooks need do no eager devfs work; they exist to satisfy the drv
// contract and to broadcast a kobject uevent so udev coldplug sees the
// device appear. Honest simplification: no per-device devfs key is
// written — the dir inodes synthesise children on demand.

/// drv `set_sysfs_hook` target: a device was registered. # C: O(1)
pub fn publish_device_cb(dev: &drv::Device) {
    let devpath = dev_devpath(dev);
    let env = dev_uevent_env(dev);
    let refs: Vec<&str> = env.iter().map(|s| s.as_str()).collect();
    ::netlink::emit_uevent_with_env("add", &devpath, dev.bus, &refs);
}

/// drv `set_sysfs_remove_hook` target: a device is being removed while it is
/// still visible in the model registry. # C: O(1)
pub fn remove_device_cb(dev: &drv::Device) {
    let devpath = dev_devpath(dev);
    let env = dev_uevent_env(dev);
    let refs: Vec<&str> = env.iter().map(|s| s.as_str()).collect();
    ::netlink::emit_uevent_with_env("remove", &devpath, dev.bus, &refs);
}

/// drv `set_driver_hook` target: a driver was registered. # C: O(1)
pub fn publish_driver_cb(_bus: &str, _name: &'static str) {}

/// drv `set_bind_hook` target: a device binding changed after model state was
/// updated. # C: O(N_devices)
pub fn bind_device_cb(bus: &str, addr: &str, _driver: &'static str, _event: drv::BindEvent) {
    let devpath = alloc::format!("/{}/{}", dev_root_canon(bus), addr);
    if let Some(dev) = find_dev(bus, addr) {
        let env = dev_uevent_env(&dev);
        let refs: Vec<&str> = env.iter().map(|s| s.as_str()).collect();
        ::netlink::emit_uevent_with_env("change", &devpath, bus, &refs);
    } else {
        ::netlink::emit_uevent("change", &devpath, bus);
    }
}
