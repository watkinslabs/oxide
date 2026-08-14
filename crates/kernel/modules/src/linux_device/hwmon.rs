use super::core;
use super::types::LinuxDevice;
use ::core::ffi::{c_char, c_void};
use ::core::ptr::null_mut;

#[repr(C)]
struct HwmonOps { visible: u16, _pad: u16, is_visible: *const c_void, _read: *const c_void, _read_string: *const c_void, _write: *const c_void }
#[repr(C)]
struct HwmonChipInfo { ops: *const HwmonOps, info: *const *const c_void }

pub(super) fn export_symbols() {
    use crate::symtab::export;
    export("hwmon_device_register_with_info", hwmon_device_register_with_info as *const () as usize, true);
    export("hwmon_device_unregister", hwmon_device_unregister as *const () as usize, true);
}

extern "C" fn hwmon_device_register_with_info(parent: *mut LinuxDevice, name: *const c_char, data: *mut c_void, chip: *const HwmonChipInfo, _groups: *const *const c_void) -> *mut LinuxDevice {
    if parent.is_null() || name.is_null() || chip.is_null() { return null_mut(); }
    // SAFETY: chip is validated non-null and follows the caller-provided hwmon ABI layout.
    let chip = unsafe { &*chip };
    if chip.ops.is_null() || chip.info.is_null() { return null_mut(); }
    // SAFETY: ops is validated non-null and only the Linux ABI visibility fields are read.
    let ops = unsafe { &*chip.ops };
    if ops.visible == 0 && ops.is_visible.is_null() { return null_mut(); }
    let dev = core::register_child(parent, name);
    if dev.is_null() { return null_mut(); }
    // SAFETY: register_child returns a live unpublished-to-caller Linux device.
    unsafe { (*dev).driver_data = data; }
    dev
}

extern "C" fn hwmon_device_unregister(dev: *mut LinuxDevice) {
    if dev.is_null() { return; }
    core::unregister_child(dev);
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn registration_validates_chip_and_preserves_parent_drvdata() {
        let _modules = crate::test_serial::claim();
        let mut parent = LinuxDevice::new();
        core::initialize_embedded(&mut parent);
        let data = &mut parent as *mut _ as *mut c_void;
        assert!(hwmon_device_register_with_info(&mut parent, c"n".as_ptr(), data, ::core::ptr::null(), ::core::ptr::null()).is_null());
        let ops = HwmonOps { visible: 1, _pad: 0, is_visible: ::core::ptr::null(), _read: ::core::ptr::null(), _read_string: ::core::ptr::null(), _write: ::core::ptr::null() };
        let info = [::core::ptr::null()];
        let chip = HwmonChipInfo { ops: &ops, info: info.as_ptr() };
        let dev = hwmon_device_register_with_info(&mut parent, c"n".as_ptr(), data, &chip, ::core::ptr::null());
        assert!(!dev.is_null());
        unsafe { assert!((*dev).parent == &mut parent); assert_eq!((*dev).driver_data, data); }
        hwmon_device_unregister(dev);
    }
}
