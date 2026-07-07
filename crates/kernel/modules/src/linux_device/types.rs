use core::ffi::{c_char, c_void};
use crate::linux_pm::types::{LinuxDevPmInfo, LinuxDevPmOps};

pub(crate) type ReleaseFn = unsafe extern "C" fn(*mut LinuxDevice);
pub(super) type DevresAction = unsafe extern "C" fn(*mut c_void);

pub(crate) const DEVICE_NAME_LEN: usize = 64;
pub(super) const GFP_ZERO: u32 = 0x8000;
pub(super) const LINUX_OK: i32 = 0;
pub(super) const LINUX_EINVAL: i32 = 22;
pub(super) const LINUX_ENOMEM: i32 = 12;
pub(super) const LINUX_EBUSY: i32 = 16;

#[repr(C)]
pub struct LinuxDevice {
    pub(crate) dma_mask: *mut u64,
    pub(crate) coherent_dma_mask: u64,
    pub(crate) driver_data: *mut c_void,
    pub(crate) parent: *mut LinuxDevice,
    pub(crate) bus: *mut LinuxBusType,
    pub(crate) class: *mut LinuxClass,
    pub(crate) driver: *mut LinuxDeviceDriver,
    pub(crate) init_name: *const c_char,
    pub(crate) name: [c_char; DEVICE_NAME_LEN],
    pub(crate) release: Option<ReleaseFn>,
    pub(crate) of_node: *mut c_void,
    pub(crate) acpi_node: *mut c_void,
    pub(crate) power: LinuxDevPmInfo,
}

#[repr(C)]
pub struct LinuxDeviceDriver {
    pub(crate) name: *const c_char,
    pub(crate) bus: *mut LinuxBusType,
    pub(crate) owner: *mut c_void,
    pub(crate) probe: Option<unsafe extern "C" fn(*mut LinuxDevice) -> i32>,
    pub(crate) remove: Option<unsafe extern "C" fn(*mut LinuxDevice) -> i32>,
    pub(crate) of_match_table: *const c_void,
    pub(crate) acpi_match_table: *const c_void,
    pub(crate) pm: *const LinuxDevPmOps,
}

#[repr(C)]
pub struct LinuxBusType {
    pub(super) name: *const c_char,
    pub(super) private: *mut c_void,
}

#[repr(C)]
pub struct LinuxClass {
    pub(super) name: *const c_char,
    pub(super) owner: *mut c_void,
    pub(super) private: *mut c_void,
}

#[repr(C)]
pub struct LinuxDeviceAttribute {
    pub(super) attr: LinuxAttribute,
    pub(super) show: Option<unsafe extern "C" fn(*mut LinuxDevice, *mut LinuxDeviceAttribute, *mut c_char) -> isize>,
    pub(super) store: Option<unsafe extern "C" fn(*mut LinuxDevice, *mut LinuxDeviceAttribute, *const c_char, usize) -> isize>,
}

#[repr(C)]
pub struct LinuxAttribute {
    pub(super) name: *const c_char,
    pub(super) mode: u16,
}
