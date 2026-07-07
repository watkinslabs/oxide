use core::ffi::{c_char, c_void};

pub(super) type ReleaseFn = unsafe extern "C" fn(*mut LinuxDevice);
pub(super) type DevresAction = unsafe extern "C" fn(*mut c_void);

pub(super) const DEVICE_NAME_LEN: usize = 64;
pub(super) const GFP_ZERO: u32 = 0x8000;
pub(super) const LINUX_OK: i32 = 0;
pub(super) const LINUX_EINVAL: i32 = 22;
pub(super) const LINUX_ENOMEM: i32 = 12;
pub(super) const LINUX_EBUSY: i32 = 16;

#[repr(C)]
pub struct LinuxDevice {
    pub(super) dma_mask: *mut u64,
    pub(super) coherent_dma_mask: u64,
    pub(super) driver_data: *mut c_void,
    pub(super) parent: *mut LinuxDevice,
    pub(super) bus: *mut LinuxBusType,
    pub(super) class: *mut LinuxClass,
    pub(super) driver: *mut LinuxDeviceDriver,
    pub(super) init_name: *const c_char,
    pub(super) name: [c_char; DEVICE_NAME_LEN],
    pub(super) release: Option<ReleaseFn>,
}

#[repr(C)]
pub struct LinuxDeviceDriver {
    pub(super) name: *const c_char,
    pub(super) bus: *mut LinuxBusType,
    pub(super) owner: *mut c_void,
    pub(super) probe: Option<unsafe extern "C" fn(*mut LinuxDevice) -> i32>,
    pub(super) remove: Option<unsafe extern "C" fn(*mut LinuxDevice) -> i32>,
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
