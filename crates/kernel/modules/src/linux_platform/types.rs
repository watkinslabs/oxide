use crate::linux_device::types::{LinuxDevice, LinuxDeviceDriver};
use core::ffi::{c_char, c_void};

pub(super) type PlatformProbe = unsafe extern "C" fn(*mut PlatformDevice) -> i32;
pub(super) type PlatformRemove = unsafe extern "C" fn(*mut PlatformDevice) -> i32;
pub(super) type PlatformShutdown = unsafe extern "C" fn(*mut PlatformDevice);

pub(super) const PLATFORM_NAME_SIZE: usize = 20;
pub(super) const ACPI_ID_LEN: usize = 9;
pub(super) const LINUX_OK: i32 = 0;
pub(super) const LINUX_ENOENT: i32 = 2;
pub(super) const LINUX_EINVAL: i32 = 22;
pub(super) const LINUX_EBUSY: i32 = 16;
pub(super) const IORESOURCE_TYPE_BITS: u64 = 0x0000_1f00;
pub(super) const IORESOURCE_MEM: u64 = 0x0000_0200;
pub(super) const IORESOURCE_IRQ: u64 = 0x0000_0400;
pub(super) const PLATFORM_DEVICE_REGISTERED: u32 = 1;

#[repr(C)]
#[derive(Copy, Clone)]
pub(super) struct LinuxResource {
    pub(super) start: u64,
    pub(super) end: u64,
    pub(super) name: *const c_char,
    pub(super) flags: u64,
    pub(super) desc: u64,
    pub(super) parent: *mut LinuxResource,
    pub(super) sibling: *mut LinuxResource,
    pub(super) child: *mut LinuxResource,
}

#[repr(C)]
pub(super) struct PlatformDeviceId {
    pub(super) name: [c_char; PLATFORM_NAME_SIZE],
    pub(super) driver_data: usize,
}

#[repr(C)]
pub(super) struct AcpiDeviceId {
    pub(super) id: [u8; ACPI_ID_LEN],
    pub(super) driver_data: usize,
}

#[repr(C)]
pub(super) struct OfDeviceId {
    pub(super) name: *const c_char,
    pub(super) ty: *const c_char,
    pub(super) compatible: *const c_char,
    pub(super) data: *const c_void,
}

#[repr(C)]
pub(super) struct AcpiDevice {
    pub(super) hid: [c_char; ACPI_ID_LEN],
    pub(super) uid: [c_char; ACPI_ID_LEN],
    pub(super) driver_data: *mut c_void,
}

#[repr(C)]
pub(super) struct DeviceNode {
    pub(super) name: *const c_char,
    pub(super) ty: *const c_char,
    pub(super) compatible: *const c_char,
    pub(super) data: *mut c_void,
}

#[repr(C)]
pub(super) struct PlatformDevice {
    pub(super) name: *const c_char,
    pub(super) id: i32,
    pub(super) dev: LinuxDevice,
    pub(super) num_resources: u32,
    pub(super) resource: *mut LinuxResource,
    pub(super) driver_data: *mut c_void,
    pub(super) driver: *mut PlatformDriver,
    pub(super) id_entry: *const PlatformDeviceId,
    pub(super) registered: u32,
}

#[repr(C)]
pub(super) struct PlatformDriver {
    pub(super) probe: Option<PlatformProbe>,
    pub(super) remove: Option<PlatformRemove>,
    pub(super) shutdown: Option<PlatformShutdown>,
    pub(super) driver: LinuxDeviceDriver,
    pub(super) id_table: *const PlatformDeviceId,
}
