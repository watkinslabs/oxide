use crate::linux_device::types::{LinuxDevice, LinuxDeviceDriver};
use core::ffi::{c_char, c_void};

pub(super) type PciProbe = unsafe extern "C" fn(*mut LinuxPciDev, *const LinuxPciDeviceId) -> i32;
pub(super) type PciRemove = unsafe extern "C" fn(*mut LinuxPciDev);

pub(super) const PCI_STD_NUM_BARS: usize = 6;
pub(super) const PCI_CONFIG_DWORDS: usize = 64;
pub(super) const PCI_NAME_LEN: usize = 13;
pub(super) const PCI_IRQ_LEGACY: u32 = 1 << 0;
pub(super) const PCI_IRQ_MSI: u32 = 1 << 1;
pub(super) const PCI_IRQ_MSIX: u32 = 1 << 2;
pub(super) const PCI_D0: i32 = 0;
pub(super) const PCI_D3HOT: i32 = 3;
pub(super) const PCI_D3COLD: i32 = 4;
pub(super) const PCI_POWER_ERROR: i32 = -1;

pub(super) const LINUX_OK: i32 = 0;
pub(super) const LINUX_EINVAL: i32 = 22;
pub(super) const LINUX_ENODEV: i32 = 19;
pub(super) const LINUX_ENOMEM: i32 = 12;
pub(super) const LINUX_EBUSY: i32 = 16;
pub(super) const LINUX_ENOSPC: i32 = 28;

#[repr(C)]
#[derive(Copy, Clone)]
pub(super) struct LinuxResource {
    pub(super) start: u64,
    pub(super) end: u64,
    pub(super) name: *const c_char,
    pub(super) flags: u64,
}

#[repr(C)]
pub(super) struct LinuxPciDeviceId {
    pub(super) vendor: u32,
    pub(super) device: u32,
    pub(super) subvendor: u32,
    pub(super) subdevice: u32,
    pub(super) class: u32,
    pub(super) class_mask: u32,
    pub(super) driver_data: usize,
}

#[repr(C)]
pub(super) struct LinuxPciDev {
    pub(super) dev: LinuxDevice,
    pub(super) dma_mask: u64,
    pub(super) vendor: u16,
    pub(super) device: u16,
    pub(super) subsystem_vendor: u16,
    pub(super) subsystem_device: u16,
    pub(super) class: u32,
    pub(super) bus: u8,
    pub(super) devfn: u8,
    pub(super) irq: u32,
    pub(super) resource: [LinuxResource; PCI_STD_NUM_BARS],
    pub(super) driver_data: *mut c_void,
    pub(super) config_space: [u32; PCI_CONFIG_DWORDS],
    pub(super) irq_vector_base: u32,
    pub(super) irq_vectors: i32,
    pub(super) irq_vector_flags: u32,
    pub(super) name: [c_char; PCI_NAME_LEN],
    pub(super) saved_config_space: [u32; PCI_CONFIG_DWORDS],
    pub(super) current_state: i32,
    pub(super) wake_enabled: bool,
}

#[repr(C)]
pub(super) struct LinuxPciDriver {
    pub(super) name: *const c_char,
    pub(super) id_table: *const LinuxPciDeviceId,
    pub(super) probe: Option<PciProbe>,
    pub(super) remove: Option<PciRemove>,
    pub(super) driver: LinuxDeviceDriver,
}
