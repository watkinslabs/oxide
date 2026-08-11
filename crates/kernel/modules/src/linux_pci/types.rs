use crate::linux_device::types::{LinuxDevice, LinuxDeviceDriver};
use core::ffi::{c_char, c_void};

pub(super) type PciProbe = unsafe extern "C" fn(*mut LinuxPciDev, *const LinuxPciDeviceId) -> i32;
pub(super) type PciRemove = unsafe extern "C" fn(*mut LinuxPciDev);
pub(super) type PciPm = unsafe extern "C" fn(*mut LinuxPciDev, i32) -> i32;
pub(super) type PciResume = unsafe extern "C" fn(*mut LinuxPciDev) -> i32;
pub(super) type PciShutdown = unsafe extern "C" fn(*mut LinuxPciDev);
pub(super) type PciSriovConfigure = unsafe extern "C" fn(*mut LinuxPciDev, i32) -> i32;
pub(super) type PciSriovGetMsix = unsafe extern "C" fn(*mut LinuxPciDev) -> u32;

pub(super) const PCI_STD_NUM_BARS: usize = 6;
pub(super) const PCI_DEVICE_COUNT_RESOURCE: usize = 17;
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
    pub(super) desc: u64,
    pub(super) parent: *mut LinuxResource,
    pub(super) sibling: *mut LinuxResource,
    pub(super) child: *mut LinuxResource,
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
    pub(super) bus_list: [*mut c_void; 2],
    pub(super) bus: *mut c_void,
    pub(super) subordinate: *mut c_void,
    pub(super) sysdata: *mut c_void,
    pub(super) procent: *mut c_void,
    pub(super) slot: *mut c_void,
    pub(super) devfn: u32,
    pub(super) vendor: u16,
    pub(super) device: u16,
    pub(super) subsystem_vendor: u16,
    pub(super) subsystem_device: u16,
    pub(super) class: u32,
    pub(super) revision: u8,
    pub(super) hdr_type: u8,
    pub(super) aer_cap: u16,
    pub(super) aer_info: *mut c_void,
    pub(super) rcec_ea: *mut c_void,
    pub(super) rcec: *mut LinuxPciDev,
    pub(super) devcap: u32,
    pub(super) rebar_cap: u16,
    pub(super) pcie_cap: u8,
    pub(super) msi_cap: u8,
    pub(super) msix_cap: u8,
    pub(super) pcie_mpss: u8,
    pub(super) rom_base_reg: u8,
    pub(super) pin: u8,
    pub(super) pcie_flags_reg: u16,
    pub(super) dma_alias_mask: *mut usize,
    pub(super) driver: *mut LinuxPciDriver,
    pub(super) dma_mask: u64,
    pub(super) dma_parms: [u8; 16],
    pub(super) current_state: i32,
    pub(super) pm_cap: u8,
    pub(super) _pm_flags: [u8; 3],
    pub(super) d3hot_delay: u32,
    pub(super) d3cold_delay: u32,
    pub(super) l1ss: u16,
    pub(super) _pad_link: [u8; 6],
    pub(super) link_state: *mut c_void,
    pub(super) _pcie_flags: u32,
    pub(super) error_state: i32,
    pub(super) dev: LinuxDevice,
    pub(super) cfg_size: i32,
    pub(super) irq: u32,
    pub(super) resource: [LinuxResource; PCI_DEVICE_COUNT_RESOURCE],
    pub(super) driver_exclusive_resource: LinuxResource,
    pub(super) _resource_flags: [u8; 6],
    pub(super) dev_flags: u16,
    pub(super) enable_cnt: i32,
    pub(super) pcie_cap_lock: u32,
    pub(super) saved_config_space: [u32; 16],
    pub(super) _tail: [u8; 520],
}

#[repr(C)]
pub(super) struct LinuxPciDriver {
    pub(super) name: *const c_char,
    pub(super) id_table: *const LinuxPciDeviceId,
    pub(super) probe: Option<PciProbe>,
    pub(super) remove: Option<PciRemove>,
    pub(super) suspend: Option<PciPm>,
    pub(super) resume: Option<PciResume>,
    pub(super) shutdown: Option<PciShutdown>,
    pub(super) sriov_configure: Option<PciSriovConfigure>,
    pub(super) sriov_set_msix_vec_count: Option<PciSriovConfigure>,
    pub(super) sriov_get_vf_total_msix: Option<PciSriovGetMsix>,
    pub(super) err_handler: *const c_void,
    pub(super) groups: *const c_void,
    pub(super) dev_groups: *const c_void,
    pub(super) driver: LinuxDeviceDriver,
    pub(super) dynids: [u8; 24],
    pub(super) driver_managed_dma: bool,
    pub(super) _pad0: [u8; 7],
}
