use core::ffi::{c_char, c_void};
use crate::linux_pm::types::{LinuxDevPmInfo, LinuxDevPmOps};

pub(crate) type ReleaseFn = unsafe extern "C" fn(*mut LinuxDevice);
pub(super) type DevresAction = unsafe extern "C" fn(*mut c_void);
pub(super) type KobjectRelease = unsafe extern "C" fn(*mut LinuxKobject);

pub(crate) const DEVICE_NAME_LEN: usize = 64;
pub(super) const GFP_ZERO: u32 = 0x8000;
pub(super) const LINUX_OK: i32 = 0;
pub(super) const LINUX_EINVAL: i32 = 22;
pub(super) const LINUX_ENOMEM: i32 = 12;
pub(super) const LINUX_EBUSY: i32 = 16;

#[repr(C)]
pub struct LinuxDevice {
    pub(crate) kobj: LinuxKobject,
    pub(crate) parent: *mut LinuxDevice,
    pub(crate) p: *mut c_void,
    pub(crate) init_name: *const c_char,
    pub(crate) ty: *const c_void,
    pub(crate) bus: *mut LinuxBusType,
    pub(crate) driver: *mut LinuxDeviceDriver,
    pub(crate) platform_data: *mut c_void,
    pub(crate) driver_data: *mut c_void,
    pub(crate) driver_override_name: *const c_char,
    pub(crate) driver_override_lock: u32,
    pub(crate) _pad_override: u32,
    pub(crate) mutex: [u8; 32],
    pub(crate) links: [u8; 56],
    pub(crate) power: LinuxDevPmInfo,
    pub(crate) pm_domain: *mut c_void,
    pub(crate) em_pd: *mut c_void,
    pub(crate) pins: *mut c_void,
    pub(crate) msi: [u8; 16],
    pub(crate) dma_ops: *const c_void,
    pub(crate) dma_mask: *mut u64,
    pub(crate) coherent_dma_mask: u64,
    pub(crate) bus_dma_limit: u64,
    pub(crate) dma_range_map: *const c_void,
    pub(crate) dma_parms: *mut c_void,
    pub(crate) dma_pools: [*mut c_void; 2],
    pub(crate) cma_area: *mut c_void,
    pub(crate) dma_io_tlb_mem: *mut c_void,
    pub(crate) of_node: *mut c_void,
    pub(crate) fwnode: *mut c_void,
    pub(crate) numa_node: i32,
    pub(crate) devt: u32,
    pub(crate) id: u32,
    pub(crate) devres_lock: u32,
    pub(crate) devres_head: [*mut c_void; 2],
    pub(crate) class: *mut LinuxClass,
    pub(crate) groups: *const c_void,
    pub(crate) release: Option<ReleaseFn>,
    pub(crate) iommu_group: *mut c_void,
    pub(crate) iommu: *mut c_void,
    pub(crate) physical_location: *mut c_void,
    pub(crate) removable: i32,
    pub(crate) flags: u32,
}

impl LinuxDevice {
    /// # C: O(1)
    pub(crate) const fn new() -> Self {
        Self {
            kobj: LinuxKobject::new(), parent: core::ptr::null_mut(), p: core::ptr::null_mut(),
            init_name: core::ptr::null(), ty: core::ptr::null(), bus: core::ptr::null_mut(),
            driver: core::ptr::null_mut(), platform_data: core::ptr::null_mut(), driver_data: core::ptr::null_mut(),
            driver_override_name: core::ptr::null(), driver_override_lock: 0, _pad_override: 0,
            mutex: [0; 32], links: [0; 56], power: LinuxDevPmInfo::new(), pm_domain: core::ptr::null_mut(),
            em_pd: core::ptr::null_mut(), pins: core::ptr::null_mut(), msi: [0; 16], dma_ops: core::ptr::null(),
            dma_mask: core::ptr::null_mut(), coherent_dma_mask: 0, bus_dma_limit: 0, dma_range_map: core::ptr::null(),
            dma_parms: core::ptr::null_mut(), dma_pools: [core::ptr::null_mut(); 2], cma_area: core::ptr::null_mut(),
            dma_io_tlb_mem: core::ptr::null_mut(), of_node: core::ptr::null_mut(), fwnode: core::ptr::null_mut(),
            numa_node: 0, devt: 0, id: 0, devres_lock: 0, devres_head: [core::ptr::null_mut(); 2],
            class: core::ptr::null_mut(), groups: core::ptr::null(), release: None, iommu_group: core::ptr::null_mut(),
            iommu: core::ptr::null_mut(), physical_location: core::ptr::null_mut(), removable: 0, flags: 0,
        }
    }
}

#[repr(C)]
pub struct LinuxKobject {
    pub(crate) name: *const c_char,
    pub(crate) entry: [*mut c_void; 2],
    pub(crate) parent: *mut LinuxKobject,
    pub(crate) kset: *mut LinuxKset,
    pub(crate) ktype: *const LinuxKobjType,
    pub(crate) sd: *mut c_void,
    pub(crate) kref: u32,
    pub(crate) state: u32,
}

impl LinuxKobject {
    pub(crate) const fn new() -> Self {
        Self {
            name: core::ptr::null(), entry: [core::ptr::null_mut(); 2], parent: core::ptr::null_mut(),
            kset: core::ptr::null_mut(), ktype: core::ptr::null(), sd: core::ptr::null_mut(), kref: 0,
            state: 0,
        }
    }
}

#[repr(C)]
pub struct LinuxKobjType {
    pub(crate) release: Option<KobjectRelease>,
}

#[repr(C)]
pub struct LinuxKset {
    pub(crate) kobj: LinuxKobject,
}

#[repr(C)]
pub struct LinuxDeviceDriver {
    pub(crate) name: *const c_char,
    pub(crate) bus: *mut LinuxBusType,
    pub(crate) owner: *mut c_void,
    pub(crate) mod_name: *const c_char,
    pub(crate) suppress_bind_attrs: bool,
    pub(crate) _pad0: [u8; 3],
    pub(crate) probe_type: i32,
    pub(crate) of_match_table: *const c_void,
    pub(crate) acpi_match_table: *const c_void,
    pub(crate) probe: Option<unsafe extern "C" fn(*mut LinuxDevice) -> i32>,
    pub(crate) sync_state: Option<unsafe extern "C" fn(*mut LinuxDevice)>,
    pub(crate) remove: Option<unsafe extern "C" fn(*mut LinuxDevice) -> i32>,
    pub(crate) shutdown: Option<unsafe extern "C" fn(*mut LinuxDevice)>,
    pub(crate) suspend: Option<unsafe extern "C" fn(*mut LinuxDevice, i32) -> i32>,
    pub(crate) resume: Option<unsafe extern "C" fn(*mut LinuxDevice) -> i32>,
    pub(crate) groups: *const c_void,
    pub(crate) dev_groups: *const c_void,
    pub(crate) pm: *const LinuxDevPmOps,
    pub(crate) coredump: Option<unsafe extern "C" fn(*mut LinuxDevice)>,
    pub(crate) private: *mut c_void,
    pub(crate) post_unbind_rust: Option<unsafe extern "C" fn(*mut LinuxDevice)>,
}

impl LinuxDeviceDriver {
    /// # C: O(1)
    pub(crate) const fn new() -> Self {
        Self {
            name: core::ptr::null(), bus: core::ptr::null_mut(), owner: core::ptr::null_mut(),
            mod_name: core::ptr::null(), suppress_bind_attrs: false, _pad0: [0; 3], probe_type: 0,
            of_match_table: core::ptr::null(), acpi_match_table: core::ptr::null(), probe: None,
            sync_state: None, remove: None, shutdown: None, suspend: None, resume: None,
            groups: core::ptr::null(), dev_groups: core::ptr::null(), pm: core::ptr::null(),
            coredump: None, private: core::ptr::null_mut(), post_unbind_rust: None,
        }
    }
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
