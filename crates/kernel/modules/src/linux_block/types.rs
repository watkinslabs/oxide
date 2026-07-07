use crate::linux_device::types::LinuxDevice;
use core::ffi::{c_char, c_void};

pub(super) type MakeRequestFn = unsafe extern "C" fn(*mut LinuxRequestQueue, *mut LinuxBio) -> i32;
pub(super) type RequestFn = unsafe extern "C" fn(*mut LinuxRequestQueue);

pub(super) const DISK_NAME_LEN: usize = 32;
pub(super) const LINUX_SECTOR_SHIFT: u32 = 9;
pub(super) const LINUX_SECTOR_SIZE: u32 = 1 << LINUX_SECTOR_SHIFT;
pub(super) const DEFAULT_LOGICAL_BLOCK_SIZE: u32 = LINUX_SECTOR_SIZE;
pub(super) const REQ_OP_READ: u32 = 0;
pub(super) const REQ_OP_WRITE: u32 = 1;
pub(super) const REQ_OP_FLUSH: u32 = 2;
pub(super) const REQ_OP_DISCARD: u32 = 3;
pub(super) const BLK_STS_OK: u8 = 0;
#[cfg(test)]
pub(super) const BLK_STS_IOERR: u8 = 10;
pub(super) const LINUX_OK: i32 = 0;
pub(super) const LINUX_EINVAL: i32 = 22;
pub(super) const LINUX_EIO: i32 = 5;

#[repr(C)]
pub(super) struct LinuxBlockDevice {
    pub(super) bd_disk: *mut LinuxGendisk,
    pub(super) bd_queue: *mut LinuxRequestQueue,
    pub(super) bd_private: *mut c_void,
}

#[repr(C)]
pub(super) struct LinuxRequestQueue {
    pub(super) make_request_fn: Option<MakeRequestFn>,
    pub(super) request_fn: Option<RequestFn>,
    pub(super) queuedata: *mut c_void,
    pub(super) logical_block_size: u32,
}

#[repr(C)]
pub(super) struct LinuxBlockDeviceOperations {
    pub(super) owner: *mut c_void,
    pub(super) open: Option<unsafe extern "C" fn(*mut LinuxBlockDevice, u32) -> i32>,
    pub(super) release: Option<unsafe extern "C" fn(*mut LinuxGendisk, u32)>,
    pub(super) ioctl: Option<unsafe extern "C" fn(*mut LinuxBlockDevice, u32, usize) -> i32>,
}

#[repr(C)]
pub(super) struct LinuxGendisk {
    pub(super) major: i32,
    pub(super) first_minor: i32,
    pub(super) minors: i32,
    pub(super) disk_name: [c_char; DISK_NAME_LEN],
    pub(super) fops: *const LinuxBlockDeviceOperations,
    pub(super) queue: *mut LinuxRequestQueue,
    pub(super) private_data: *mut c_void,
    pub(super) capacity: u64,
    pub(super) flags: u32,
    pub(super) dev: LinuxDevice,
    pub(super) registered: u32,
}

#[repr(C)]
pub(super) struct LinuxBio {
    pub(super) bi_disk: *mut LinuxGendisk,
    pub(super) bi_bdev: *mut LinuxBlockDevice,
    pub(super) bi_private: *mut c_void,
    pub(super) bi_sector: u64,
    pub(super) bi_opf: u32,
    pub(super) bi_status: u8,
    pub(super) bi_size: u32,
    pub(super) bi_data: *mut u8,
    pub(super) owner: *mut c_void,
}

#[repr(C)]
pub(super) struct LinuxBlkMqTagSet {
    pub(super) ops: *const c_void,
    pub(super) nr_hw_queues: u32,
    pub(super) queue_depth: u32,
    pub(super) numa_node: i32,
    pub(super) cmd_size: u32,
    pub(super) flags: u32,
    pub(super) driver_data: *mut c_void,
}
