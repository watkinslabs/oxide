use crate::linux_device::types::LinuxDevice;
use core::ffi::{c_char, c_void};

pub(super) type MakeRequestFn = unsafe extern "C" fn(*mut LinuxRequestQueue, *mut LinuxBio) -> i32;
pub(super) type RequestFn = unsafe extern "C" fn(*mut LinuxRequestQueue);
pub(super) type BioEndIoFn = unsafe extern "C" fn(*mut LinuxBio);
pub(super) type RqEndIoFn = unsafe extern "C" fn(*mut LinuxRequest, u8, *const c_void) -> i32;
pub(super) type QueueRqFn = unsafe extern "C" fn(*mut LinuxBlkMqHwCtx, *const LinuxBlkMqQueueData) -> u8;
pub(super) type CompleteFn = unsafe extern "C" fn(*mut LinuxRequest);
pub(super) type InitRequestFn = unsafe extern "C" fn(*mut LinuxBlkMqTagSet, *mut LinuxRequest, u32, u32) -> i32;
pub(super) type ExitRequestFn = unsafe extern "C" fn(*mut LinuxBlkMqTagSet, *mut LinuxRequest, u32);
pub(super) type CleanupRqFn = unsafe extern "C" fn(*mut LinuxRequest);
pub(super) type BusyFn = unsafe extern "C" fn(*mut LinuxRequestQueue) -> bool;
pub(super) type MapQueuesFn = unsafe extern "C" fn(*mut LinuxBlkMqTagSet);

pub(super) const DISK_NAME_LEN: usize = 32;
pub(super) const LINUX_SECTOR_SHIFT: u32 = 9;
pub(super) const LINUX_SECTOR_SIZE: u32 = 1 << LINUX_SECTOR_SHIFT;
pub(super) const DEFAULT_LOGICAL_BLOCK_SIZE: u32 = LINUX_SECTOR_SIZE;
pub(super) const REQ_OP_READ: u32 = 0;
pub(super) const REQ_OP_WRITE: u32 = 1;
pub(super) const REQ_OP_FLUSH: u32 = 2;
pub(super) const REQ_OP_DISCARD: u32 = 3;
pub(super) const BLK_STS_OK: u8 = 0;
pub(super) const BLK_STS_RESOURCE: u8 = 1;
pub(super) const BLK_STS_AGAIN: u8 = 2;
pub(super) const BLK_STS_IOERR: u8 = 10;
pub(super) const MAX_HW_SECTORS: u32 = 1024;
pub(super) const MAX_SEGMENTS: u32 = 128;
pub(super) const RQ_END_IO_NONE: i32 = 0;
pub(super) const RQ_END_IO_FREE: i32 = 1;
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
    pub(super) mq_ops: *const LinuxBlkMqOps,
    pub(super) tag_set: *mut LinuxBlkMqTagSet,
    pub(super) disk: *mut LinuxGendisk,
    pub(super) rq_timeout: u32,
    pub(super) nr_hw_queues: u32,
    pub(super) freeze_depth: u32,
    pub(super) quiesce_depth: u32,
    pub(super) limits: LinuxQueueLimits,
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
    pub(super) bi_end_io: Option<BioEndIoFn>,
    pub(super) owner: *mut c_void,
}

#[repr(C)]
pub(super) struct LinuxBlkMqTagSet {
    pub(super) ops: *const LinuxBlkMqOps,
    pub(super) nr_hw_queues: u32,
    pub(super) queue_depth: u32,
    pub(super) numa_node: i32,
    pub(super) cmd_size: u32,
    pub(super) flags: u32,
    pub(super) driver_data: *mut c_void,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub(super) struct LinuxQueueLimits {
    pub(super) logical_block_size: u32,
    pub(super) physical_block_size: u32,
    pub(super) io_min: u32,
    pub(super) io_opt: u32,
    pub(super) max_hw_sectors: u32,
    pub(super) max_segments: u32,
    pub(super) discard_granularity: u32,
    pub(super) discard_alignment: u32,
}

#[repr(C)]
pub(super) struct LinuxBlkMqOps {
    pub(super) queue_rq: Option<QueueRqFn>,
    pub(super) commit_rqs: Option<unsafe extern "C" fn(*mut LinuxBlkMqHwCtx)>,
    pub(super) queue_rqs: *mut c_void,
    pub(super) get_budget: Option<unsafe extern "C" fn(*mut LinuxRequestQueue) -> i32>,
    pub(super) put_budget: Option<unsafe extern "C" fn(*mut LinuxRequestQueue, i32)>,
    pub(super) set_rq_budget_token: Option<unsafe extern "C" fn(*mut LinuxRequest, i32)>,
    pub(super) get_rq_budget_token: Option<unsafe extern "C" fn(*mut LinuxRequest) -> i32>,
    pub(super) timeout: *mut c_void,
    pub(super) poll: *mut c_void,
    pub(super) complete: Option<CompleteFn>,
    pub(super) init_hctx: *mut c_void,
    pub(super) exit_hctx: *mut c_void,
    pub(super) init_request: Option<InitRequestFn>,
    pub(super) exit_request: Option<ExitRequestFn>,
    pub(super) cleanup_rq: Option<CleanupRqFn>,
    pub(super) busy: Option<BusyFn>,
    pub(super) map_queues: Option<MapQueuesFn>,
    pub(super) show_rq: *mut c_void,
}

#[repr(C)]
pub(super) struct LinuxBlkMqHwCtx {
    pub(super) queue: *mut LinuxRequestQueue,
    pub(super) driver_data: *mut c_void,
    pub(super) queue_num: u32,
    pub(super) nr_ctx: u32,
}

#[repr(C)]
pub(super) struct LinuxBlkMqQueueData {
    pub(super) rq: *mut LinuxRequest,
    pub(super) last: bool,
}

#[repr(C)]
pub(super) struct LinuxRequest {
    pub(super) q: *mut LinuxRequestQueue,
    pub(super) mq_ctx: *mut c_void,
    pub(super) mq_hctx: *mut LinuxBlkMqHwCtx,
    pub(super) cmd_flags: u32,
    pub(super) rq_flags: u32,
    pub(super) tag: i32,
    pub(super) internal_tag: i32,
    pub(super) timeout: u32,
    pub(super) data_len: u32,
    pub(super) sector: u64,
    pub(super) bio: *mut LinuxBio,
    pub(super) biotail: *mut LinuxBio,
    pub(super) part: *mut LinuxBlockDevice,
    pub(super) state: u32,
    pub(super) status: u8,
    pub(super) end_io: Option<RqEndIoFn>,
    pub(super) end_io_data: *mut c_void,
}
