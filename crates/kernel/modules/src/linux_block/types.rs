use crate::linux_alloc::LinuxPage;
use crate::linux_device::types::{LinuxDevice, LinuxKobject};
use alloc::vec::Vec;
use core::ffi::{c_char, c_void};
use core::sync::atomic::AtomicU32;
use sync::{Modules as ModulesLockClass, Spinlock};

pub(super) type MakeRequestFn = unsafe extern "C" fn(*mut LinuxRequestQueue, *mut LinuxBio) -> i32;
pub(super) type RequestFn = unsafe extern "C" fn(*mut LinuxRequestQueue);
pub(super) type BioEndIoFn = unsafe extern "C" fn(*mut LinuxBio);
pub(super) type RqEndIoFn = unsafe extern "C" fn(*mut LinuxRequest, u8, *const LinuxIoCompBatch) -> i32;
pub(super) type IoCompCompleteFn = unsafe extern "C" fn(*mut LinuxIoCompBatch);
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
pub(super) const MAX_SEGMENTS: u16 = 128;
pub(super) const RQ_END_IO_NONE: i32 = 0;
pub(super) const RQ_END_IO_FREE: i32 = 1;
pub(super) const LINUX_OK: i32 = 0;
pub(super) const LINUX_EINVAL: i32 = 22;
pub(super) const LINUX_EIO: i32 = 5;

#[repr(C)]
pub(super) struct LinuxBlockDevice {
    pub(super) bd_start_sect: u64,
    pub(super) bd_nr_sectors: u64,
    pub(super) bd_disk: *mut LinuxGendisk,
    pub(super) bd_queue: *mut LinuxRequestQueue,
    pub(super) bd_stats: *mut c_void,
    pub(super) bd_stamp: u64,
    pub(super) bd_flags: u32,
    pub(super) bd_dev: u32,
    pub(super) bd_mapping: *mut c_void,
    pub(super) bd_openers: u32,
    pub(super) bd_size_lock: u32,
    pub(super) bd_claiming: *mut c_void,
    pub(super) bd_holder: *mut c_void,
    pub(super) bd_holder_ops: *mut c_void,
    pub(super) bd_holder_lock: [u8; 32],
    pub(super) bd_holders: *mut c_void,
    pub(super) bd_holder_dir: *mut c_void,
    pub(super) bd_fsfreeze_count: u32,
    pub(super) bd_fsfreeze_pad: u32,
    pub(super) bd_fsfreeze_mutex: [u8; 32],
    pub(super) bd_meta_info: *mut c_void,
    pub(super) bd_writers: *mut c_void,
    pub(super) bd_security: *mut c_void,
    pub(super) bd_device: LinuxDevice,
}

impl LinuxBlockDevice {
    pub(super) fn new() -> Self {
        Self {
            bd_start_sect: 0, bd_nr_sectors: 0, bd_disk: core::ptr::null_mut(),
            bd_queue: core::ptr::null_mut(), bd_stats: core::ptr::null_mut(), bd_stamp: 0,
            bd_flags: 0, bd_dev: 0, bd_mapping: core::ptr::null_mut(), bd_openers: 0,
            bd_size_lock: 0, bd_claiming: core::ptr::null_mut(), bd_holder: core::ptr::null_mut(),
            bd_holder_ops: core::ptr::null_mut(), bd_holder_lock: [0; 32],
            bd_holders: core::ptr::null_mut(), bd_holder_dir: core::ptr::null_mut(),
            bd_fsfreeze_count: 0, bd_fsfreeze_pad: 0, bd_fsfreeze_mutex: [0; 32],
            bd_meta_info: core::ptr::null_mut(), bd_writers: core::ptr::null_mut(),
            bd_security: core::ptr::null_mut(), bd_device: LinuxDevice::new(),
        }
    }
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
    pub(super) lifecycle: *mut LinuxQueueLifecycle,
}

pub(super) struct LinuxQueueLifecycle {
    pub(super) gate: Spinlock<(), ModulesLockClass>,
    pub(super) users: AtomicU32,
    #[cfg(target_os = "oxide-kernel")]
    pub(super) freeze_wait: sched::live::WaitList,
}

impl LinuxQueueLifecycle {
    pub(super) fn new() -> Self {
        Self {
            gate: Spinlock::new(()),
            users: AtomicU32::new(0),
            #[cfg(target_os = "oxide-kernel")]
            freeze_wait: sched::live::WaitList::new(),
        }
    }
}

#[repr(C)]
pub(super) struct LinuxBlockDeviceOperations {
    pub(super) owner: *mut c_void,
    pub(super) open: Option<unsafe extern "C" fn(*mut LinuxBlockDevice, u32) -> i32>,
    pub(super) release: Option<unsafe extern "C" fn(*mut LinuxGendisk, u32)>,
    pub(super) ioctl: Option<unsafe extern "C" fn(*mut LinuxBlockDevice, u32, u32, usize) -> i32>,
}

#[repr(C)]
pub(super) struct LinuxGendisk {
    pub(super) major: i32,
    pub(super) first_minor: i32,
    pub(super) minors: i32,
    pub(super) disk_name: [c_char; DISK_NAME_LEN],
    pub(super) events: u16,
    pub(super) event_flags: u16,
    /// Inline `struct xarray part_tbl` (16 bytes), as in Linux `struct gendisk`.
    pub(super) part_tbl: [u8; 16],
    pub(super) part0: *mut LinuxBlockDevice,
    pub(super) fops: *const LinuxBlockDeviceOperations,
    pub(super) queue: *mut LinuxRequestQueue,
    pub(super) private_data: *mut c_void,
    pub(super) bio_split: *mut c_void,
    pub(super) _pre_flags: [u8; 240],
    pub(super) flags: u32,
    pub(super) _state_pad: u32,
    pub(super) state: usize,
    pub(super) open_mutex: [u8; 32],
    pub(super) open_partitions: u32,
    pub(super) _bdi_pad: u32,
    pub(super) bdi: *mut c_void,
    pub(super) queue_kobj: LinuxKobject,
    pub(super) slave_dir: *mut c_void,
    pub(super) slave_bdevs: [u8; 16],
    pub(super) random: *mut c_void,
    pub(super) ev: *mut c_void,
    pub(super) _zoned: [u8; 72],
    pub(super) node_id: i32,
    pub(super) _node_pad: u32,
    pub(super) bb: *mut c_void,
    pub(super) diskseq: u64,
    pub(super) open_mode: u32,
    pub(super) _open_mode_pad: u32,
    pub(super) ia_ranges: *mut c_void,
    pub(super) rqos_state_mutex: [u8; 32],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub(super) struct LinuxBioVec {
    pub(super) bv_page: *mut LinuxPage,
    pub(super) bv_len: u32,
    pub(super) bv_offset: u32,
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
    pub(super) bi_io_vec: *mut LinuxBioVec,
    pub(super) bi_vcnt: u16,
    pub(super) bi_max_vecs: u16,
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
    pub(super) lifecycle: *mut LinuxTagSetLifecycle,
}

pub(super) struct LinuxTagSetLifecycle {
    pub(super) queues: Spinlock<Vec<usize>, ModulesLockClass>,
    pub(super) dispatches: AtomicU32,
    pub(super) completions: AtomicU32,
    #[cfg(target_os = "oxide-kernel")]
    pub(super) dispatch_wait: sched::live::WaitList,
    #[cfg(target_os = "oxide-kernel")]
    pub(super) completion_wait: sched::live::WaitList,
}

impl LinuxTagSetLifecycle {
    pub(super) fn new() -> Self {
        Self {
            queues: Spinlock::new(Vec::new()),
            dispatches: AtomicU32::new(0),
            completions: AtomicU32::new(0),
            #[cfg(target_os = "oxide-kernel")]
            dispatch_wait: sched::live::WaitList::new(),
            #[cfg(target_os = "oxide-kernel")]
            completion_wait: sched::live::WaitList::new(),
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub(super) struct LinuxBlkIntegrity {
    pub(super) flags: u8,
    pub(super) csum_type: u8,
    pub(super) metadata_size: u8,
    pub(super) pi_offset: u8,
    pub(super) interval_exp: u8,
    pub(super) tag_size: u8,
    pub(super) pi_tuple_size: u8,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub(super) struct LinuxQueueLimits {
    pub(super) features: u32,
    pub(super) flags: u32,
    pub(super) seg_boundary_mask: usize,
    pub(super) virt_boundary_mask: usize,
    pub(super) max_hw_sectors: u32,
    pub(super) max_dev_sectors: u32,
    pub(super) chunk_sectors: u32,
    pub(super) max_sectors: u32,
    pub(super) max_user_sectors: u32,
    pub(super) max_segment_size: u32,
    pub(super) max_fast_segment_size: u32,
    pub(super) physical_block_size: u32,
    pub(super) logical_block_size: u32,
    pub(super) alignment_offset: u32,
    pub(super) io_min: u32,
    pub(super) io_opt: u32,
    pub(super) max_discard_sectors: u32,
    pub(super) max_hw_discard_sectors: u32,
    pub(super) max_user_discard_sectors: u32,
    pub(super) max_secure_erase_sectors: u32,
    pub(super) max_write_zeroes_sectors: u32,
    pub(super) max_wzeroes_unmap_sectors: u32,
    pub(super) max_hw_wzeroes_unmap_sectors: u32,
    pub(super) max_user_wzeroes_unmap_sectors: u32,
    pub(super) max_hw_zone_append_sectors: u32,
    pub(super) max_zone_append_sectors: u32,
    pub(super) discard_granularity: u32,
    pub(super) discard_alignment: u32,
    pub(super) zone_write_granularity: u32,
    pub(super) atomic_write_hw_max: u32,
    pub(super) atomic_write_max_sectors: u32,
    pub(super) atomic_write_hw_boundary: u32,
    pub(super) atomic_write_boundary_sectors: u32,
    pub(super) atomic_write_hw_unit_min: u32,
    pub(super) atomic_write_unit_min: u32,
    pub(super) atomic_write_hw_unit_max: u32,
    pub(super) atomic_write_unit_max: u32,
    pub(super) max_segments: u16,
    pub(super) max_integrity_segments: u16,
    pub(super) max_discard_segments: u16,
    pub(super) max_write_streams: u16,
    pub(super) write_stream_granularity: u32,
    pub(super) max_open_zones: u32,
    pub(super) max_active_zones: u32,
    pub(super) dma_alignment: u32,
    pub(super) dma_pad_mask: u32,
    pub(super) integrity: LinuxBlkIntegrity,
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
pub(super) struct LinuxRqList {
    pub(super) head: *mut LinuxRequest,
    pub(super) tail: *mut LinuxRequest,
}

#[repr(C)]
pub(super) struct LinuxIoCompBatch {
    pub(super) req_list: LinuxRqList,
    pub(super) need_ts: bool,
    pub(super) complete: Option<IoCompCompleteFn>,
    pub(super) poll_ctx: *mut c_void,
}

#[repr(C)]
pub(super) struct LinuxRequest {
    pub(super) q: *mut LinuxRequestQueue,
    pub(super) mq_ctx: *mut c_void,
    pub(super) mq_hctx: *mut LinuxBlkMqHwCtx,
    pub(super) bio: *mut LinuxBio,
    pub(super) biotail: *mut LinuxBio,
    pub(super) cmd_flags: u32,
    pub(super) rq_flags: u32,
    pub(super) tag: i32,
    pub(super) internal_tag: i32,
    pub(super) timeout: u32,
    pub(super) data_len: u32,
    pub(super) sector: u64,
    pub(super) part: *mut LinuxBlockDevice,
    pub(super) state: u32,
    pub(super) status: u8,
    pub(super) end_io: Option<RqEndIoFn>,
    pub(super) end_io_data: *mut c_void,
    pub(super) rq_next: *mut LinuxRequest,
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::{offset_of, size_of};

    #[test]
    fn bio_layout_matches_the_module_header_contract() {
        assert_eq!(size_of::<LinuxBioVec>(), 16);
        assert_eq!(size_of::<LinuxBio>(), 80);
        assert_eq!(offset_of!(LinuxBio, bi_size), 40);
        assert_eq!(offset_of!(LinuxBio, bi_io_vec), 48);
        assert_eq!(offset_of!(LinuxBio, bi_vcnt), 56);
        assert_eq!(offset_of!(LinuxBio, bi_end_io), 64);
    }

    #[test]
    fn block_device_layout_matches_the_supported_module_abi() {
        assert_eq!(size_of::<LinuxBlockDevice>(), 984);
        assert_eq!(offset_of!(LinuxBlockDevice, bd_disk), 16);
        assert_eq!(offset_of!(LinuxBlockDevice, bd_queue), 24);
        assert_eq!(offset_of!(LinuxBlockDevice, bd_holders), 128);
        assert_eq!(offset_of!(LinuxBlockDevice, bd_fsfreeze_mutex), 152);
        assert_eq!(offset_of!(LinuxBlockDevice, bd_device), 208);
    }

    #[test]
    fn gendisk_layout_matches_the_supported_module_abi() {
        assert_eq!(size_of::<LinuxGendisk>(), 656);
        assert_eq!(offset_of!(LinuxGendisk, part0), 64);
        assert_eq!(offset_of!(LinuxGendisk, queue), 80);
        assert_eq!(offset_of!(LinuxGendisk, flags), 344);
        assert_eq!(offset_of!(LinuxGendisk, state), 352);
        assert_eq!(offset_of!(LinuxGendisk, queue_kobj), 408);
        assert_eq!(offset_of!(LinuxGendisk, diskseq), 600);
        assert_eq!(offset_of!(LinuxGendisk, rqos_state_mutex), 624);
    }

    #[test]
    fn request_and_batch_layouts_match_the_module_header_contract() {
        assert_eq!(size_of::<LinuxRequest>(), 112);
        assert_eq!(offset_of!(LinuxRequest, bio), 24);
        assert_eq!(offset_of!(LinuxRequest, cmd_flags), 40);
        assert_eq!(offset_of!(LinuxRequest, sector), 64);
        assert_eq!(offset_of!(LinuxRequest, end_io), 88);
        assert_eq!(offset_of!(LinuxRequest, rq_next), 104);
        assert_eq!(size_of::<LinuxIoCompBatch>(), 40);
        assert_eq!(offset_of!(LinuxIoCompBatch, complete), 24);
    }

    #[test]
    fn queue_limits_layout_matches_the_supported_module_abi() {
        assert_eq!(size_of::<LinuxBlkIntegrity>(), 7);
        assert_eq!(size_of::<LinuxQueueLimits>(), 192);
        assert_eq!(offset_of!(LinuxQueueLimits, logical_block_size), 56);
        assert_eq!(offset_of!(LinuxQueueLimits, max_segments), 156);
        assert_eq!(offset_of!(LinuxQueueLimits, integrity), 184);
    }
}
