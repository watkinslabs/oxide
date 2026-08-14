use super::types::*;
use core::ffi::c_void;
use core::ptr::null_mut;

type BusyIterFn = unsafe extern "C" fn(*mut LinuxRequest, *mut c_void) -> bool;
const LINUX_ENOIOCTLCMD: i32 = 515;

static FS_BIO_SET: usize = 0;

/// Register low-frequency Linux block KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("bdev_start_io_acct",       bdev_start_io_acct       as *const () as usize),
        ("bdev_end_io_acct",         bdev_end_io_acct         as *const () as usize),
        ("bio_start_io_acct",        bio_start_io_acct        as *const () as usize),
        ("bio_end_io_acct_remapped", bio_end_io_acct_remapped as *const () as usize),
        ("blk_mq_num_possible_queues", blk_mq_num_possible_queues as *const () as usize),
        ("blk_mq_tagset_busy_iter",  blk_mq_tagset_busy_iter  as *const () as usize),
        ("blk_mq_unfreeze_queue_non_owner", blk_mq_unfreeze_queue_non_owner as *const () as usize),
        ("blkdev_compat_ptr_ioctl", blkdev_compat_ptr_ioctl as *const () as usize),
        ("__blk_rq_map_sg",          __blk_rq_map_sg          as *const () as usize),
        ("blk_rq_integrity_map_user", blk_rq_integrity_map_user as *const () as usize),
        ("blk_rq_is_poll",           blk_rq_is_poll           as *const () as usize),
        ("blk_rq_map_integrity_sg",  blk_rq_map_integrity_sg  as *const () as usize),
        ("blk_rq_map_kern",          blk_rq_map_kern          as *const () as usize),
        ("blk_rq_map_user_io",       blk_rq_map_user_io       as *const () as usize),
        ("blk_rq_map_user_iov",      blk_rq_map_user_iov      as *const () as usize),
        ("blk_rq_poll",              blk_rq_poll              as *const () as usize),
        ("blk_rq_unmap_user",        blk_rq_unmap_user        as *const () as usize),
        ("blk_steal_bios",           blk_steal_bios           as *const () as usize),
        ("blk_zone_cond_str",        blk_zone_cond_str        as *const () as usize),
    ] { export(name, addr, false); }
    export("disk_report_zone", disk_report_zone as *const () as usize, true);
    export("fs_bio_set", &FS_BIO_SET as *const usize as usize, false);
}

unsafe extern "C" fn bdev_start_io_acct(_bdev: *mut LinuxBlockDevice, _sectors: u64, _op: u32, _start: u64) -> u64 { 0 }
unsafe extern "C" fn bdev_end_io_acct(_bdev: *mut LinuxBlockDevice, _op: u32, _start: u64) {}
unsafe extern "C" fn bio_start_io_acct(_bio: *mut LinuxBio) -> u64 { 0 }
unsafe extern "C" fn bio_end_io_acct_remapped(_bio: *mut LinuxBio, _start: u64, _dev: *mut c_void) {}

/// Bound hardware queues by the CPUs available to the scheduler.
/// # C: O(1)
extern "C" fn blk_mq_num_possible_queues(max_queues: u32) -> u32 {
    let possible = cpu::enabled_count()
        .max(cpu::smp::online_count())
        .clamp(1, cpu::MAX_CPUS as u32);
    if max_queues == 0 { possible } else { possible.min(max_queues) }
}

unsafe extern "C" fn blk_mq_tagset_busy_iter(_set: *mut LinuxBlkMqTagSet, _f: Option<BusyIterFn>, _priv: *mut c_void) {}

unsafe extern "C" fn blk_mq_unfreeze_queue_non_owner(q: *mut LinuxRequestQueue) {
    if q.is_null() { return; }
    // SAFETY: q points to a live request queue supplied by the caller.
    unsafe { (*q).mq_freeze_depth = (*q).mq_freeze_depth.saturating_sub(1); }
}

unsafe extern "C" fn blkdev_compat_ptr_ioctl(bdev: *mut LinuxBlockDevice, mode: u32, cmd: u32, arg: usize) -> i32 {
    if bdev.is_null() { return -LINUX_ENOIOCTLCMD; }
    // SAFETY: bdev is non-null and its disk/fops pointers are the block-device ownership chain established by the driver.
    unsafe {
        let disk = (*bdev).bd_disk;
        if disk.is_null() || (*disk).fops.is_null() { return -LINUX_ENOIOCTLCMD; }
        let Some(ioctl) = (*(*disk).fops).ioctl else { return -LINUX_ENOIOCTLCMD; };
        ioctl(bdev, mode, cmd, arg as u32 as usize)
    }
}

unsafe extern "C" fn __blk_rq_map_sg(rq: *mut LinuxRequest, sg: *mut c_void, last: *mut *mut c_void) -> i32 {
    if rq.is_null() || sg.is_null() { return 0; }
    if !last.is_null() {
        // SAFETY: last is an optional caller-provided out pointer.
        unsafe { *last = sg; }
    }
    1
}

unsafe extern "C" fn blk_rq_integrity_map_user(_rq: *mut LinuxRequest, _ubuf: *mut c_void, _len: u32) -> i32 { -LINUX_EINVAL }
unsafe extern "C" fn blk_rq_is_poll(_rq: *mut LinuxRequest) -> bool { false }
unsafe extern "C" fn blk_rq_map_integrity_sg(_q: *mut LinuxRequestQueue, _rq: *mut LinuxRequest, _sg: *mut c_void) -> i32 { 0 }
unsafe extern "C" fn blk_rq_map_kern(_q: *mut LinuxRequestQueue, _rq: *mut LinuxRequest, _kbuf: *mut c_void, _len: u32, _gfp: u32) -> i32 { -LINUX_EINVAL }
unsafe extern "C" fn blk_rq_map_user_io(_rq: *mut LinuxRequest, _map: *mut c_void, _iter: *mut c_void, _gfp: u32, _copy: bool) -> i32 { -LINUX_EINVAL }
unsafe extern "C" fn blk_rq_map_user_iov(_q: *mut LinuxRequestQueue, _rq: *mut LinuxRequest, _map: *mut c_void, _iter: *mut c_void, _gfp: u32) -> i32 { -LINUX_EINVAL }
unsafe extern "C" fn blk_rq_poll(_rq: *mut LinuxRequest, _iob: *mut c_void, _flags: u32) -> i32 { 0 }
unsafe extern "C" fn blk_rq_unmap_user(_bio: *mut LinuxBio) {}

unsafe extern "C" fn blk_steal_bios(rq: *mut LinuxRequest) -> *mut LinuxBio {
    if rq.is_null() { return null_mut(); }
    // SAFETY: rq points to a live request; ownership is transferred to caller.
    unsafe {
        let bio = (*rq).bio;
        (*rq).bio = null_mut();
        (*rq).biotail = null_mut();
        bio
    }
}

extern "C" fn blk_zone_cond_str(_cond: u8) -> *const u8 {
    b"not-wp\0".as_ptr()
}

/// Report a single zone, normalising an uncached active report before calling its consumer.
/// # C: O(1) plus callback
unsafe extern "C" fn disk_report_zone(disk: *mut LinuxGendisk, zone: *mut LinuxBlkZone, idx: u32,
    args: *mut LinuxBlkReportZonesArgs) -> i32 {
    // SAFETY: disk and zone have the live driver-report lifetime required by this KPI.
    unsafe { crate::linux_block::core::sync_reported_zone(disk, zone); }
    if !args.is_null() {
        // SAFETY: the driver's report_zones operation receives this live core-owned argument record;
        // its zone descriptor is live for the call by the disk_report_zone KPI contract.
        unsafe {
            if (*args).report_active {
                match (*zone).cond {
                    BLK_ZONE_COND_IMP_OPEN | BLK_ZONE_COND_EXP_OPEN | BLK_ZONE_COND_CLOSED => (*zone).cond = BLK_ZONE_COND_ACTIVE,
                    _ => {}
                }
            }
            if let Some(cb) = (*args).cb { return cb(zone, idx, (*args).data); }
        }
    }
    LINUX_OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

    static COMPAT_MODE: AtomicU32 = AtomicU32::new(0);
    static COMPAT_CMD: AtomicU32 = AtomicU32::new(0);
    static COMPAT_ARG: AtomicUsize = AtomicUsize::new(0);
    static REPORT_IDX: AtomicU32 = AtomicU32::new(0);
    static REPORT_DATA: AtomicUsize = AtomicUsize::new(0);
    static REPORT_COND: AtomicU32 = AtomicU32::new(0);

    unsafe extern "C" fn report_zone_cb(zone: *mut LinuxBlkZone, idx: u32, data: *mut c_void) -> i32 {
        // SAFETY: disk_report_zone gives the callback the live zone descriptor supplied by this test.
        unsafe { REPORT_COND.store((*zone).cond as u32, Ordering::SeqCst); }
        REPORT_IDX.store(idx, Ordering::SeqCst); REPORT_DATA.store(data as usize, Ordering::SeqCst); 71
    }

    unsafe extern "C" fn compat_ioctl(_bdev: *mut LinuxBlockDevice, mode: u32, cmd: u32, arg: usize) -> i32 {
        COMPAT_MODE.store(mode, Ordering::SeqCst); COMPAT_CMD.store(cmd, Ordering::SeqCst); COMPAT_ARG.store(arg, Ordering::SeqCst); 37
    }

    #[test]
    fn possible_queue_count_honors_the_driver_cap() {
        let available = cpu::enabled_count()
            .max(cpu::smp::online_count())
            .clamp(1, cpu::MAX_CPUS as u32);
        assert_eq!(blk_mq_num_possible_queues(0), available);
        assert_eq!(blk_mq_num_possible_queues(1), 1);
        assert_eq!(blk_mq_num_possible_queues(u32::MAX), available);
    }

    #[test]
    fn compat_ioctl_zero_extends_the_32_bit_argument_and_forwards_mode() {
        let _modules = crate::test_serial::claim();
        let ops = LinuxBlockDeviceOperations { owner: core::ptr::null_mut(), open: None, release: None, ioctl: Some(compat_ioctl) };
        let mut disk = unsafe { core::mem::zeroed::<LinuxGendisk>() }; disk.fops = &ops;
        let mut bdev = LinuxBlockDevice::new();
        bdev.bd_disk = &mut disk;
        assert_eq!(unsafe { blkdev_compat_ptr_ioctl(&mut bdev, 0x12, 0x34, usize::MAX) }, 37);
        assert_eq!(COMPAT_MODE.load(Ordering::SeqCst), 0x12); assert_eq!(COMPAT_CMD.load(Ordering::SeqCst), 0x34); assert_eq!(COMPAT_ARG.load(Ordering::SeqCst), u32::MAX as usize);
    }

    #[test]
    fn compat_ioctl_without_driver_callback_reports_linux_no_ioctl() {
        let _modules = crate::test_serial::claim();
        let mut bdev = LinuxBlockDevice::new();
        assert_eq!(unsafe { blkdev_compat_ptr_ioctl(&mut bdev, 0, 0, 0) }, -LINUX_ENOIOCTLCMD);
    }

    #[test]
    fn disk_report_zone_normalizes_active_reports_before_the_callback() {
        let mut zone = LinuxBlkZone { start: 0, len: 0, wp: 0, zone_type: 0, cond: BLK_ZONE_COND_EXP_OPEN,
            non_seq: 0, reset: 0, resv: [0; 4], capacity: 0, reserved: [0; 24] };
        let data = 0x1234usize as *mut c_void;
        let mut args = LinuxBlkReportZonesArgs { cb: Some(report_zone_cb), data, report_active: true };
        // SAFETY: zone and args are live ABI records throughout this direct helper call.
        assert_eq!(unsafe { disk_report_zone(null_mut(), &mut zone, 9, &mut args) }, 71);
        assert_eq!(zone.cond, BLK_ZONE_COND_ACTIVE);
        assert_eq!(REPORT_COND.load(Ordering::SeqCst), BLK_ZONE_COND_ACTIVE as u32);
        assert_eq!(REPORT_IDX.load(Ordering::SeqCst), 9);
        assert_eq!(REPORT_DATA.load(Ordering::SeqCst), data as usize);
    }

    #[test]
    fn disk_report_zone_preserves_regular_condition_and_returns_zero_without_a_callback() {
        let mut zone = LinuxBlkZone { start: 0, len: 0, wp: 0, zone_type: 0, cond: BLK_ZONE_COND_CLOSED,
            non_seq: 0, reset: 0, resv: [0; 4], capacity: 0, reserved: [0; 24] };
        let mut args = LinuxBlkReportZonesArgs { cb: None, data: null_mut(), report_active: false };
        // SAFETY: zone and args are live ABI records throughout this direct helper call.
        assert_eq!(unsafe { disk_report_zone(null_mut(), &mut zone, 0, &mut args) }, LINUX_OK);
        assert_eq!(zone.cond, BLK_ZONE_COND_CLOSED);
        // SAFETY: a null args pointer is an explicitly supported no-callback report form.
        assert_eq!(unsafe { disk_report_zone(null_mut(), &mut zone, 0, null_mut()) }, LINUX_OK);
    }

    #[test]
    fn disk_report_zone_active_normalization_leaves_other_conditions_unchanged() {
        for cond in [0, 1, 0xd, 0xe, 0xf, BLK_ZONE_COND_ACTIVE] {
            let mut zone = LinuxBlkZone { start: 0, len: 0, wp: 0, zone_type: 0, cond,
                non_seq: 0, reset: 0, resv: [0; 4], capacity: 0, reserved: [0; 24] };
            let mut args = LinuxBlkReportZonesArgs { cb: None, data: null_mut(), report_active: true };
            // SAFETY: zone and args are live ABI records throughout this direct helper call.
            assert_eq!(unsafe { disk_report_zone(null_mut(), &mut zone, 0, &mut args) }, LINUX_OK);
            assert_eq!(zone.cond, cond);
        }
    }

    #[test]
    fn disk_report_zone_synchronizes_a_pending_write_plug_without_a_callback() {
        let mut disk: LinuxGendisk = unsafe { core::mem::zeroed() };
        disk.zoned.nr_zones = 1; disk.zoned.zone_capacity = 100; disk.zoned.last_zone_capacity = 100;
        // SAFETY: this test owns the gendisk and installs its only canonical plug before reporting.
        unsafe { crate::linux_block::core::install_test_wplug(&mut disk, 0); }
        let mut zone = LinuxBlkZone { start: 0, len: 100, wp: 33, zone_type: 0, cond: BLK_ZONE_COND_IMP_OPEN,
            non_seq: 0, reset: 0, resv: [0; 4], capacity: 100, reserved: [0; 24] };
        // SAFETY: disk, the installed plug, and zone are live for this no-callback report.
        assert_eq!(unsafe { disk_report_zone(&mut disk, &mut zone, 0, null_mut()) }, LINUX_OK);
        // SAFETY: exactly one test plug is still owned by the gendisk.
        assert_eq!(unsafe { crate::linux_block::core::test_wplug(&mut disk) }, (33, BLK_ZONE_COND_ACTIVE, 0));
        // SAFETY: the test plug has no users after the report returned.
        unsafe { crate::linux_block::core::drop_test_wplug(&mut disk); }
    }
}
