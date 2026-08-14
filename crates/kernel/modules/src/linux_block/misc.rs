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

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

    static COMPAT_MODE: AtomicU32 = AtomicU32::new(0);
    static COMPAT_CMD: AtomicU32 = AtomicU32::new(0);
    static COMPAT_ARG: AtomicUsize = AtomicUsize::new(0);

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
}
