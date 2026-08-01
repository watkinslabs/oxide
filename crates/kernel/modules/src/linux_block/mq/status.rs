extern crate alloc;
use crate::linux_block::core;
use crate::linux_block::types::*;
use ::core::ffi::c_void;

const BLK_STS_NOTSUPP: u8 = 9;
const BLK_STS_TARGET: u8 = 11;
const IOERRNO: i32 = 5;
const AGAINERRNO: i32 = 11;
const NOMEMERRNO: i32 = 12;
const OPNOTSUPPERRNO: i32 = 95;
const OP_MASK: u32 = 0xff;

/// Register the blk_status_t mapping and gendisk notification symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("blk_op_str",                blk_op_str                as *const () as usize),
        ("blk_status_to_errno",       blk_status_to_errno       as *const () as usize),
        ("errno_to_blk_status",       errno_to_blk_status       as *const () as usize),
        ("bdev_disk_changed",         bdev_disk_changed         as *const () as usize),
        ("device_add_disk",           device_add_disk           as *const () as usize),
        ("blk_mark_disk_dead",        blk_mark_disk_dead        as *const () as usize),
        ("blk_revalidate_disk_zones", blk_revalidate_disk_zones as *const () as usize),
    ] { export(name, addr, false); }
}

extern "C" fn blk_op_str(op: u32) -> *const u8 {
    match op & OP_MASK {
        REQ_OP_READ => b"READ\0".as_ptr(),
        REQ_OP_WRITE => b"WRITE\0".as_ptr(),
        REQ_OP_FLUSH => b"FLUSH\0".as_ptr(),
        REQ_OP_DISCARD => b"DISCARD\0".as_ptr(),
        _ => b"UNKNOWN\0".as_ptr(),
    }
}

extern "C" fn blk_status_to_errno(status: u8) -> i32 {
    match status {
        BLK_STS_OK => 0,
        BLK_STS_RESOURCE => -NOMEMERRNO,
        BLK_STS_AGAIN => -AGAINERRNO,
        BLK_STS_NOTSUPP => -OPNOTSUPPERRNO,
        BLK_STS_TARGET => -LINUX_EIO,
        _ => -IOERRNO,
    }
}

extern "C" fn errno_to_blk_status(errno: i32) -> u8 {
    match errno {
        0 => BLK_STS_OK,
        e if e == -NOMEMERRNO || e == NOMEMERRNO => BLK_STS_RESOURCE,
        e if e == -AGAINERRNO || e == AGAINERRNO => BLK_STS_AGAIN,
        e if e == -OPNOTSUPPERRNO || e == OPNOTSUPPERRNO => BLK_STS_NOTSUPP,
        _ => BLK_STS_IOERR,
    }
}

unsafe extern "C" fn bdev_disk_changed(_disk: *mut LinuxGendisk, _invalidate: bool) -> i32 { LINUX_OK }

unsafe extern "C" fn device_add_disk(_parent: *mut c_void, disk: *mut LinuxGendisk, _groups: *const *const c_void) -> i32 {
    if disk.is_null() { return -LINUX_EINVAL; }
    // SAFETY: disk is a live gendisk; add_disk publishes it through the block registry.
    unsafe { core::add_disk(disk); }
    LINUX_OK
}

unsafe extern "C" fn blk_mark_disk_dead(disk: *mut LinuxGendisk) {
    // SAFETY: disk is the module's gendisk from alloc_disk*, which is mark_disk_dead's precondition; that
    // helper null-checks the pointer itself before touching the flags word.
    unsafe { core::mark_disk_dead(disk); }
}

unsafe extern "C" fn blk_revalidate_disk_zones(_disk: *mut LinuxGendisk, _report: *mut c_void) -> i32 { LINUX_OK }
