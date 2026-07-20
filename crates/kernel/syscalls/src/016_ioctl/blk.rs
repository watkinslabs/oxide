#![cfg(any(target_os = "oxide-kernel", test))]

//! Block-device ioctls (Linux `block/ioctl.c blkdev_ioctl`). blkid, mkfs,
//! udev and systemd-fsck all probe `/dev/vda` with these right after opening
//! it; a block node is NOT a CharDev, so without this they'd fall through the
//! ioctl shim to `ENOTTY`. The disk geometry and discard operations come from
//! the block registry via the node's `dev_t` (`block::devbridge`).

use syscall::errno::Errno;
use vfs::{File, Fmode, InodeRef};

use crate::userbuf::{validate_user_buf_readable, validate_user_buf_writable};

/// Sectors are 512 bytes in the `BLKGETSIZE` ABI regardless of logical block
/// size (Linux reports `bdev_nr_sectors`, always 512-B units).
const ABI_SECTOR: u64 = 512;

/// Answer a block-device ioctl. `Some(rv)` when `req` is one we own,
/// `None` to let the caller continue (e.g. FIONBIO or the ENOTTY fallback).
/// `EINVAL` when the node's `dev_t` has no registered disk. # C: O(N_disks)
pub(super) fn handle_blk_ioctl(file: &File, req: u64, arg: u64) -> Option<i64> {
    let inode = file.inode();
    match req {
        super::uapi::BLKGETSIZE64 => {
            let devt = vfs::device_inode_devt(&inode)?;
            match block::devbridge::size_bytes(devt.raw()) {
                Some(bytes) => Some(write_u64(arg, bytes)),
                None => Some(-errno(Errno::Einval)),
            }
        }
        super::uapi::BLKGETSIZE => {
            let devt = vfs::device_inode_devt(&inode)?;
            match block::devbridge::size_bytes(devt.raw()) {
                // `unsigned long` is 8 bytes on both x86_64 and aarch64.
                Some(bytes) => Some(write_u64(arg, bytes / ABI_SECTOR)),
                None => Some(-errno(Errno::Einval)),
            }
        }
        super::uapi::BLKSSZGET | super::uapi::BLKBSZGET => {
            let devt = vfs::device_inode_devt(&inode)?;
            match block::devbridge::sector_size(devt.raw()) {
                Some(ss) => Some(write_u32(arg, ss)),
                None => Some(-errno(Errno::Einval)),
            }
        }
        super::uapi::BLKROGET => Some(write_u32(arg, 0)),
        super::uapi::BLKDISCARD => Some(ioctl_discard(&inode, file, arg)),
        super::uapi::BLKSECDISCARD => Some(ioctl_secure_erase(file)),
        super::uapi::BLKZEROOUT => Some(ioctl_zeroout(&inode, file, arg)),
        super::uapi::BLKDISCARDZEROES => Some(write_u32(arg, 0)),
        _ => None,
    }
}

fn ioctl_discard(inode: &InodeRef, file: &File, arg: u64) -> i64 {
    let (start, len) = match read_range(arg) {
        Ok(r) => r,
        Err(rv) => return rv,
    };
    let devt = match vfs::device_inode_devt(inode) {
        Some(d) => d,
        None => return -errno(Errno::Einval),
    };
    if block::devbridge::size_bytes(devt.raw()).is_none() { return -errno(Errno::Einval); }
    if !file.f_mode().contains(Fmode::WRITE) { return -errno(Errno::Ebadf); }
    let err = validate_discard_range(devt.raw(), start, len);
    if err != 0 { return err; }
    match block::devbridge::discard_range(devt.raw(), start, len) {
        Some(Ok(())) => 0,
        Some(Err(e)) => -block_errno(e),
        None => -errno(Errno::Einval),
    }
}

fn ioctl_secure_erase(file: &File) -> i64 {
    if !file.f_mode().contains(Fmode::WRITE) { return -errno(Errno::Ebadf); }
    -errno(Errno::Eopnotsupp)
}

fn ioctl_zeroout(inode: &InodeRef, file: &File, arg: u64) -> i64 {
    if !file.f_mode().contains(Fmode::WRITE) { return -errno(Errno::Ebadf); }
    let (start, len) = match read_range(arg) {
        Ok(r) => r,
        Err(rv) => return rv,
    };
    let devt = match vfs::device_inode_devt(inode) {
        Some(d) => d,
        None => return -errno(Errno::Einval),
    };
    let cap = match block::devbridge::size_bytes(devt.raw()) {
        Some(v) => v,
        None => return -errno(Errno::Einval),
    };
    let block_size = match block::devbridge::sector_size(devt.raw()) {
        Some(size) if size != 0 => u64::from(size),
        _ => return -errno(Errno::Einval),
    };
    if start % block_size != 0 || len == 0 || len % block_size != 0 {
        return -errno(Errno::Einval);
    }
    let end = match start.checked_add(len) { Some(value) => value, None => return -errno(Errno::Einval) };
    if end > cap { return -errno(Errno::Einval); }
    match block::devbridge::zeroout_range(devt.raw(), start, len, true) {
        Some(Ok(())) => 0,
        Some(Err(e)) => -block_errno(e),
        None => -errno(Errno::Einval),
    }
}

fn validate_discard_range(devt: u32, start: u64, len: u64) -> i64 {
    let bs = match block::devbridge::sector_size(devt) {
        Some(v) if v != 0 => v as u64,
        _ => return -errno(Errno::Einval),
    };
    let cap = match block::devbridge::size_bytes(devt) {
        Some(v) => v,
        None => return -errno(Errno::Einval),
    };
    if (start | len) & (bs - 1) != 0 || len == 0 { return -errno(Errno::Einval); }
    match start.checked_add(len) {
        Some(end) if end <= cap => 0,
        _ => -errno(Errno::Einval),
    }
}

fn read_range(arg: u64) -> Result<(u64, u64), i64> {
    if let Err(rv) = validate_user_buf_readable(arg, 16, 1) { return Err(rv); }
    // SAFETY: arg validated readable for two adjacent u64 fields.
    let start = unsafe { core::ptr::read_volatile(arg as *const u64) };
    // SAFETY: arg+8 remains inside the validated 16-byte range.
    let len = unsafe { core::ptr::read_volatile((arg + 8) as *const u64) };
    Ok((start, len))
}

fn block_errno(e: block::types::BlockError) -> i64 {
    match e {
        block::types::BlockError::Eio => errno(Errno::Eio),
        block::types::BlockError::Enxio => errno(Errno::Enxio),
        block::types::BlockError::Eagain => errno(Errno::Eagain),
        block::types::BlockError::Enomem => errno(Errno::Enomem),
        block::types::BlockError::Ebusy => errno(Errno::Ebusy),
        block::types::BlockError::Einval => errno(Errno::Einval),
        block::types::BlockError::Enospc => errno(Errno::Enospc),
        block::types::BlockError::Eopnotsupp => errno(Errno::Eopnotsupp),
    }
}

fn errno(e: Errno) -> i64 { e.as_i32() as i64 }

/// Store a `u64` out-param at the user pointer `arg`, guarding the address like
/// the FIONREAD path in `core.rs`. Returns `0` (ioctl success). # C: O(1)
fn write_u64(arg: u64, v: u64) -> i64 {
    if let Err(rv) = validate_user_buf_writable(arg, 8, 1) { return rv; }
    // SAFETY: arg validated writable; 8-byte out-param matching the
    // BLKGETSIZE64 / BLKGETSIZE `u64`/`unsigned long *` ABI.
    unsafe { core::ptr::write_volatile(arg as *mut u64, v); }
    0
}

/// Store an `int`/`u32` out-param at the user pointer `arg`. # C: O(1)
fn write_u32(arg: u64, v: u32) -> i64 {
    if let Err(rv) = validate_user_buf_writable(arg, 4, 1) { return rv; }
    // SAFETY: arg validated writable; 4-byte out-param matching the BLKSSZGET
    // / BLKBSZGET `int *` ABI.
    unsafe { core::ptr::write_volatile(arg as *mut u32, v); }
    0
}
