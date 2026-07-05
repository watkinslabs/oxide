#![cfg(target_os = "oxide-kernel")]

//! Block-device size ioctls (Linux `block/ioctl.c blkdev_ioctl`). blkid, mkfs,
//! udev and systemd-fsck all probe `/dev/vda` with these right after opening it;
//! a block node is NOT a CharDev, so without this they'd fall through the ioctl
//! shim to `ENOTTY`. The disk geometry comes from the block registry via the
//! node's `dev_t` (`block::devbridge`).

use vfs::InodeRef;

/// `_IO(0x12,96)` — capacity in 512-byte sectors, `unsigned long *` out.
const BLKGETSIZE:   u64 = 0x1260;
/// `_IO(0x12,104)` — logical sector size, `int *` out.
const BLKSSZGET:    u64 = 0x1268;
/// `_IOR(0x12,112,size_t)` — soft block size, `int *` out.
const BLKBSZGET:    u64 = 0x8008_1270;
/// `_IOR(0x12,114,size_t)` — capacity in bytes, `u64 *` out.
const BLKGETSIZE64: u64 = 0x8008_1272;

/// Sectors are 512 bytes in the `BLKGETSIZE` ABI regardless of logical block
/// size (Linux reports `bdev_nr_sectors`, always 512-B units).
const ABI_SECTOR: u64 = 512;

/// Answer a block-device size ioctl. `Some(rv)` when `req` is one we own,
/// `None` to let the caller continue (e.g. FIONBIO or the ENOTTY fallback).
/// `EINVAL` when the node's `dev_t` has no registered disk. # C: O(N_disks)
pub(super) fn handle_blk_ioctl(inode: &InodeRef, req: u64, arg: u64) -> Option<i64> {
    match req {
        BLKGETSIZE64 => {
            let devt = vfs::device_inode_devt(inode)?;
            match block::devbridge::size_bytes(devt.raw()) {
                Some(bytes) => Some(write_u64(arg, bytes)),
                None => Some(-(syscall::errno::Errno::Einval.as_i32() as i64)),
            }
        }
        BLKGETSIZE => {
            let devt = vfs::device_inode_devt(inode)?;
            match block::devbridge::size_bytes(devt.raw()) {
                // `unsigned long` is 8 bytes on both x86_64 and aarch64.
                Some(bytes) => Some(write_u64(arg, bytes / ABI_SECTOR)),
                None => Some(-(syscall::errno::Errno::Einval.as_i32() as i64)),
            }
        }
        BLKSSZGET | BLKBSZGET => {
            let devt = vfs::device_inode_devt(inode)?;
            match block::devbridge::sector_size(devt.raw()) {
                Some(ss) => Some(write_u32(arg, ss)),
                None => Some(-(syscall::errno::Errno::Einval.as_i32() as i64)),
            }
        }
        _ => None,
    }
}

/// Store a `u64` out-param at the user pointer `arg`, guarding the address like
/// the FIONREAD path in `core.rs`. Returns `0` (ioctl success). # C: O(1)
fn write_u64(arg: u64, v: u64) -> i64 {
    if arg != 0 && arg < hal::USER_VA_END {
        // SAFETY: arg validated non-null and below USER_VA_END; 8-byte out-param
        // matching the BLKGETSIZE64 / BLKGETSIZE `u64`/`unsigned long *` ABI.
        unsafe { core::ptr::write_volatile(arg as *mut u64, v); }
    }
    0
}

/// Store an `int`/`u32` out-param at the user pointer `arg`. # C: O(1)
fn write_u32(arg: u64, v: u32) -> i64 {
    if arg != 0 && arg < hal::USER_VA_END {
        // SAFETY: arg validated non-null and below USER_VA_END; 4-byte out-param
        // matching the BLKSSZGET / BLKBSZGET `int *` ABI.
        unsafe { core::ptr::write_volatile(arg as *mut u32, v); }
    }
    0
}
