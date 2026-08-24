#![cfg(target_os = "oxide-kernel")]

//! `/dev/mapper/control` ioctl boundary.
//!
//! Device-mapper owns command parsing and state transitions. This shim owns
//! only the exact control-node check, CAP_SYS_ADMIN gate, and bounded usercopy.

extern crate alloc;

use alloc::vec::Vec;

use syscall::errno::Errno;

const HEADER_BYTES: usize = device_mapper::uapi::DM_MIN_DATA_SIZE as usize;
const DATA_SIZE_OFFSET: usize = 12;
const MAX_BYTES: usize = (device_mapper::uapi::DM_MAX_TARGETS as usize)
    * (device_mapper::uapi::DM_MAX_TARGET_PARAMS as usize);

fn err(error: Errno) -> i64 { -(error.as_i32() as i64) }

fn is_control_node(inode: &vfs::InodeRef) -> bool {
    inode.file_type() == vfs::FileType::CharDev
        && vfs::kdev_major(inode.rdev()) == 10
        && vfs::kdev_minor(inode.rdev()) == device_mapper::uapi::MISC_MAPPER_CONTROL_MINOR
}

/// Handle the exact misc control node. `Some` means this node owns the
/// request even when its command number is unknown, matching the reference's
/// `ENOTTY` response instead of leaking it to a generic character driver.
/// # C: O(data_size + command payload)
pub(super) fn handle_mapper_control_ioctl(file: &vfs::File, request: u64, arg: u64,
                                           cap_sys_admin: bool) -> Option<i64> {
    let inode = file.inode();
    if !is_control_node(inode) { return None; }
    if !cap_sys_admin { return Some(err(Errno::Eperm)); }
    let mut prefix = [0u8; HEADER_BYTES];
    if uaccess::copy_from_user(&mut prefix, arg).is_err() { return Some(err(Errno::Efault)); }
    let size = u32::from_le_bytes([
        prefix[DATA_SIZE_OFFSET], prefix[DATA_SIZE_OFFSET + 1],
        prefix[DATA_SIZE_OFFSET + 2], prefix[DATA_SIZE_OFFSET + 3],
    ]) as usize;
    if size < HEADER_BYTES || size > MAX_BYTES { return Some(err(Errno::Einval)); }
    let mut bytes = Vec::new();
    if bytes.try_reserve_exact(size).is_err() { return Some(err(Errno::Enomem)); }
    bytes.resize(size, 0);
    if uaccess::copy_from_user(&mut bytes, arg).is_err() { return Some(err(Errno::Efault)); }
    match device_mapper::control::dispatch(request as u32, &mut bytes) {
        Ok(()) => match uaccess::copy_to_user(arg, &bytes) {
            Ok(()) => {
                if device_mapper::uapi::cmd_nr(request as u32) == device_mapper::uapi::DM_DEV_ARM_POLL_CMD {
                    device_mapper::control::arm_poll_file(file);
                }
                Some(0)
            },
            Err(_) => Some(err(Errno::Efault)),
        },
        Err(error) => Some(err(error)),
    }
}
