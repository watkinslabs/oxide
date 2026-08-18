//! Linux MD assembled-array ioctl bridge.

use syscall::errno::Errno;
use vfs::File;

use crate::ioctl_user as user;
use crate::userbuf::{validate_user_buf_readable, validate_user_buf_writable};

/// Answer supported MD array ioctls on a live canonical MD block node. Unknown
/// commands return `None` so the generic ioctl dispatcher owns `ENOTTY`.
/// # C: O(disks + members)
pub(super) fn handle_md_ioctl(file: &File, req: u64, arg: u64, cap_sys_admin: bool) -> Option<i64> {
    if !matches!(req, ::md::uapi::RAID_VERSION | ::md::uapi::GET_ARRAY_INFO | ::md::uapi::GET_DISK_INFO
        | ::md::uapi::STOP_ARRAY_RO | ::md::uapi::RESTART_ARRAY_RW) { return None; }
    let dev_t = vfs::device_inode_devt(&file.inode())?.raw();
    if !::md::is_md_device(dev_t) { return None; }
    match req {
        ::md::uapi::RAID_VERSION => Some(write(arg, &::md::uapi::Version::current().encode())),
        ::md::uapi::GET_ARRAY_INFO => Some(::md::array_info(dev_t).map_or_else(|| err(Errno::Enodev), |info| write(arg, &info.encode()))),
        ::md::uapi::GET_DISK_INFO => Some(get_disk_info(dev_t, arg)),
        ::md::uapi::STOP_ARRAY_RO => Some(lifecycle(cap_sys_admin, || ::md::stop_array_read_only(dev_t))),
        ::md::uapi::RESTART_ARRAY_RW => Some(lifecycle(cap_sys_admin, || ::md::restart_array_read_write(dev_t))),
        _ => None,
    }
}

fn get_disk_info(dev_t: u32, arg: u64) -> i64 {
    // The reference first confirms this is an initialized array, then reads
    // the caller-selected persistent member number, then writes the full reply.
    if ::md::array_info(dev_t).is_none() { return err(Errno::Enodev); }
    if let Err(rv) = validate_user_buf_readable(arg, ::md::uapi::DISK_INFO_BYTES as u64, 1) { return rv; }
    let request = match user::get_bytes::<{ ::md::uapi::DISK_INFO_BYTES }>(arg) { Ok(bytes) => bytes, Err(rv) => return rv };
    let number = ::md::uapi::DiskInfo::requested_number(&request);
    let reply = ::md::disk_info(dev_t, number).expect("initialized MD array remains queryable");
    write(arg, &reply.encode())
}

fn write(arg: u64, bytes: &[u8]) -> i64 {
    if let Err(rv) = validate_user_buf_writable(arg, bytes.len() as u64, 1) { return rv; }
    user::put_bytes(arg, bytes).map_or_else(|rv| rv, |_| 0)
}

fn lifecycle(cap_sys_admin: bool, action: impl FnOnce() -> Result<(), block::BlockError>) -> i64 {
    if !cap_sys_admin { return err(Errno::Eacces); }
    match action() {
        Ok(()) => 0,
        Err(block::BlockError::Enxio) => err(Errno::Enxio),
        Err(block::BlockError::Ebusy) => err(Errno::Ebusy),
        Err(block::BlockError::Erofs) => err(Errno::Erofs),
        Err(_) => err(Errno::Eio),
    }
}

fn err(error: Errno) -> i64 { -(error.as_i32() as i64) }
