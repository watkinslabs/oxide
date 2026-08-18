//! ATA identity ioctl on live AHCI-backed `sd*` nodes.

use syscall::errno::Errno;
use vfs::File;

/// Route `HDIO_GET_IDENTITY` only to the ATA owner that published this exact
/// canonical block device. Other block transports retain generic `ENOTTY`.
/// # C: O(devices)
pub(super) fn handle_ata_ioctl(file: &File, req: u64, arg: u64) -> Option<i64> {
    if req != ::ata::HDIO_GET_IDENTITY { return None; }
    let dev_t = vfs::device_inode_devt(&file.inode())?.raw();
    let target = ::ata::identity_target(dev_t)?;
    let page = target.hdio_identity().ok_or_else(|| err(Errno::Enomsg));
    Some(match page {
        Ok(page) => uaccess::copy_to_user(arg, &page).map_or_else(|_| err(Errno::Efault), |_| 0),
        Err(result) => result,
    })
}

fn err(error: Errno) -> i64 { -(error.as_i32() as i64) }
