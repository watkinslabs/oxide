//! ATA identity and raw-taskfile ioctls on live AHCI-backed `sd*` nodes.

extern crate alloc;

use alloc::vec::Vec;
use syscall::errno::Errno;
use vfs::File;

/// Route ATA ioctls only to the ATA owner that published this exact canonical
/// block device. The syscall layer owns bounded usercopy; ATA owns command
/// translation and output-register semantics. # C: O(data)
pub(super) fn handle_ata_ioctl(file: &File, req: u64, arg: u64, sys_admin: bool, raw_io: bool) -> Option<i64> {
    match req {
        ::ata::HDIO_GET_IDENTITY => Some(identity(file, arg)),
        ::ata::HDIO_DRIVE_CMD | ::ata::HDIO_DRIVE_TASK => {
            if !sys_admin || !raw_io { return Some(err(Errno::Eacces)); }
            let dev_t = vfs::device_inode_devt(&file.inode())?.raw();
            let target = ::ata::identity_target(dev_t)?;
            Some(if req == ::ata::HDIO_DRIVE_CMD { drive_cmd(target.device(), arg) }
                else { drive_task(target.device(), arg) })
        }
        _ => None,
    }
}

fn identity(file: &File, arg: u64) -> i64 {
    let Some(dev_t) = vfs::device_inode_devt(&file.inode()).map(|dev_t| dev_t.raw()) else { return err(Errno::Enotty); };
    let Some(target) = ::ata::identity_target(dev_t) else { return err(Errno::Enotty); };
    match target.hdio_identity() {
        Some(page) => uaccess::copy_to_user(arg, &page).map_or_else(|_| err(Errno::Efault), |_| 0),
        None => err(Errno::Enomsg),
    }
}

fn drive_cmd(device: alloc::sync::Arc<dyn ::ata::Device>, arg: u64) -> i64 {
    if arg == 0 { return err(Errno::Einval); }
    let mut args = [0u8; ::ata::DRIVE_CMD_BYTES];
    if uaccess::copy_from_user(&mut args, arg).is_err() { return err(Errno::Efault); }
    let mut data = match allocate(::ata::drive_cmd_data_bytes(&args)) { Ok(data) => data, Err(rv) => return rv };
    let completed = match ::ata::drive_cmd(device.as_ref(), &mut args, &mut data) {
        Ok(completed) => completed, Err(error) => return block_err(error),
    };
    if uaccess::copy_to_user(arg, &args).is_err() { return err(Errno::Efault); }
    if !completed { return err(Errno::Eio); }
    uaccess::copy_to_user(arg + ::ata::DRIVE_CMD_BYTES as u64, &data).map_or_else(|_| err(Errno::Efault), |_| 0)
}

fn drive_task(device: alloc::sync::Arc<dyn ::ata::Device>, arg: u64) -> i64 {
    if arg == 0 { return err(Errno::Einval); }
    let mut args = [0u8; ::ata::DRIVE_TASK_BYTES];
    if uaccess::copy_from_user(&mut args, arg).is_err() { return err(Errno::Efault); }
    let completed = match ::ata::drive_task(device.as_ref(), &mut args) {
        Ok(completed) => completed, Err(error) => return block_err(error),
    };
    if uaccess::copy_to_user(arg, &args).is_err() { return err(Errno::Efault); }
    if completed { 0 } else { err(Errno::Eio) }
}

fn allocate(bytes: usize) -> Result<Vec<u8>, i64> {
    let mut data = Vec::new();
    if data.try_reserve_exact(bytes).is_err() { return Err(err(Errno::Enomem)); }
    data.resize(bytes, 0);
    Ok(data)
}

fn block_err(error: block::BlockError) -> i64 {
    match error {
        block::BlockError::Eio => err(Errno::Eio),
        block::BlockError::Enxio => err(Errno::Enxio),
        block::BlockError::Eagain => err(Errno::Eagain),
        block::BlockError::Enomem => err(Errno::Enomem),
        block::BlockError::Ebusy => err(Errno::Ebusy),
        block::BlockError::Einval => err(Errno::Einval),
        block::BlockError::Enospc => err(Errno::Enospc),
        block::BlockError::Erofs => err(Errno::Erofs),
        block::BlockError::Eopnotsupp => err(Errno::Eopnotsupp),
        block::BlockError::Eoverflow => err(Errno::Eoverflow),
        block::BlockError::Etoomanyrefs => err(Errno::Etoomanyrefs),
    }
}

fn err(error: Errno) -> i64 { -(error.as_i32() as i64) }
