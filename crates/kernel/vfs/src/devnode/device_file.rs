//! Open character/block device file-operation dispatch.

use alloc::sync::Arc;

use crate::file::File;
use crate::file_ops::{FileOps, stream_write_iter_with};
use crate::inode::Inode;
use crate::poll_subs::PollSubscribers;
use crate::types::{FileType, KResult, VfsError};

use super::{OpenedDevice, device_data, lookup_blkdev, lookup_chrdev};

/// Character/block special-node data operations. The driver chosen at open
/// owns every per-file operation until final release.
pub(super) struct DeviceFileOps;
impl FileOps for DeviceFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = device_data(inode)?;
        match d.ft {
            FileType::CharDev  => lookup_chrdev(d.devt).ok_or(VfsError::Enxio)?.read(d.devt, off, buf),
            FileType::BlockDev => lookup_blkdev(d.devt).ok_or(VfsError::Enxio)?.read(d.devt, off, buf),
            _ => Err(VfsError::Eio) }
    }

    fn write(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        let d = device_data(inode)?;
        match d.ft {
            FileType::CharDev  => lookup_chrdev(d.devt).ok_or(VfsError::Enxio)?.write(d.devt, off, buf),
            FileType::BlockDev => lookup_blkdev(d.devt).ok_or(VfsError::Enxio)?.write(d.devt, off, buf),
            _ => Err(VfsError::Eio) }
    }

    /// Linux `blkdev_fsync` (`block/fops.c`): write back the block device's
    /// page cache, then `blkdev_issue_flush`. `datasync` is not consulted —
    /// a raw block device has no metadata to elide, which is why Linux gives
    /// `fsync` and `fdatasync` the same slot here. A character device keeps
    /// the generic answer (`EINVAL` unless its own f_op says otherwise).
    fn fsync(&self, file: &File, _datasync: bool) -> KResult<()> {
        match file.opened_device().ok_or(VfsError::Enxio)? {
            OpenedDevice::Block { devt, ops } => ops.flush_cache(devt),
            OpenedDevice::Char { .. } => Err(VfsError::Einval),
        }
    }

    fn read_file(&self, file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> {
        match file.opened_device().ok_or(VfsError::Enxio)? {
            OpenedDevice::Char { devt, ops } => ops.read_file(devt, file, off, buf),
            OpenedDevice::Block { devt, ops } => ops.read(devt, off, buf),
        }
    }

    fn write_file(&self, file: &File, off: u64, buf: &[u8]) -> KResult<usize> {
        match file.opened_device().ok_or(VfsError::Enxio)? {
            OpenedDevice::Char { devt, ops } => ops.write_file(devt, file, off, buf),
            OpenedDevice::Block { devt, ops } => ops.write(devt, off, buf),
        }
    }

    fn read_nonblock_file(&self, file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> {
        match file.opened_device().ok_or(VfsError::Enxio)? {
            OpenedDevice::Char { devt, ops } => ops.read_nonblock_file(devt, file, off, buf),
            OpenedDevice::Block { devt, ops } => ops.read(devt, off, buf),
        }
    }

    fn write_nonblock_file(&self, file: &File, off: u64, buf: &[u8]) -> KResult<usize> {
        match file.opened_device().ok_or(VfsError::Enxio)? {
            OpenedDevice::Char { devt, ops } => ops.write_nonblock_file(devt, file, off, buf),
            OpenedDevice::Block { devt, ops } => ops.write(devt, off, buf),
        }
    }

    fn write_iter_file(&self, file: &File, off: u64, bufs: &[&[u8]], nonblock: bool) -> KResult<usize> {
        match file.opened_device().ok_or(VfsError::Enxio)? {
            OpenedDevice::Char { devt, ops } => ops.write_iter_file(devt, file, off, bufs, nonblock),
            OpenedDevice::Block { devt, ops } => {
                stream_write_iter_with(off, bufs, |pos, buf| ops.write(devt, pos, buf))
            }
        }
    }

    fn on_open(&self, inode: &Inode) -> KResult<()> {
        let d = device_data(inode)?;
        match d.ft {
            FileType::CharDev  => lookup_chrdev(d.devt).map(|_| ()).ok_or(VfsError::Enxio),
            FileType::BlockDev => lookup_blkdev(d.devt).map(|_| ()).ok_or(VfsError::Enxio),
            _ => Err(VfsError::Enodev),
        }
    }

    fn on_open_file(&self, file: &File) -> KResult<()> {
        let d = device_data(file.inode())?;
        let opened = match d.ft {
            FileType::CharDev => {
                let ops = lookup_chrdev(d.devt).ok_or(VfsError::Enxio)?;
                ops.open_file(d.devt, file)?;
                OpenedDevice::Char { devt: d.devt, ops }
            }
            FileType::BlockDev => {
                let ops = lookup_blkdev(d.devt).ok_or(VfsError::Enxio)?;
                ops.open_file(d.devt, file)?;
                OpenedDevice::Block { devt: d.devt, ops }
            }
            _ => return Err(VfsError::Enodev),
        };
        file.retain_opened_device(opened);
        Ok(())
    }

    fn on_release_file(&self, file: &File) {
        match file.take_opened_device() {
            Some(OpenedDevice::Char { devt, ops }) => ops.release_file(devt, file),
            Some(OpenedDevice::Block { devt, ops }) => ops.release_file(devt, file),
            None => {}
        }
    }

    fn poll(&self, inode: &Inode) -> u32 {
        let Ok(d) = device_data(inode) else { return 0; };
        match d.ft {
            FileType::CharDev => lookup_chrdev(d.devt).and_then(|o| o.poll(d.devt).ok()).unwrap_or(0),
            _ => 0,
        }
    }

    fn poll_open_file(&self, file: &File) -> u32 {
        match file.opened_device() {
            Some(OpenedDevice::Char { devt, ops }) => ops.poll_file(devt, file).unwrap_or(0),
            Some(OpenedDevice::Block { .. }) => 0,
            None => 0,
        }
    }

    /// Block devices have no readiness operation at all; a character device
    /// answers for its own driver. # C: O(1)
    fn can_poll(&self, file: &File) -> bool {
        match file.opened_device() {
            Some(OpenedDevice::Char { devt, ops }) => ops.can_poll(devt),
            Some(OpenedDevice::Block { .. }) | None => false,
        }
    }

    fn poll_subscribers(&self, file: &File) -> Option<Arc<PollSubscribers>> {
        match file.opened_device() {
            Some(OpenedDevice::Char { devt, ops }) => ops.poll_subscribers_file(devt, file),
            Some(OpenedDevice::Block { .. }) => file.inode().poll_subscribers_arc(),
            None => None,
        }
    }

    fn mmap_shared_frame(&self, inode: &Inode, off: u64) -> KResult<Option<crate::SharedFrame>> {
        let d = device_data(inode)?;
        match d.ft {
            FileType::CharDev => lookup_chrdev(d.devt).map_or(Ok(None), |o| {
                o.mmap_shared_frame(d.devt, off)
                    .map(|frame| frame.map(|pa| crate::SharedFrame { pa, map_ref_held: false }))
            }),
            _ => Ok(None),
        }
    }
}
