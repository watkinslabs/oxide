use super::*;

/// `struct cdev` operations — a char driver's per-`dev_t` I/O vtable. The
/// `devt` is passed on every call so one driver instance can back a whole
/// minor range (mem driver: null=3, zero=5, random=8, urandom=9).
pub trait CharDevOps: Send + Sync {
    /// `cdev->open`. Default OK. # C: driver-dependent
    fn open(&self, devt: Devt) -> KResult<()> { let _ = devt; Ok(()) }
    /// `cdev->open` with the open file description available. # C: driver-dependent
    fn open_file(&self, devt: Devt, file: &File) -> KResult<()> { let _ = file; self.open(devt) }
    /// `cdev->read`. # C: driver-dependent
    fn read(&self, devt: Devt, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let _ = (devt, off, buf); Err(VfsError::Eio)
    }
    /// `cdev->read` with per-open state. # C: driver-dependent
    fn read_file(&self, devt: Devt, file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let _ = file; self.read(devt, off, buf)
    }
    /// Non-blocking `cdev->read` with per-open state. # C: driver-dependent
    fn read_nonblock_file(&self, devt: Devt, file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> { self.read_file(devt, file, off, buf) }
    /// `cdev->write`. # C: driver-dependent
    fn write(&self, devt: Devt, off: u64, buf: &[u8]) -> KResult<usize> {
        let _ = (devt, off, buf); Err(VfsError::Eio)
    }
    /// `cdev->write` with per-open state. # C: driver-dependent
    fn write_file(&self, devt: Devt, file: &File, off: u64, buf: &[u8]) -> KResult<usize> {
        let _ = file; self.write(devt, off, buf)
    }
    /// Non-blocking `cdev->write` with per-open state. # C: driver-dependent
    fn write_nonblock_file(&self, devt: Devt, file: &File, off: u64, buf: &[u8]) -> KResult<usize> { self.write_file(devt, file, off, buf) }
    /// One imported vectored write with per-open state. Record-oriented drivers
    /// override this; the default preserves scalar stream progress. # C: O(sum lens)
    fn write_iter_file(&self, devt: Devt, file: &File, off: u64, bufs: &[&[u8]], nonblock: bool) -> KResult<usize> {
        stream_write_iter_with(off, bufs, |pos, buf| {
            if nonblock { self.write_nonblock_file(devt, file, pos, buf) }
            else { self.write_file(devt, file, pos, buf) }
        })
    }
    /// `cdev->unlocked_ioctl`. # C: driver-dependent
    fn ioctl(&self, devt: Devt, cmd: u32, arg: usize) -> KResult<usize> {
        let _ = (devt, cmd, arg); Err(VfsError::Enotty)
    }
    /// `cdev->unlocked_ioctl` with the open file description. Drivers that
    /// retain per-open state receive the same file object from open to release.
    /// # C: driver-dependent
    fn ioctl_file(&self, devt: Devt, file: &File, cmd: u32, arg: usize) -> KResult<usize> {
        let _ = file; self.ioctl(devt, cmd, arg)
    }
    /// `file_operations->uring_cmd` with the exact open description.
    /// # C: driver-dependent
    fn uring_cmd_file(&self, devt: Devt, file: &File, cmd: *mut core::ffi::c_void, issue_flags: u32) -> KResult<i32> {
        let _ = (devt, file, cmd, issue_flags); Err(VfsError::Eopnotsupp)
    }
    /// Build the ABI `struct file` retained by one external io_uring command.
    /// # C: driver-dependent
    fn uring_file_new(&self, devt: Devt, file: &File) -> Option<*mut core::ffi::c_void> { let _ = (devt, file); None }
    /// Release storage returned by [`Self::uring_file_new`].
    /// # C: driver-dependent
    unsafe fn uring_file_drop(&self, devt: Devt, file: *mut core::ffi::c_void) { let _ = (devt, file); }
    /// `cdev->poll`. # C: driver-dependent
    fn poll(&self, devt: Devt) -> KResult<u32> { let _ = devt; Ok(crate::inode::POLL_IN | crate::inode::POLL_OUT) }
    /// `cdev->poll` with per-open state. # C: driver-dependent
    fn poll_file(&self, devt: Devt, file: &File) -> KResult<u32> { let _ = file; self.poll(devt) }
    /// Wait source for this open device description. # C: O(1)
    fn poll_subscribers_file(&self, devt: Devt, file: &File) -> Option<Arc<PollSubscribers>> { let _ = devt; file.inode().poll_subscribers_arc() }
    /// Does this driver supply `cdev->poll`? `epoll_ctl(2)` rejects a target
    /// without one with EPERM; `poll(2)`/`select(2)` keep the default mask.
    /// # C: O(1)
    fn can_poll(&self, devt: Devt) -> bool { let _ = devt; false }
    /// `cdev->mmap`/shared-frame probe. # C: driver-dependent
    fn mmap_shared_frame(&self, devt: Devt, off: u64) -> KResult<Option<u64>> { let _ = (devt, off); Ok(None) }
    /// Build one persistent mapping object for this exact open character file.
    /// The VMM invokes its setup hook after choosing the final VMA range.
    /// # C: driver-dependent
    fn mmap_backing_file(&self, devt: Devt, file: &Arc<File>, off: u64)
        -> KResult<Option<Arc<dyn vmm::FileBacking>>>
    { let _ = (devt, file, off); Ok(None) }
    /// `cdev->release`. # C: driver-dependent
    fn release_file(&self, devt: Devt, file: &File) { let _ = (devt, file); }
}
/// `struct block_device_operations` — a block driver's per-`dev_t` vtable.
/// Offsets/lengths are byte-granular here (the page cache / blk layer slices
/// to the device block size above this).
pub trait BlockDevOps: Send + Sync {
    /// # C: driver-dependent
    fn open(&self, devt: Devt) -> KResult<()> { let _ = devt; Ok(()) }
    /// `blkdev_open` with the allocated open file description. Block drivers
    /// that account openers must acquire their reference here, because this is
    /// paired exactly once with `release_file` at final `fput`.
    /// # C: driver-dependent
    fn open_file(&self, devt: Devt, file: &File) -> KResult<()> { let _ = file; self.open(devt) }
    /// Final open-file-description release. `open` succeeds once per new
    /// `struct file`; this runs once after the last dup reference disappears.
    /// # C: driver-dependent
    fn release_file(&self, devt: Devt, file: &File) { let _ = (devt, file); }
    /// # C: driver-dependent
    fn read(&self, devt: Devt, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let _ = (devt, off, buf); Err(VfsError::Eio)
    }
    /// # C: driver-dependent
    fn write(&self, devt: Devt, off: u64, buf: &[u8]) -> KResult<usize> {
        let _ = (devt, off, buf); Err(VfsError::Eio)
    }
    /// `block_device_operations->mmap`: return the page-cache frame for a
    /// page-aligned file offset, or `None` when this driver has no mappable
    /// address space.
    fn mmap_shared_frame(&self, devt: Devt, off: u64) -> KResult<Option<u64>> {
        let _ = (devt, off); Ok(None)
    }
    /// `vm_operations_struct.page_mkwrite` for a shared writable mapping.
    fn mmap_page_mkwrite(&self, devt: Devt, off: u64) -> KResult<()> {
        let _ = (devt, off); Ok(())
    }
    /// # C: driver-dependent
    fn ioctl(&self, devt: Devt, cmd: u32, arg: usize) -> KResult<usize> {
        let _ = (devt, cmd, arg); Err(VfsError::Enotty)
    }
    /// `block_device_operations` completion polling — reap what the driver has
    /// already finished, without waiting. `None` = this driver installs no poll
    /// operation (Linux `blk_mq_ops->poll` absent); `Some(n)` = polled, `n`
    /// completions reaped, where `Some(0)` means "none ready", not "cannot".
    /// # C: driver-dependent
    fn iopoll(&self, devt: Devt) -> Option<usize> { let _ = devt; None }
    /// Whether that poll operation exists, asked without reaping. # C: O(1)
    fn can_iopoll(&self, devt: Devt) -> bool { let _ = devt; false }
    /// Queue one direct transfer at the driver's request queue and return
    /// before it completes — the block half of
    /// [`crate::file_ops::FileOps::submit_direct`]. Paired with
    /// [`Self::iopoll`], which is what finds the completion afterwards.
    /// # C: driver-dependent
    fn submit_direct(&self, devt: Devt, io: crate::file_ops::DirectIo)
        -> crate::file_ops::DirectSubmit
    {
        let _ = devt;
        crate::file_ops::DirectSubmit::Unsupported(io)
    }
    /// `blkdev_issue_flush` — force the device's volatile write cache to
    /// stable media. `fsync(2)` on a block-device fd is required to issue it;
    /// the generic file-ops default answers `Ok(())` for a block device, which
    /// reports durability the hardware was never asked for.
    /// # C: driver-dependent; sleeps
    fn flush_cache(&self, devt: Devt) -> KResult<()> { let _ = devt; Ok(()) }
}
