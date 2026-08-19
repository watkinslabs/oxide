//! Block-node open bridge — publishes each registered [`Disk`] into the VFS
//! `BLKDEV` dispatch table so `open("/dev/vda")` from userspace resolves to the
//! driver (Linux `blkdev_open`/`def_blk_fops`).
//!
//! Before this, the registry only minted the devtmpfs `/dev/<name>` NODE (via
//! `drv::try_device_add`) but never registered a `vfs::BlockDevOps` for its
//! `dev_t`, so `DeviceFileOps` (vfs) hit `lookup_blkdev(devt) == None` and every
//! open of `/dev/vda` returned `ENXIO` ("Failed to open '/dev/vda': No such
//! device or address"). The kernel still booted because ext4 mounts by-serial
//! (`by_serial("oxide-root")`), bypassing the node — but blkid/udev/fsck, which
//! open the node by PATH, all failed.
//!
//! The registry (`register_with_serial`/`unregister`) calls [`publish`] /
//! [`unpublish`] here; [`DiskBlkOps`] forwards byte-granular read/write to the
//! disk's page cache (`crate::bdev`), which owns the translation to whole
//! device blocks. There is deliberately no second, uncached byte path beside
//! it: a raw open that bypassed the cache would disagree with one that used
//! it, and with the filesystem mounted on the same disk.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use vfs::{BlockDevOps, Devt};
use vfs::types::{KResult, VfsError};

use crate::blockdev::{BlockDevice, BlockRequest};
use crate::types::{BlockError, KResult as BlockResult, BlockOp};
use crate::registry::{by_dev, close_by_dev, close_disk, partition_by_dev, try_open_by_dev, DevNum, Disk, OpenFailure, Partition};

/// Block-layer error as the errno a file operation returns. Both enums carry
/// the Linux numeric value, so this is a name-to-name mapping of one code.
/// # C: O(1)
fn block_err(e: BlockError) -> VfsError {
    match e {
        BlockError::Enxio      => VfsError::Enxio,
        BlockError::Eagain     => VfsError::Eagain,
        BlockError::Enomem     => VfsError::Enomem,
        BlockError::Ebusy      => VfsError::Ebusy,
        BlockError::Einval     => VfsError::Einval,
        BlockError::Enospc     => VfsError::Enospc,
        BlockError::Erofs      => VfsError::Erofs,
        BlockError::Eopnotsupp => VfsError::Eopnotsupp,
        BlockError::Eoverflow  => VfsError::Eoverflow,
        BlockError::Etoomanyrefs => VfsError::Etoomanyrefs,
        BlockError::Eio        => VfsError::Eio,
    }
}

/// Issue a block discard over an already-validated byte range. # C: O(blocks)
pub fn discard_range(dev_t: u32, off: u64, len: u64) -> Option<BlockResult<()>> {
    by_dev(dev_t).map(|d| submit_discard(d.dev.as_ref(), off, len))
}

fn submit_discard(dev: &dyn BlockDevice, off: u64, len: u64) -> BlockResult<()> {
    let bs = dev.block_size() as u64;
    if bs == 0 || (off | len) & (bs - 1) != 0 { return Err(BlockError::Einval); }
    let mut block = off / bs;
    let mut left = len / bs;
    while left != 0 {
        let n = core::cmp::min(left, u32::MAX as u64) as u32;
        let mut req = BlockRequest {
            op: BlockOp::Discard, start_block: block, len_blocks: n, buffer: Vec::new(), ..Default::default() };
        dev.submit_sync(&mut req)?;
        block += n as u64;
        left -= n as u64;
    }
    Ok(())
}

/// Issue Linux `WRITE_ZEROES` over a validated byte range. A caller that
/// supplies `no_unmap` receives zeroed data without deallocation. Devices
/// advertise native support in queue limits; all other devices take the
/// ordinary-write fallback, using one PMM page as the bounded transfer buffer.
/// # C: O(len / page)
pub fn zeroout_range(dev_t: u32, off: u64, len: u64, no_unmap: bool) -> Option<BlockResult<()>> {
    by_dev(dev_t).map(|d| issue_zeroout(d.dev.as_ref(), off, len, no_unmap))
}

fn issue_zeroout(dev: &dyn BlockDevice, off: u64, len: u64, no_unmap: bool) -> BlockResult<()> {
    let block_size = dev.block_size() as u64;
    if block_size == 0 || off % block_size != 0 || len == 0 || len % block_size != 0 {
        return Err(BlockError::Einval);
    }
    let end = off.checked_add(len).ok_or(BlockError::Einval)?;
    let capacity = dev.capacity_blocks().checked_mul(block_size).ok_or(BlockError::Einval)?;
    if end > capacity { return Err(BlockError::Einval); }

    let sectors_per_block = block_size.checked_div(crate::queue_limits::LINUX_SECTOR_BYTES as u64)
        .filter(|sectors| *sectors != 0).ok_or(BlockError::Einval)?;
    let limits = dev.queue_limits()?;
    let native_blocks = u64::from(limits.max_write_zeroes_sectors()) / sectors_per_block;
    let mut block = off / block_size;
    let mut left = len / block_size;
    if no_unmap && native_blocks != 0 {
        while left != 0 {
            let count = core::cmp::min(left, native_blocks).min(u32::MAX as u64) as u32;
            let mut request = BlockRequest::new_write_zeroes(block, count, true);
            match dev.submit_sync(&mut request) {
                Ok(()) => { block += count as u64; left -= count as u64; }
                // A driver that had to revoke its advertised native feature
                // uses the ordinary-write path for the remaining range.
                Err(BlockError::Eopnotsupp) => break,
                Err(error) => return Err(error),
            }
        }
    }
    // `WRITE_ZEROES` is semantically an ordinary zero write when native
    // support is absent. One PMM page bounds allocation without a fabricated
    // byte-count tuning constant.
    let fallback_blocks = core::cmp::max(1, (hal::PAGE_SIZE_BYTES / block_size) as u64);
    while left != 0 {
        let count = core::cmp::min(left, fallback_blocks).min(u32::MAX as u64) as u32;
        let bytes = (count as usize).checked_mul(block_size as usize).ok_or(BlockError::Einval)?;
        let mut request = BlockRequest::new_write(block, count, vec![0; bytes]);
        dev.submit_sync(&mut request)?;
        block += count as u64;
        left -= count as u64;
    }
    Ok(())
}

/// `vfs::BlockDevOps` adapter over one registered disk's `BlockDevice`. Held by
/// the VFS `BLKDEV` region for the disk's `(major,minor)`; `open`/`read`/`write`
/// on `/dev/<name>` dispatch through here. Size ioctls (`BLKGETSIZE64` etc.) are
/// answered in the ioctl syscall shim (`016_ioctl`), which has userspace access.
pub struct DiskBlkOps {
    disk: Arc<Disk>,
}

/// Bounded block-node operations for one published partition.
pub struct PartitionBlkOps { part: Arc<Partition>, mapping: Arc<crate::bdev::BdevMapping> }
impl PartitionBlkOps {
    /// # C: O(1)
    pub fn new(part: Arc<Partition>) -> Arc<Self> {
        let mapping = crate::bdev::BdevMapping::new(Arc::clone(&part.dev));
        Arc::new(Self { part, mapping })
    }
}
impl BlockDevOps for PartitionBlkOps {
    fn open(&self, devt: Devt) -> KResult<()> { partition_by_dev(devt.raw()).is_some().then_some(()).ok_or(VfsError::Enxio) }
    fn open_file(&self, devt: Devt, _file: &vfs::File) -> KResult<()> {
        match try_open_by_dev(devt.raw()) {
            Ok(()) => Ok(()), Err(OpenFailure::Closing) => Err(VfsError::Enodev), Err(OpenFailure::Missing) => Err(VfsError::Enxio),
        }
    }
    fn release_file(&self, devt: Devt, _file: &vfs::File) {
        let _ = self.mapping.write_and_wait();
        let _ = close_by_dev(devt.raw());
    }
    fn read(&self, _devt: Devt, off: u64, buf: &mut [u8]) -> KResult<usize> { self.mapping.read_at(off, buf).map_err(block_err) }
    fn write(&self, _devt: Devt, off: u64, buf: &[u8]) -> KResult<usize> { self.mapping.write_at(off, buf).map_err(block_err) }
    fn flush_cache(&self, _devt: Devt) -> KResult<()> {
        self.mapping.write_and_wait().map_err(block_err)?;
        self.part.dev.flush().map_err(block_err)
    }
}

impl DiskBlkOps {
    /// # C: O(1)
    pub fn new(disk: Arc<Disk>) -> Arc<Self> { Arc::new(Self { disk }) }
}

impl BlockDevOps for DiskBlkOps {
    // Probe-only inode opens do not own a `struct file` and therefore cannot
    // acquire an opener reference. `open_file` below is the paired lifecycle
    // path used by ordinary `open(2)`.
    fn open(&self, devt: Devt) -> KResult<()> {
        if by_dev(devt.raw()).is_some() { Ok(()) } else { Err(VfsError::Enxio) }
    }
    fn open_file(&self, devt: Devt, _file: &vfs::File) -> KResult<()> {
        match try_open_by_dev(devt.raw()) {
            Ok(()) => Ok(()), Err(OpenFailure::Closing) => Err(VfsError::Enodev), Err(OpenFailure::Missing) => Err(VfsError::Enxio),
        }
    }
    /// Final release of one description. When it is the LAST opener, the
    /// device's dirty pages are written back here (Linux `bdev_release` syncs
    /// when it looks like the last opener is leaving): the device pass of
    /// `sync(2)` skips a disk nobody has open, so without this a raw write
    /// followed by a close would leave dirty pages nothing would ever flush.
    fn release_file(&self, _devt: Devt, _file: &vfs::File) {
        if self.disk.opener_count() == 1 { let _ = self.disk.mapping.write_and_wait(); }
        let _ = close_disk(&self.disk);
    }
    /// Linux `blkdev_read_iter` — through the device's page cache, not
    /// straight at the driver.
    fn read(&self, _devt: Devt, off: u64, buf: &mut [u8]) -> KResult<usize> {
        self.disk.mapping.read_at(off, buf).map_err(block_err)
    }
    /// Linux `blkdev_write_iter` — buffered: the bytes land in the device's
    /// page cache and writeback puts them on the medium.
    fn write(&self, _devt: Devt, off: u64, buf: &[u8]) -> KResult<usize> {
        self.disk.mapping.write_at(off, buf).map_err(block_err)
    }
    /// The one link between `f_op->iopoll` and the driver's queue: the disk's
    /// own `BlockDevice` decides both whether it can be polled at all and how
    /// many completions a poll reaped. The capability is asked FIRST and
    /// separately, because a device that reaped nothing must still answer
    /// `Some(0)` — "polled, none ready" — while one with no poll operation
    /// answers `None` and gets refused by the caller instead of spun on.
    /// # C: driver-dependent
    fn iopoll(&self, _devt: Devt) -> Option<usize> {
        if !self.disk.dev.can_poll() { return None; }
        Some(self.disk.dev.poll_completions())
    }
    /// The same capability the reap above gates on, answered without reaping —
    /// one source, so an admission check and a poll can never disagree about
    /// whether this disk has a poll operation. # C: O(1)
    fn can_iopoll(&self, _devt: Devt) -> bool { self.disk.dev.can_poll() }
    /// Queue one direct transfer at the driver's request queue — the whole
    /// point of a polled ring, and the half that was missing: a transfer that
    /// completes inside the call that issued it has already posted its result
    /// before any poll could look for it.
    ///
    /// It bypasses the disk's page cache, which is what `O_DIRECT` asks for,
    /// but it is NOT the "second, uncached byte path" this module's header
    /// rules out: the submission still goes through the disk's published
    /// handle, so the coherence decorator writes back and drops the overlapping
    /// cached pages before the device sees it, exactly as it does for every
    /// other request. A raw direct write and a mounted filesystem still agree.
    /// # C: O(1) submit; the transfer completes later
    fn submit_direct(&self, _devt: Devt, io: vfs::file_ops::DirectIo)
        -> vfs::file_ops::DirectSubmit
    {
        use vfs::file_ops::DirectSubmit;
        // A backend nothing can poll must not accept work it finishes later:
        // the completion would have nobody to find it.
        if !self.disk.dev.can_poll() { return DirectSubmit::Unsupported(io); }
        let bs = self.disk.dev.block_size();
        let plan = match crate::direct::plan(io.write, io.off, io.len(), bs, self.disk.dev.capacity_blocks()) {
            Ok(p) => p,
            Err(e) => return DirectSubmit::Failed(e),
        };
        let vfs::file_ops::DirectIo { write, buf, done, .. } = io;
        let (start_block, len_blocks, bytes) = match plan {
            crate::direct::Plan::Done(n) => { done(buf, Ok(n)); return DirectSubmit::Queued; }
            crate::direct::Plan::Io { start_block, len_blocks, bytes } => (start_block, len_blocks, bytes),
        };
        let mut request = BlockRequest {
            op: if write { BlockOp::Write } else { BlockOp::Read },
            start_block, len_blocks, buffer: buf,
            // A poller, not an interrupt, will find this completion — the
            // `can_poll` gate above is what makes that true. Stating it on the
            // request is how a driver with a dedicated interrupt-free queue
            // knows to issue it there and spend no interrupt on it.
            polled: true,
            ..BlockRequest::default()
        };
        // The clamp above may have shortened the transfer; the request's buffer
        // is the transfer, so it is shortened to match rather than handing the
        // device a length its block count disagrees with.
        request.buffer.truncate(bytes);
        if !write && request.buffer.len() < bytes { request.buffer.resize(bytes, 0); }
        self.disk.dev.submit(request, alloc::boxed::Box::new(move |req: BlockRequest, res: BlockResult<()>| {
            done(req.buffer, res.map(|()| bytes).map_err(block_err));
        }));
        DirectSubmit::Queued
    }
    /// Linux `blkdev_fsync`: write back the device's page cache and wait for
    /// it, THEN `blkdev_issue_flush`. The barrier alone would report a
    /// durability the cached bytes never reached.
    fn flush_cache(&self, _devt: Devt) -> KResult<()> {
        self.disk.mapping.write_and_wait().map_err(block_err)?;
        self.disk.dev.flush().map_err(|_| VfsError::Eio)
    }
}

/// Register the disk's canonical number → its stats-wrapped `dev` into the VFS
/// `BLKDEV` table so `open("/dev/<name>")` resolves. Idempotent overlap
/// (`Ebusy`) is ignored — a re-`register` of the same disk keeps the live
/// region. # C: O(R)
pub fn publish(number: DevNum, disk: Arc<Disk>) {
    let _ = vfs::devnode::register_blkdev_region(number.major, number.minor, 1, DiskBlkOps::new(disk));
}

/// Publish one disk-owned partition into the VFS block-device table. # C: O(R)
pub fn publish_partition(part: Arc<Partition>) {
    let _ = vfs::devnode::register_blkdev_region(part.number_dev.major, part.number_dev.minor, 1, PartitionBlkOps::new(part));
}

/// Drop the disk's VFS `BLKDEV` region on `unregister` so future opens ENXIO
/// again (Linux `del_gendisk`). # C: O(R)
pub fn unpublish(number: DevNum) {
    vfs::devnode::unregister_blkdev_region(number.major, number.minor, 1);
}

/// Drop one partition's VFS block region. # C: O(R)
pub fn unpublish_partition(part: &Partition) {
    vfs::devnode::unregister_blkdev_region(part.number_dev.major, part.number_dev.minor, 1);
}

/// Capacity of the disk owning `dev_t` in bytes, for `BLKGETSIZE64`. # C: O(N)
pub fn size_bytes(dev_t: u32) -> Option<u64> {
    by_dev(dev_t).map(|d| d.dev.capacity_blocks().saturating_mul(d.dev.block_size() as u64))
}

/// Logical sector size of the disk owning `dev_t`, for `BLKSSZGET`/`BLKBSZGET`.
/// # C: O(N)
pub fn sector_size(dev_t: u32) -> Option<u32> {
    by_dev(dev_t).map(|d| d.dev.block_size())
}

#[cfg(test)]
#[path = "devbridge/tests.rs"]
mod tests;
