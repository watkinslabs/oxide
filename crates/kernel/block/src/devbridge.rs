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
use crate::registry::{by_dev, close_by_dev, open_by_dev, DevNum, Disk};

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
        BlockError::Eopnotsupp => VfsError::Eopnotsupp,
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
        if open_by_dev(devt.raw()) { Ok(()) } else { Err(VfsError::Enxio) }
    }
    /// Final release of one description. When it is the LAST opener, the
    /// device's dirty pages are written back here (Linux `bdev_release` syncs
    /// when it looks like the last opener is leaving): the device pass of
    /// `sync(2)` skips a disk nobody has open, so without this a raw write
    /// followed by a close would leave dirty pages nothing would ever flush.
    fn release_file(&self, devt: Devt, _file: &vfs::File) {
        if self.disk.opener_count() == 1 { let _ = self.disk.mapping.write_and_wait(); }
        let _ = close_by_dev(devt.raw());
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

/// Drop the disk's VFS `BLKDEV` region on `unregister` so future opens ENXIO
/// again (Linux `del_gendisk`). # C: O(R)
pub fn unpublish(number: DevNum) {
    vfs::devnode::unregister_blkdev_region(number.major, number.minor, 1);
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
mod tests {
    extern crate alloc;
    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;

    use crate::blockdev::{BlockDevice, MemDisk};
    use crate::registry::{self, dev_t_of, opener_count};
    use sync::Inode as InodeClass;
    use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
    use vfs::{File, FileType, KResult, OpenFlags, make_device_node_inode};

    struct TestFs;
    impl FileSystemType for TestFs {
        fn name(&self) -> &str { "block-test" }
        fn mount(&self, _s: Option<&str>, _o: &str) -> KResult<Arc<SuperBlock>> { unreachable!() }
    }
    struct TestSbOps;
    impl SuperOps for TestSbOps { fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) } }
    fn test_sb() -> Arc<SuperBlock> {
        SuperBlock::new(Arc::new(TestFs), Arc::new(TestSbOps), 0, 0, 4096, "block-test".into(), Arc::new(()))
    }

    // A `vd*` disk: 8 sectors of 512 B = 4096 B, major 254 (virtio-blk).
    fn disk(cap_blocks: u64) -> Arc<dyn BlockDevice> {
        MemDisk::<InodeClass>::new(512, cap_blocks)
    }

    // The core regression: before registration a `/dev/vdX` open would find no
    // BLKDEV region → ENXIO; registration must publish one, and unregister must
    // remove it. This is exactly what `open("/dev/vda")` in blkid/udev hits.
    #[test]
    fn register_publishes_blkdev_region_open_resolves() {
        let idx = registry::register("vdq", disk(8));
        assert_ne!(idx, 0, "register should succeed in hosted mode");
        let devt = vfs::Devt(dev_t_of("vdq", idx).unwrap());
        // Was ENXIO before this fix; must resolve to a driver now.
        let ops = vfs::lookup_blkdev(devt).expect("BLKDEV region published on register");
        ops.open(devt).expect("open dispatches to the disk");
        registry::unregister("vdq");
        assert!(vfs::lookup_blkdev(devt).is_none(), "region dropped on unregister");
    }

    // The published ops must actually move bytes to/from the backing device,
    // including a write that straddles two sectors (RMW correctness).
    #[test]
    fn published_ops_read_write_roundtrip_across_sectors() {
        let idx = registry::register("vdr", disk(8));
        let devt = vfs::Devt(dev_t_of("vdr", idx).unwrap());
        let ops = vfs::lookup_blkdev(devt).unwrap();
        let data: Vec<u8> = (0..600u32).map(|i| i as u8).collect(); // 600 B spans 2 sectors
        assert_eq!(ops.write(devt, 100, &data).unwrap(), 600);
        let mut buf = vec![0u8; 600];
        assert_eq!(ops.read(devt, 100, &mut buf).unwrap(), 600);
        assert_eq!(buf, data, "RMW write then read returns the same bytes");
        // A neighbouring untouched byte stays zero (no over-write of the RMW head).
        let mut head = vec![0u8; 100];
        ops.read(devt, 0, &mut head).unwrap();
        assert!(head.iter().all(|&b| b == 0));
        registry::unregister("vdr");
    }

    // Reads at/after end-of-device are short/EOF, never an error (Linux).
    #[test]
    fn read_past_end_is_eof_not_error() {
        let idx = registry::register("vdu", disk(2)); // 1024 B
        let devt = vfs::Devt(dev_t_of("vdu", idx).unwrap());
        let ops = vfs::lookup_blkdev(devt).unwrap();
        let mut buf = [0u8; 512];
        assert_eq!(ops.read(devt, 1024, &mut buf).unwrap(), 0);
        // A read straddling the end returns only the in-bounds tail.
        assert_eq!(ops.read(devt, 1000, &mut buf).unwrap(), 24);
        registry::unregister("vdu");
    }

    // `fsync` on a block-device fd is writeback THEN barrier: the bytes a
    // buffered write left in the device's page cache must be on the medium
    // when it returns, not merely ordered behind a flush of nothing.
    #[test]
    fn blockdev_fsync_writes_back_the_cache_then_flushes() {
        let idx = registry::register("vdv", disk(8));
        let devt = vfs::Devt(dev_t_of("vdv", idx).unwrap());
        let ops = vfs::lookup_blkdev(devt).unwrap();
        let d = registry::by_dev(devt.raw()).unwrap();
        assert_eq!(ops.write(devt, 0, &[0xC3; 64]).unwrap(), 64);
        assert_eq!(d.mapping.dirty_pages(), 1, "buffered, not written through");
        ops.flush_cache(devt).unwrap();
        assert_eq!(d.mapping.dirty_pages(), 0, "fsync wrote it back");
        registry::unregister("vdv");
    }

    // Closing the LAST description writes the device's dirty pages back
    // (Linux `bdev_release`) — the device pass of `sync(2)` skips a disk with
    // no opener, so nothing else would.
    #[test]
    fn final_close_writes_back_the_device_cache() {
        let idx = registry::register("vdw", disk(8));
        let devt = vfs::Devt(dev_t_of("vdw", idx).unwrap());
        let ops = vfs::lookup_blkdev(devt).unwrap();
        let sb = test_sb();
        let node = make_device_node_inode(1, FileType::BlockDev, devt, 0o660, Arc::downgrade(&sb));
        let file = File::new(node.clone(), vfs::dcache::d_obtain_alias(node), OpenFlags::empty());
        ops.open_file(devt, &file).unwrap();
        let d = registry::by_dev(devt.raw()).unwrap();
        ops.write(devt, 0, &[0xD4; 32]).unwrap();
        assert_eq!(d.mapping.dirty_pages(), 1);
        ops.release_file(devt, &file);
        assert_eq!(d.mapping.dirty_pages(), 0, "final close flushed the cache");
        registry::unregister("vdw");
    }

    // Size ioctl helpers report capacity in bytes + the logical sector size.
    #[test]
    fn size_and_sector_helpers() {
        let idx = registry::register("vds", disk(8));
        let raw = dev_t_of("vds", idx).unwrap();
        assert_eq!(super::size_bytes(raw), Some(4096));
        assert_eq!(super::sector_size(raw), Some(512));
        assert_eq!(super::size_bytes(0xDEAD), None, "unknown dev_t → None");
        registry::unregister("vds");
    }

    #[test]
    fn real_block_file_lifecycle_blocks_unregister_until_final_fput() {
        let idx = registry::register("vdt", disk(8));
        let devt = vfs::Devt(dev_t_of("vdt", idx).unwrap());
        let sb = test_sb();
        let node = make_device_node_inode(1, FileType::BlockDev, devt, 0o660, Arc::downgrade(&sb));
        let file = File::new(node.clone(), vfs::dcache::d_obtain_alias(node), OpenFlags::empty());
        file.open_hook().expect("block File ->open acquires generic opener");
        assert_eq!(opener_count("vdt"), Some(1));
        assert!(!registry::unregister("vdt"), "open file description blocks del_gendisk");
        let duplicate = file.clone();
        drop(file);
        assert_eq!(opener_count("vdt"), Some(1), "dup is one opener");
        drop(duplicate);
        assert_eq!(opener_count("vdt"), Some(0));
        assert!(registry::unregister("vdt"));
    }
}
