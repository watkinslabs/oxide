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
//! `Disk`'s stats-wrapped `BlockDevice` via whole-sector RMW.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use vfs::{BlockDevOps, Devt};
use vfs::types::{KResult, VfsError};

use crate::blockdev::{BlockDevice, BlockRequest};
use crate::types::{BlockError, KResult as BlockResult, BlockOp};
use crate::registry::{by_dev, close_by_dev, open_by_dev, DevNum, Disk};

/// Read `buf.len()` bytes from `dev` at byte offset `off`, translating to
/// whole-sector reads (Linux block layer slices to `block_size` below the fops).
/// Reads past the device capacity return a short/zero count (EOF), never an
/// error — matching a read on a block device positioned at/after its end.
/// # C: O(buf.len() / block_size)
pub fn read_at(dev: &dyn BlockDevice, off: u64, buf: &mut [u8]) -> KResult<usize> {
    if buf.is_empty() { return Ok(0); }
    let bs = dev.block_size() as u64;
    let cap = dev.capacity_blocks().saturating_mul(bs);
    if off >= cap { return Ok(0); }
    let len = core::cmp::min(buf.len() as u64, cap - off) as usize;
    let first = off / bs;
    let last_excl = (off + len as u64 + bs - 1) / bs;
    let n = (last_excl - first) as u32;
    let mut req = BlockRequest::new_read(first, n, dev.block_size());
    dev.submit_sync(&mut req).map_err(|_| VfsError::Eio)?;
    let inner = (off - first * bs) as usize;
    buf[..len].copy_from_slice(&req.buffer[inner .. inner + len]);
    Ok(len)
}

/// Write `data` to `dev` at byte offset `off` via read-modify-write for any
/// partial leading/trailing sector. Writes past capacity are clamped; a write
/// starting at/after the end returns `0` (Linux short-writes a block device at
/// its end). # C: O(data.len() / block_size + 2 RMW sectors)
pub fn write_at(dev: &dyn BlockDevice, off: u64, data: &[u8]) -> KResult<usize> {
    if data.is_empty() { return Ok(0); }
    let bs = dev.block_size() as u64;
    let cap = dev.capacity_blocks().saturating_mul(bs);
    if off >= cap { return Ok(0); }
    let len = core::cmp::min(data.len() as u64, cap - off) as usize;
    let first = off / bs;
    let last_excl = (off + len as u64 + bs - 1) / bs;
    let n = (last_excl - first) as u32;
    let mut rmw = BlockRequest::new_read(first, n, dev.block_size());
    dev.submit_sync(&mut rmw).map_err(|_| VfsError::Eio)?;
    let inner = (off - first * bs) as usize;
    rmw.buffer[inner .. inner + len].copy_from_slice(&data[..len]);
    let mut wreq = BlockRequest::new_write(first, n, rmw.buffer);
    dev.submit_sync(&mut wreq).map_err(|_| VfsError::Eio)?;
    Ok(len)
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
            op: BlockOp::Discard, start_block: block, len_blocks: n, buffer: Vec::new(),
        };
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
    fn release_file(&self, devt: Devt, _file: &vfs::File) {
        let _ = close_by_dev(devt.raw());
    }
    fn read(&self, _devt: Devt, off: u64, buf: &mut [u8]) -> KResult<usize> {
        read_at(self.disk.dev.as_ref(), off, buf)
    }
    fn write(&self, _devt: Devt, off: u64, buf: &[u8]) -> KResult<usize> {
        write_at(self.disk.dev.as_ref(), off, buf)
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
        let d = disk(2); // 1024 B
        let mut buf = [0u8; 512];
        assert_eq!(super::read_at(d.as_ref(), 1024, &mut buf).unwrap(), 0);
        // A read straddling the end returns only the in-bounds tail.
        assert_eq!(super::read_at(d.as_ref(), 1000, &mut buf).unwrap(), 24);
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
