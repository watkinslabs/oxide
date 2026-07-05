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

use vfs::{BlockDevOps, Devt};
use vfs::types::{KResult, VfsError};

use crate::blockdev::{BlockDevice, BlockRequest};
use crate::registry::{by_dev, major_minor};

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

/// `vfs::BlockDevOps` adapter over one registered disk's `BlockDevice`. Held by
/// the VFS `BLKDEV` region for the disk's `(major,minor)`; `open`/`read`/`write`
/// on `/dev/<name>` dispatch through here. Size ioctls (`BLKGETSIZE64` etc.) are
/// answered in the ioctl syscall shim (`016_ioctl`), which has userspace access.
pub struct DiskBlkOps {
    dev: Arc<dyn BlockDevice>,
}

impl DiskBlkOps {
    /// # C: O(1)
    pub fn new(dev: Arc<dyn BlockDevice>) -> Arc<Self> { Arc::new(Self { dev }) }
}

impl BlockDevOps for DiskBlkOps {
    fn open(&self, _devt: Devt) -> KResult<()> { Ok(()) }
    fn read(&self, _devt: Devt, off: u64, buf: &mut [u8]) -> KResult<usize> {
        read_at(self.dev.as_ref(), off, buf)
    }
    fn write(&self, _devt: Devt, off: u64, buf: &[u8]) -> KResult<usize> {
        write_at(self.dev.as_ref(), off, buf)
    }
}

/// Register the disk `(name,index)` → its stats-wrapped `dev` into the VFS
/// `BLKDEV` table so `open("/dev/<name>")` resolves. Idempotent overlap
/// (`Ebusy`) is ignored — a re-`register` of the same disk keeps the live
/// region. # C: O(R)
pub fn publish(name: &str, index: u32, dev: Arc<dyn BlockDevice>) {
    let (major, minor) = major_minor(name, index);
    let _ = vfs::devnode::register_blkdev_region(major, minor, 1, DiskBlkOps::new(dev));
}

/// Drop the disk's VFS `BLKDEV` region on `unregister` so future opens ENXIO
/// again (Linux `del_gendisk`). # C: O(R)
pub fn unpublish(name: &str, index: u32) {
    let (major, minor) = major_minor(name, index);
    vfs::devnode::unregister_blkdev_region(major, minor, 1);
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
    use crate::registry::{self, dev_t_of};
    use sync::Inode as InodeClass;

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
        let devt = vfs::Devt(dev_t_of("vdq", idx));
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
        let devt = vfs::Devt(dev_t_of("vdr", idx));
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
        let raw = dev_t_of("vds", idx);
        assert_eq!(super::size_bytes(raw), Some(4096));
        assert_eq!(super::sector_size(raw), Some(512));
        assert_eq!(super::size_bytes(0xDEAD), None, "unknown dev_t → None");
        registry::unregister("vds");
    }
}
