//! D1-c acceptance: a char/block device node dispatches read/write/ioctl/open
//! to the driver registered by `(major,minor)` — and an unregistered number
//! returns ENXIO (Linux `chrdev_open` miss), never EIO from a bespoke inode.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, Ordering};

use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{BlockDevOps, CharDevOps, Devt, File, FileType, KResult, OpenFlags, VfsError, device_inode_ioctl, device_inode_open, make_device_node_inode};

struct NullType;
impl FileSystemType for NullType {
    fn name(&self) -> &str { "t" }
    fn mount(&self, _s: Option<&str>, _o: &str) -> KResult<Arc<SuperBlock>> { unreachable!() }
}
struct NullOps;
impl SuperOps for NullOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
}
fn sb(dev: u64) -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(NullType), Arc::new(NullOps), 0, dev, 4096, "t".into(), Arc::new(()))
}

// ---- mem char driver: (1,5)=zero returns zeros, (1,3)=null swallows ----
struct MemChar;
impl CharDevOps for MemChar {
    fn read(&self, devt: Devt, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        match devt.minor() {
            5 => { buf.fill(0); Ok(buf.len()) }     // /dev/zero
            3 => Ok(0),                              // /dev/null EOF
            _ => Err(VfsError::Enxio),
        }
    }
    fn write(&self, devt: Devt, _off: u64, buf: &[u8]) -> KResult<usize> {
        match devt.minor() { 3 | 5 => Ok(buf.len()), _ => Err(VfsError::Enxio) }
    }
    fn ioctl(&self, _devt: Devt, cmd: u32, _arg: usize) -> KResult<usize> { Ok(cmd as usize + 1) }
}

// ---- memdisk block driver: a backing Vec the node reads/writes ----
struct MemDisk { data: Mutex<Vec<u8>> }
impl BlockDevOps for MemDisk {
    fn read(&self, _devt: Devt, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = self.data.lock().unwrap();
        let start = off as usize;
        if start >= d.len() { return Ok(0); }
        let n = buf.len().min(d.len() - start);
        buf[..n].copy_from_slice(&d[start..start + n]);
        Ok(n)
    }
    fn write(&self, _devt: Devt, off: u64, buf: &[u8]) -> KResult<usize> {
        let mut d = self.data.lock().unwrap();
        let end = off as usize + buf.len();
        if d.len() < end { d.resize(end, 0); }
        d[off as usize..end].copy_from_slice(buf);
        Ok(buf.len())
    }
}

#[test]
fn devt_pack_roundtrip() {
    let d = Devt::new(1, 5);
    assert_eq!(d.major(), 1);
    assert_eq!(d.minor(), 5);
    // Large minor exercising the extended bits.
    let big = Devt::new(136, 0x1234);
    assert_eq!(big.major(), 136);
    assert_eq!(big.minor(), 0x1234);
    assert_eq!(Devt::from_raw(big.raw()), big);
}

#[test]
fn chrdev_node_dispatches_to_driver() {
    vfs::register_chrdev(1, Arc::new(MemChar));
    let s = sb(0x10);
    let zero = make_device_node_inode(100, FileType::CharDev, Devt::new(1, 5), 0o666, Arc::downgrade(&s));
    // read /dev/zero → zeros via the registered mem driver
    let mut buf = [0xffu8; 8];
    assert_eq!(zero.read(0, &mut buf).unwrap(), 8);
    assert_eq!(buf, [0u8; 8]);
    // write /dev/null swallows
    let null = make_device_node_inode(101, FileType::CharDev, Devt::new(1, 3), 0o666, Arc::downgrade(&s));
    assert_eq!(null.write(0, b"discard").unwrap(), 7);
    // stat surfaces the dev_t + type
    assert_eq!(zero.rdev(), Devt::new(1, 5).raw());
    assert_eq!(zero.file_type(), FileType::CharDev);
    assert_eq!(zero.fsid(), 0x10, "fsid derives from i_sb().s_dev");
    // ioctl + open route through
    assert_eq!(device_inode_ioctl(&zero, 41, 0).unwrap(), 42);
    assert!(device_inode_open(&zero).is_ok());
    vfs::unregister_chrdev(1);
}

#[test]
fn unregistered_number_is_enxio() {
    // No driver for major 99: open/read return ENXIO, not EIO.
    let s = sb(1);
    let n = make_device_node_inode(1, FileType::CharDev, Devt::new(99, 0), 0o666, Arc::downgrade(&s));
    assert_eq!(device_inode_open(&n), Err(VfsError::Enxio));
    let mut b = [0u8; 4];
    assert_eq!(n.read(0, &mut b), Err(VfsError::Enxio));
}

#[test]
fn blockdev_node_forwards_to_memdisk() {
    vfs::register_blkdev(8, Arc::new(MemDisk { data: Mutex::new(vec![0u8; 16]) }));
    let s = sb(2);
    let sda = make_device_node_inode(7, FileType::BlockDev, Devt::new(8, 0), 0o660, Arc::downgrade(&s));
    assert_eq!(sda.write(4, b"DATA").unwrap(), 4);
    let mut buf = [0u8; 8];
    assert_eq!(sda.read(2, &mut buf).unwrap(), 8);
    assert_eq!(&buf[2..6], b"DATA");
    assert_eq!(sda.file_type(), FileType::BlockDev);
    vfs::unregister_blkdev(8);
}

struct LifecycleBlk { opens: AtomicU32, releases: AtomicU32 }
impl BlockDevOps for LifecycleBlk {
    fn open_file(&self, _devt: Devt, _file: &File) -> KResult<()> {
        self.opens.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
    fn release_file(&self, _devt: Devt, _file: &File) {
        self.releases.fetch_add(1, Ordering::AcqRel);
    }
}

#[test]
fn blockdev_open_file_and_final_release_are_paired() {
    let ops = Arc::new(LifecycleBlk { opens: AtomicU32::new(0), releases: AtomicU32::new(0) });
    vfs::register_blkdev(205, ops.clone());
    let s = sb(3);
    let node = make_device_node_inode(8, FileType::BlockDev, Devt::new(205, 0), 0o660, Arc::downgrade(&s));
    let file = File::new(node.clone(), vfs::dcache::d_obtain_alias(node), OpenFlags::empty());
    assert_eq!(file.open_hook(), Ok(()));
    assert_eq!(ops.opens.load(Ordering::Acquire), 1);
    let duplicate = file.clone();
    drop(file);
    assert_eq!(ops.releases.load(Ordering::Acquire), 0, "dup shares one open file description");
    drop(duplicate);
    assert_eq!(ops.releases.load(Ordering::Acquire), 1, "final fput releases exactly once");
    vfs::unregister_blkdev(205);
}

struct RejectBlk { releases: AtomicU32 }
impl BlockDevOps for RejectBlk {
    fn open_file(&self, _devt: Devt, _file: &File) -> KResult<()> { Err(VfsError::Ebusy) }
    fn release_file(&self, _devt: Devt, _file: &File) { self.releases.fetch_add(1, Ordering::AcqRel); }
}

#[test]
fn failed_or_opath_block_open_never_runs_release() {
    let rejected = Arc::new(RejectBlk { releases: AtomicU32::new(0) });
    vfs::register_blkdev(206, rejected.clone());
    let s = sb(4);
    let node = make_device_node_inode(9, FileType::BlockDev, Devt::new(206, 0), 0o660, Arc::downgrade(&s));
    let failed = File::new(node.clone(), vfs::dcache::d_obtain_alias(node.clone()), OpenFlags::empty());
    assert_eq!(failed.open_hook(), Err(VfsError::Ebusy));
    drop(failed);
    let path = File::new(node.clone(), vfs::dcache::d_obtain_alias(node), OpenFlags::O_PATH);
    drop(path);
    assert_eq!(rejected.releases.load(Ordering::Acquire), 0);
    vfs::unregister_blkdev(206);
}
