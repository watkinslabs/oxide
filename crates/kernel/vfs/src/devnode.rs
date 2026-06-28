//! Device-number dispatch (`19§4`) — char/block device inodes route I/O to a
//! driver registered by `(major,minor)`, the Linux `cdev`/`block_device`
//! model. A `mknod(2)` node stores a `dev_t`; `open`/`read`/`write`/`ioctl`
//! look the driver up by `dev_t` and forward. A node whose number has no
//! registered driver returns `ENXIO` (Linux `chrdev_open` miss) — never the
//! old `EIO`-from-a-bespoke-inode behaviour.
//!
//! Replaces the per-inode bespoke device bodies (devfs `NullInode`/…,
//! tmpfs `TmpfsSpecialInode` EIO) with ONE dispatcher keyed by number, so a
//! user `mknod /dev/null c 1 3` reaches the same driver the kernel registered.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;

use sync::{Devices as DevClass, Spinlock};

use crate::inode::{Inode, InodeRef};
use crate::superblock::SuperBlock;
use crate::types::{FileType, Ino, KResult, VfsError};

/// `dev_t` (Linux `MKDEV`/`MAJOR`/`MINOR`, glibc 12:20 encoding). Stored as
/// the 32-bit value `mknod(2)` passes: minor in bits `[0..8)`+`[20..32)`,
/// major in `[8..20)`.
#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Debug)]
pub struct Devt(pub u32);

impl Devt {
    /// `MKDEV(major, minor)`. # C: O(1)
    pub fn new(major: u32, minor: u32) -> Devt {
        Devt((minor & 0xff) | ((major & 0xfff) << 8) | ((minor & !0xff) << 12))
    }
    /// `MAJOR(dev)`. # C: O(1)
    pub fn major(self) -> u32 { (self.0 >> 8) & 0xfff }
    /// `MINOR(dev)`. # C: O(1)
    pub fn minor(self) -> u32 { (self.0 & 0xff) | ((self.0 >> 12) & !0xff) }
    /// Packed `dev_t` (the value `rdev()` reports). # C: O(1)
    pub fn raw(self) -> u32 { self.0 }
    /// Wrap a raw packed `dev_t` from `mknod(2)`. # C: O(1)
    pub fn from_raw(raw: u32) -> Devt { Devt(raw) }
}

/// `struct cdev` operations — a char driver's per-`dev_t` I/O vtable. The
/// `devt` is passed on every call so one driver instance can back a whole
/// minor range (mem driver: null=3, zero=5, random=8, urandom=9).
pub trait CharDevOps: Send + Sync {
    /// `cdev->open`. Default OK. # C: driver-dependent
    fn open(&self, devt: Devt) -> KResult<()> { let _ = devt; Ok(()) }
    /// `cdev->read`. # C: driver-dependent
    fn read(&self, devt: Devt, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let _ = (devt, off, buf); Err(VfsError::Eio)
    }
    /// `cdev->write`. # C: driver-dependent
    fn write(&self, devt: Devt, off: u64, buf: &[u8]) -> KResult<usize> {
        let _ = (devt, off, buf); Err(VfsError::Eio)
    }
    /// `cdev->unlocked_ioctl`. # C: driver-dependent
    fn ioctl(&self, devt: Devt, cmd: u32, arg: usize) -> KResult<usize> {
        let _ = (devt, cmd, arg); Err(VfsError::Enotty)
    }
}

/// `struct block_device_operations` — a block driver's per-`dev_t` vtable.
/// Offsets/lengths are byte-granular here (the page cache / blk layer slices
/// to the device block size above this).
pub trait BlockDevOps: Send + Sync {
    /// # C: driver-dependent
    fn open(&self, devt: Devt) -> KResult<()> { let _ = devt; Ok(()) }
    /// # C: driver-dependent
    fn read(&self, devt: Devt, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let _ = (devt, off, buf); Err(VfsError::Eio)
    }
    /// # C: driver-dependent
    fn write(&self, devt: Devt, off: u64, buf: &[u8]) -> KResult<usize> {
        let _ = (devt, off, buf); Err(VfsError::Eio)
    }
    /// # C: driver-dependent
    fn ioctl(&self, devt: Devt, cmd: u32, arg: usize) -> KResult<usize> {
        let _ = (devt, cmd, arg); Err(VfsError::Enotty)
    }
}

/// Number of minor numbers in a major (Linux `MINORBITS == 20`, so a major
/// spans `1 << 20` minors). A legacy whole-major claim covers `[0, MINOR_SPAN)`.
pub const MINOR_SPAN: u32 = 1 << 20;

/// One registered `(baseminor, count)` slice of a major and the driver that
/// backs it — Linux `cdev_add(cdev, MKDEV(major,baseminor), count)`. Distinct
/// drivers share a major by claiming disjoint minor ranges (e.g. major 10
/// "misc", major 4 ttys), so the registry maps a major to a LIST of ranges,
/// not a single driver. `covers(minor)` is the half-open `[base, base+count)`
/// containment test `chrdev_open`/`blkdev_open` use to pick the driver.
struct Region<T: ?Sized> {
    base:  u32,
    count: u32,
    ops:   Arc<T>,
}

impl<T: ?Sized> Region<T> {
    /// `[base, base+count)` containment (u64 math: `base+count` can reach
    /// `1<<20` and must not wrap a `u32`). # C: O(1)
    fn covers(&self, minor: u32) -> bool {
        let (s, e) = (self.base as u64, self.base as u64 + self.count as u64);
        (minor as u64) >= s && (minor as u64) < e
    }
    /// Half-open overlap with another `[base, base+count)` range. # C: O(1)
    fn overlaps(&self, base: u32, count: u32) -> bool {
        let (s, e)   = (self.base as u64, self.base as u64 + self.count as u64);
        let (os, oe) = (base as u64, base as u64 + count as u64);
        s < oe && os < e
    }
}

/// `chrdevs[]` — `major -> [region]`. Each region is a `(baseminor, count)`
/// slice owned by one `CharDevOps` (Linux `cdev_map`), so several drivers can
/// share a major with disjoint minor ranges.
static CHRDEV: Spinlock<BTreeMap<u32, Vec<Region<dyn CharDevOps>>>, DevClass>
    = Spinlock::new(BTreeMap::new());

/// `blkdevs[]` — `major -> [region]`.
static BLKDEV: Spinlock<BTreeMap<u32, Vec<Region<dyn BlockDevOps>>>, DevClass>
    = Spinlock::new(BTreeMap::new());

/// Insert `(base, count, ops)` into a major's region list, `Ebusy` on overlap
/// (Linux `__register_chrdev_region` returns `-EBUSY`). `count == 0` is
/// `Einval`. # C: O(R) in regions on the major.
fn region_insert<T: ?Sized>(
    map:   &mut BTreeMap<u32, Vec<Region<T>>>,
    major: u32,
    base:  u32,
    count: u32,
    ops:   Arc<T>,
) -> KResult<()> {
    if count == 0 { return Err(VfsError::Einval); }
    let regs = map.entry(major).or_default();
    if regs.iter().any(|r| r.overlaps(base, count)) { return Err(VfsError::Ebusy); }
    regs.push(Region { base, count, ops });
    Ok(())
}

/// Drop the exact `(base, count)` region from a major; prune the major when its
/// last region leaves. # C: O(R).
fn region_remove<T: ?Sized>(map: &mut BTreeMap<u32, Vec<Region<T>>>, major: u32, base: u32, count: u32) {
    if let Some(regs) = map.get_mut(&major) {
        regs.retain(|r| !(r.base == base && r.count == count));
        if regs.is_empty() { map.remove(&major); }
    }
}

/// `register_chrdev(major, ops)` — legacy whole-major claim (Linux
/// `register_chrdev`, minors `[0, MINOR_SPAN)`). Replaces any existing regions
/// on the major. For disjoint minor ranges use [`register_chrdev_region`].
/// # C: O(R)
pub fn register_chrdev(major: u32, ops: Arc<dyn CharDevOps>) {
    CHRDEV.lock().insert(major, vec![Region { base: 0, count: MINOR_SPAN, ops }]);
}
/// `register_chrdev_region(major, baseminor, count, ops)` — claim a minor
/// SLICE of a major (Linux `__register_chrdev_region` + `cdev_add`). `Ebusy`
/// if `[baseminor, baseminor+count)` overlaps a region already on the major;
/// `Einval` if `count == 0`. # C: O(R)
pub fn register_chrdev_region(major: u32, baseminor: u32, count: u32, ops: Arc<dyn CharDevOps>) -> KResult<()> {
    region_insert(&mut CHRDEV.lock(), major, baseminor, count, ops)
}
/// `lookup_chrdev(devt)` — the driver whose region covers this exact
/// `(major,minor)`, if any (Linux `kobj_lookup` of `cdev_map`). # C: O(R)
pub fn lookup_chrdev(devt: Devt) -> Option<Arc<dyn CharDevOps>> {
    let g = CHRDEV.lock();
    let regs = g.get(&devt.major())?;
    regs.iter().find(|r| r.covers(devt.minor())).map(|r| r.ops.clone())
}
/// `unregister_chrdev(major)` — drop every region on the major. # C: O(log N)
pub fn unregister_chrdev(major: u32) { CHRDEV.lock().remove(&major); }
/// `unregister_chrdev_region(major, baseminor, count)` — drop one registered
/// slice (Linux `unregister_chrdev_region`). # C: O(R)
pub fn unregister_chrdev_region(major: u32, baseminor: u32, count: u32) {
    region_remove(&mut CHRDEV.lock(), major, baseminor, count);
}

/// `register_blkdev(major, ops)` — legacy whole-major claim. # C: O(R)
pub fn register_blkdev(major: u32, ops: Arc<dyn BlockDevOps>) {
    BLKDEV.lock().insert(major, vec![Region { base: 0, count: MINOR_SPAN, ops }]);
}
/// `register_blkdev_region(major, baseminor, count, ops)` — claim a minor
/// slice (Linux `blk_register_region`). `Ebusy` on overlap, `Einval` on
/// `count == 0`. # C: O(R)
pub fn register_blkdev_region(major: u32, baseminor: u32, count: u32, ops: Arc<dyn BlockDevOps>) -> KResult<()> {
    region_insert(&mut BLKDEV.lock(), major, baseminor, count, ops)
}
/// `lookup_blkdev(devt)` — the driver whose region covers `(major,minor)`.
/// # C: O(R)
pub fn lookup_blkdev(devt: Devt) -> Option<Arc<dyn BlockDevOps>> {
    let g = BLKDEV.lock();
    let regs = g.get(&devt.major())?;
    regs.iter().find(|r| r.covers(devt.minor())).map(|r| r.ops.clone())
}
/// `unregister_blkdev(major)` — drop every region on the major. # C: O(log N)
pub fn unregister_blkdev(major: u32) { BLKDEV.lock().remove(&major); }
/// `unregister_blkdev_region(major, baseminor, count)` — drop one slice.
/// # C: O(R)
pub fn unregister_blkdev_region(major: u32, baseminor: u32, count: u32) {
    region_remove(&mut BLKDEV.lock(), major, baseminor, count);
}

/// A `mknod(2)` device node (Linux `S_ISCHR`/`S_ISBLK` inode). Carries the
/// `dev_t` + perm; every operation dispatches to the registered driver by
/// number. Built by any fs's `mknod_child` for `CharDev`/`BlockDev`.
pub struct DeviceNodeInode {
    ino:  Ino,
    ft:   FileType,
    devt: Devt,
    perm: u16,
    sb:   Weak<SuperBlock>,
}

impl DeviceNodeInode {
    /// Build a char/block device node. `ft` must be `CharDev` or `BlockDev`.
    /// # C: O(1)
    pub fn new(ino: Ino, ft: FileType, devt: Devt, perm: u16, sb: Weak<SuperBlock>) -> Arc<Self> {
        Arc::new(Self { ino, ft, devt, perm, sb })
    }

    /// `dev_t` this node addresses. # C: O(1)
    pub fn devt(&self) -> Devt { self.devt }

    /// `open(2)` routing — bind the driver (Linux `chrdev_open`). `ENXIO`
    /// when the number has no registered driver. # C: O(log N)
    pub fn do_open(&self) -> KResult<()> {
        match self.ft {
            FileType::CharDev  => lookup_chrdev(self.devt).ok_or(VfsError::Enxio)?.open(self.devt),
            FileType::BlockDev => lookup_blkdev(self.devt).ok_or(VfsError::Enxio)?.open(self.devt),
            _ => Err(VfsError::Enodev),
        }
    }

    /// `ioctl(2)` routing. # C: O(log N)
    pub fn ioctl(&self, cmd: u32, arg: usize) -> KResult<usize> {
        match self.ft {
            FileType::CharDev  => lookup_chrdev(self.devt).ok_or(VfsError::Enxio)?.ioctl(self.devt, cmd, arg),
            FileType::BlockDev => lookup_blkdev(self.devt).ok_or(VfsError::Enxio)?.ioctl(self.devt, cmd, arg),
            _ => Err(VfsError::Enotty),
        }
    }
}

impl Inode for DeviceNodeInode {
    fn ino(&self) -> Ino { self.ino }
    fn i_sb(&self) -> Option<Arc<SuperBlock>> { self.sb.upgrade() }
    fn file_type(&self) -> FileType { self.ft }
    fn perm(&self) -> Option<u16> { Some(self.perm) }
    fn rdev(&self) -> u32 { self.devt.raw() }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }

    /// Dispatch read to the registered driver; `ENXIO` if none. # C: O(log N)
    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        match self.ft {
            FileType::CharDev  => lookup_chrdev(self.devt).ok_or(VfsError::Enxio)?.read(self.devt, off, buf),
            FileType::BlockDev => lookup_blkdev(self.devt).ok_or(VfsError::Enxio)?.read(self.devt, off, buf),
            _ => Err(VfsError::Eio),
        }
    }

    /// Dispatch write to the registered driver; `ENXIO` if none. # C: O(log N)
    fn write(&self, off: u64, buf: &[u8]) -> KResult<usize> {
        match self.ft {
            FileType::CharDev  => lookup_chrdev(self.devt).ok_or(VfsError::Enxio)?.write(self.devt, off, buf),
            FileType::BlockDev => lookup_blkdev(self.devt).ok_or(VfsError::Enxio)?.write(self.devt, off, buf),
            _ => Err(VfsError::Eio),
        }
    }
}

/// A FIFO/named-pipe inode (Linux `S_ISFIFO`). `init_special_inode` binds
/// `pipefifo_fops` to a FIFO node; the pipe buffer + read/write f_op are
/// allocated by the pipe subsystem at `open(2)` (`fifo_open`), NOT by the
/// bare on-disk inode. The inode itself carries no `dev_t` (FIFOs have no
/// device number) and exposes no data op — a direct `read`/`write` on the
/// unopened inode falls through to the VFS `Einval` (no `f_op->read`).
pub struct FifoInode {
    ino:  Ino,
    perm: u16,
    sb:   Weak<SuperBlock>,
}

impl FifoInode {
    /// Build a FIFO node (Linux `S_IFIFO`). No `rdev` — a FIFO has none.
    /// # C: O(1)
    pub fn new(ino: Ino, perm: u16, sb: Weak<SuperBlock>) -> Arc<Self> {
        Arc::new(Self { ino, perm, sb })
    }
}

impl Inode for FifoInode {
    fn ino(&self) -> Ino { self.ino }
    fn i_sb(&self) -> Option<Arc<SuperBlock>> { self.sb.upgrade() }
    fn file_type(&self) -> FileType { FileType::Fifo }
    fn perm(&self) -> Option<u16> { Some(self.perm) }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    // read/write/rdev inherit the trait defaults: rdev()==0 and the bare
    // inode has no data op (the pipe f_op binds at open) → Einval.
}

/// A socket inode (Linux `S_ISSOCK`). `init_special_inode` leaves a socket
/// node on `no_open_fops`: a `mknod(2)` socket node addresses an AF_UNIX
/// rendezvous point for `bind(2)`/`connect(2)` by pathname, and `open(2)` of
/// it by path returns `ENXIO` (`sock_no_open`). The inode carries no `dev_t`
/// and no data op — a socket fd comes from `socket(2)`, never from opening
/// the node, so a direct `read`/`write` on the node is `Einval`.
pub struct SocketInode {
    ino:  Ino,
    perm: u16,
    sb:   Weak<SuperBlock>,
}

impl SocketInode {
    /// Build a socket node (Linux `S_IFSOCK`). No `rdev`. # C: O(1)
    pub fn new(ino: Ino, perm: u16, sb: Weak<SuperBlock>) -> Arc<Self> {
        Arc::new(Self { ino, perm, sb })
    }

    /// `sock_no_open` (Linux `no_open_fops.open`) — opening a socket node by
    /// path always fails `ENXIO`; a socket fd is born from `socket(2)`.
    /// # C: O(1)
    pub fn do_open(&self) -> KResult<()> { Err(VfsError::Enxio) }
}

impl Inode for SocketInode {
    fn ino(&self) -> Ino { self.ino }
    fn i_sb(&self) -> Option<Arc<SuperBlock>> { self.sb.upgrade() }
    fn file_type(&self) -> FileType { FileType::Socket }
    fn perm(&self) -> Option<u16> { Some(self.perm) }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, _n: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
    // read/write/rdev inherit the trait defaults (rdev()==0, read/write Einval).
}

/// `init_special_inode` (Linux `fs/inode.c`) — build the right special inode
/// for a `mknod(2)` type, binding the op set by `S_IFMT`. `S_IFCHR`/`S_IFBLK`
/// get a [`DeviceNodeInode`] with `rdev` set (def_chr/blk dispatch); `S_IFIFO`
/// a [`FifoInode`]; `S_IFSOCK` a [`SocketInode`]. `rdev` is consumed only for
/// the two device types (Linux sets `i_rdev` for char/block alone). Any other
/// `FileType` is a "bogus i_mode" for a special inode and returns `Einval`.
/// # C: O(1)
pub fn init_special_inode(
    ino:  Ino,
    ft:   FileType,
    rdev: u32,
    perm: u16,
    sb:   Weak<SuperBlock>,
) -> KResult<InodeRef> {
    match ft {
        FileType::CharDev | FileType::BlockDev =>
            Ok(DeviceNodeInode::new(ino, ft, Devt::from_raw(rdev), perm, sb) as InodeRef),
        FileType::Fifo   => Ok(FifoInode::new(ino, perm, sb) as InodeRef),
        FileType::Socket => Ok(SocketInode::new(ino, perm, sb) as InodeRef),
        _ => Err(VfsError::Einval),
    }
}
