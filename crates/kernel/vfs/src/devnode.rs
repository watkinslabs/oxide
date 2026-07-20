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

use crate::inode::{Inode, InodeBuilder, InodeRef};
use crate::inode_ops::InodeOps;
use crate::file::File;
use crate::file_ops::{FileOps, default_file_ops};
use crate::poll_subs::PollSubscribers;
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
    /// Build a [`Devt`] from a KERNEL `dev_t` (Linux 12:20 split: minor in the
    /// low 20 bits, major in the top 12) by re-packing into the glibc `st_rdev`
    /// wire form. The inverse of [`Self::to_kdev`]. # C: O(1)
    pub fn from_kdev(kdev: u32) -> Devt { Devt::new(kdev_major(kdev), kdev_minor(kdev)) }
    /// This device's KERNEL `dev_t` (Linux `MKDEV`, 12:20 split). # C: O(1)
    pub fn to_kdev(self) -> u32 { mkdev(self.major(), self.minor()) }
}

// ---------------------------------------------------------------------------
// Linux KERNEL `dev_t` model (`include/linux/kdev_t.h`).
//
// Two encodings coexist in Linux and both are reproduced here, byte-faithfully:
//   * KERNEL dev_t — a 32-bit `(major:12 << 20) | minor:20` split used in-core
//     (`i_rdev`, `s_dev`, `MKDEV`/`MAJOR`/`MINOR`).
//   * USER dev_t — the glibc/`new_encode_dev` wire form the stat(2) ABI exposes
//     (minor[0..8] | major[8..20] | minor[20..32]); this is what [`Devt`] stores
//     and `st_rdev`/`st_dev` carry. `huge_encode_dev` is the kernel→user map.
// ---------------------------------------------------------------------------

/// `MINORBITS` (Linux `include/linux/kdev_t.h`) — minor occupies the low 20 bits
/// of a kernel `dev_t`, major the top 12.
pub const MINORBITS: u32 = 20;
/// `MINORMASK` — `(1 << MINORBITS) - 1`, the kernel-`dev_t` minor field mask.
pub const MINORMASK: u32 = (1 << MINORBITS) - 1;

/// `MKDEV(ma, mi)` (Linux) — pack a KERNEL `dev_t` from `(major, minor)`.
/// # C: O(1)
pub const fn mkdev(major: u32, minor: u32) -> u32 { (major << MINORBITS) | (minor & MINORMASK) }
/// `MAJOR(dev)` (Linux) for a KERNEL `dev_t`. # C: O(1)
pub const fn kdev_major(kdev: u32) -> u32 { kdev >> MINORBITS }
/// `MINOR(dev)` (Linux) for a KERNEL `dev_t`. # C: O(1)
pub const fn kdev_minor(kdev: u32) -> u32 { kdev & MINORMASK }

/// `new_encode_dev` (Linux `include/linux/kdev_t.h`) — map a KERNEL `dev_t` to
/// the 32-bit glibc/user wire form the stat ABI exposes (`st_rdev`/`st_dev`):
/// `minor[0..8] | major[8..20] | minor[20..32]`. The high-minor split lets a
/// minor exceed 255 without clobbering the 12-bit major. # C: O(1)
pub const fn new_encode_dev(kdev: u32) -> u32 {
    let major = kdev_major(kdev);
    let minor = kdev_minor(kdev);
    (minor & 0xff) | ((major & 0xfff) << 8) | ((minor & !0xff) << 12)
}

/// `huge_encode_dev` (Linux `include/linux/kdev_t.h`) — the 64-bit `st_dev`
/// user form; identical to [`new_encode_dev`] widened to `u64` (the upper bits
/// stay clear for a 32-bit-representable dev). # C: O(1)
pub const fn huge_encode_dev(kdev: u32) -> u64 { new_encode_dev(kdev) as u64 }

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
    /// `cdev->write`. # C: driver-dependent
    fn write(&self, devt: Devt, off: u64, buf: &[u8]) -> KResult<usize> {
        let _ = (devt, off, buf); Err(VfsError::Eio)
    }
    /// `cdev->write` with per-open state. # C: driver-dependent
    fn write_file(&self, devt: Devt, file: &File, off: u64, buf: &[u8]) -> KResult<usize> {
        let _ = file; self.write(devt, off, buf)
    }
    /// `cdev->unlocked_ioctl`. # C: driver-dependent
    fn ioctl(&self, devt: Devt, cmd: u32, arg: usize) -> KResult<usize> {
        let _ = (devt, cmd, arg); Err(VfsError::Enotty)
    }
    /// `cdev->poll`. # C: driver-dependent
    fn poll(&self, devt: Devt) -> KResult<u32> { let _ = devt; Ok(crate::inode::POLL_IN | crate::inode::POLL_OUT) }
    /// `cdev->poll` with per-open state. # C: driver-dependent
    fn poll_file(&self, devt: Devt, file: &File) -> KResult<u32> { let _ = file; self.poll(devt) }
    /// `cdev->mmap`/shared-frame probe. # C: driver-dependent
    fn mmap_shared_frame(&self, devt: Devt, off: u64) -> KResult<Option<u64>> { let _ = (devt, off); Ok(None) }
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

/// Backend-private state (`i_private`) for a `mknod(2)` special inode — the
/// `dev_t` + type the dispatching `i_fop` reads off the inode. Recovered with
/// `inode.private::<DeviceNodeData>()` (the old `as_any` downcast). # C: O(1)
pub struct DeviceNodeData {
    /// `S_ISCHR`/`S_ISBLK`/`S_ISFIFO`/`S_ISSOCK` (the inode's `S_IFMT`).
    pub ft:   FileType,
    /// Packed `dev_t` (`0` for FIFO/socket).
    pub devt: Devt,
}

/// Pull the [`DeviceNodeData`] off a special inode's `i_private`; `Einval` if
/// the inode is not a special node. # C: O(1)
fn device_data(inode: &Inode) -> KResult<&DeviceNodeData> {
    inode.private::<DeviceNodeData>().ok_or(VfsError::Einval)
}

/// `inode_operations` for every special node — `lookup` is `ENOTDIR`; metadata
/// ops take the generic defaults. # C: O(1)
struct SpecialInodeOps;
impl InodeOps for SpecialInodeOps {
    fn lookup(&self, _inode: &Inode, _name: &str) -> KResult<InodeRef> { Err(VfsError::Enotdir) }
}

/// `file_operations` for a char/block device node — read/write/open dispatch to
/// the driver registered for the inode's `dev_t` (`def_chr_fops`/`def_blk_fops`
/// + `chrdev_open`/`blkdev_open`). `ENXIO` when the number has no driver.
struct DeviceFileOps;
impl FileOps for DeviceFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = device_data(inode)?;
        match d.ft {
            FileType::CharDev  => lookup_chrdev(d.devt).ok_or(VfsError::Enxio)?.read(d.devt, off, buf),
            FileType::BlockDev => lookup_blkdev(d.devt).ok_or(VfsError::Enxio)?.read(d.devt, off, buf),
            _ => Err(VfsError::Eio),
        }
    }
    fn write(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        let d = device_data(inode)?;
        match d.ft {
            FileType::CharDev  => lookup_chrdev(d.devt).ok_or(VfsError::Enxio)?.write(d.devt, off, buf),
            FileType::BlockDev => lookup_blkdev(d.devt).ok_or(VfsError::Enxio)?.write(d.devt, off, buf),
            _ => Err(VfsError::Eio),
        }
    }
    fn read_file(&self, file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = device_data(file.inode())?;
        match d.ft {
            FileType::CharDev  => lookup_chrdev(d.devt).ok_or(VfsError::Enxio)?.read_file(d.devt, file, off, buf),
            FileType::BlockDev => lookup_blkdev(d.devt).ok_or(VfsError::Enxio)?.read(d.devt, off, buf),
            _ => Err(VfsError::Eio),
        }
    }
    fn write_file(&self, file: &File, off: u64, buf: &[u8]) -> KResult<usize> {
        let d = device_data(file.inode())?;
        match d.ft {
            FileType::CharDev  => lookup_chrdev(d.devt).ok_or(VfsError::Enxio)?.write_file(d.devt, file, off, buf),
            FileType::BlockDev => lookup_blkdev(d.devt).ok_or(VfsError::Enxio)?.write(d.devt, off, buf),
            _ => Err(VfsError::Eio),
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
        let result = match d.ft {
            FileType::CharDev  => lookup_chrdev(d.devt).ok_or(VfsError::Enxio)?.open_file(d.devt, file),
            FileType::BlockDev => lookup_blkdev(d.devt).ok_or(VfsError::Enxio)?.open_file(d.devt, file),
            _ => Err(VfsError::Enodev),
        };
        if result.is_ok() { file.mark_device_opened(); }
        result
    }
    fn on_release_file(&self, file: &File) {
        if !file.take_device_opened() { return; }
        if let Ok(d) = device_data(file.inode()) {
            if d.ft == FileType::CharDev {
                if let Some(ops) = lookup_chrdev(d.devt) { ops.release_file(d.devt, file); }
            }
            if d.ft == FileType::BlockDev {
                if let Some(ops) = lookup_blkdev(d.devt) { ops.release_file(d.devt, file); }
            }
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
        let Ok(d) = device_data(file.inode()) else { return 0; };
        match d.ft {
            FileType::CharDev => lookup_chrdev(d.devt).and_then(|o| o.poll_file(d.devt, file).ok()).unwrap_or(0),
            _ => self.poll(file.inode()),
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

/// `file_operations` for a socket node (`sock_no_open`): `open(2)` by path is
/// always `ENXIO` (a socket fd is born from `socket(2)`); no data op.
struct SocketFileOps;
impl FileOps for SocketFileOps {
    fn on_open(&self, _inode: &Inode) -> KResult<()> { Err(VfsError::Enxio) }
}

/// Build a char/block device node inode (Linux `init_special_inode` for
/// `S_IFCHR`/`S_IFBLK`): `i_rdev` set, `i_fop` = the driver dispatcher, the
/// `(ft, devt)` stored in `i_private`. # C: O(1)
pub fn make_device_node_inode(ino: Ino, ft: FileType, devt: Devt, perm: u16, sb: Weak<SuperBlock>) -> InodeRef {
    let mode = (ft.to_ifmt() as u32) | (perm as u32 & 0o7777);
    InodeBuilder::new(ino, mode, Arc::new(SpecialInodeOps), Arc::new(DeviceFileOps))
        .sb(sb).rdev(devt.raw()).private(Arc::new(DeviceNodeData { ft, devt })).build()
}

/// Build a FIFO/named-pipe inode (Linux `S_IFIFO`): no `i_rdev`, the DEFAULT
/// `i_fop` on the bare on-disk inode. The shared pipe ring + the pipe read/
/// write/poll vtable bind PER-OPEN at `open(2)` via `fs::pipe::fifo_open`
/// (which swaps `file->f_op` to `pipefifo_fops`); a `poll_subs` set is attached
/// so epoll/poll on the FIFO can receive readiness edges. # C: O(1)
pub fn make_fifo_inode(ino: Ino, perm: u16, sb: Weak<SuperBlock>) -> InodeRef {
    let mode = (FileType::Fifo.to_ifmt() as u32) | (perm as u32 & 0o7777);
    InodeBuilder::new(ino, mode, Arc::new(SpecialInodeOps), default_file_ops())
        .sb(sb).poll_subs(PollSubscribers::new())
        .private(Arc::new(DeviceNodeData { ft: FileType::Fifo, devt: Devt(0) })).build()
}

/// Build a socket inode (Linux `S_IFSOCK`): no `i_rdev`, `open(2)` by path →
/// `ENXIO` (`SocketFileOps`). # C: O(1)
pub fn make_socket_inode(ino: Ino, perm: u16, sb: Weak<SuperBlock>) -> InodeRef {
    let mode = (FileType::Socket.to_ifmt() as u32) | (perm as u32 & 0o7777);
    InodeBuilder::new(ino, mode, Arc::new(SpecialInodeOps), Arc::new(SocketFileOps))
        .sb(sb).private(Arc::new(DeviceNodeData { ft: FileType::Socket, devt: Devt(0) })).build()
}

/// `dev_t` a device node addresses, recovered from `i_private`. # C: O(1)
pub fn device_inode_devt(inode: &Inode) -> Option<Devt> {
    inode.private::<DeviceNodeData>().map(|d| d.devt)
}

/// `open(2)` routing for a device node (Linux `chrdev_open`). # C: O(log N)
pub fn device_inode_open(inode: &Inode) -> KResult<()> { inode.on_open() }

/// `ioctl(2)` routing for a device node — dispatch to the driver registered for
/// the inode's `dev_t`; `ENXIO` if none, `ENOTTY` for a non-device. # C: O(log N)
pub fn device_inode_ioctl(inode: &Inode, cmd: u32, arg: usize) -> KResult<usize> {
    let d = device_data(inode)?;
    match d.ft {
        FileType::CharDev  => lookup_chrdev(d.devt).ok_or(VfsError::Enxio)?.ioctl(d.devt, cmd, arg),
        FileType::BlockDev => lookup_blkdev(d.devt).ok_or(VfsError::Enxio)?.ioctl(d.devt, cmd, arg),
        _ => Err(VfsError::Enotty),
    }
}

/// `init_special_inode` (Linux `fs/inode.c`) — build the right special inode for
/// a `mknod(2)` type, binding the op set by `S_IFMT`. `rdev` is consumed only
/// for the two device types. A non-special `FileType` is a bogus `i_mode` and
/// returns `Einval`. # C: O(1)
pub fn init_special_inode(ino: Ino, ft: FileType, rdev: u32, perm: u16, sb: Weak<SuperBlock>) -> KResult<InodeRef> {
    match ft {
        FileType::CharDev | FileType::BlockDev =>
            Ok(make_device_node_inode(ino, ft, Devt::from_raw(rdev), perm, sb)),
        FileType::Fifo   => Ok(make_fifo_inode(ino, perm, sb)),
        FileType::Socket => Ok(make_socket_inode(ino, perm, sb)),
        _ => Err(VfsError::Einval),
    }
}
