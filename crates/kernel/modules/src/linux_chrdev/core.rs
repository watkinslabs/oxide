use super::types::*;
use crate::linux_device::types::LinuxKobject;
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ffi::{c_char, c_void};
use core::ptr::null_mut;
use sync::{Modules as ModulesLockClass, Spinlock};
use vfs::{CharDevOps, Devt, File, VfsError};

const MAX_CDEV_REGIONS: usize = 128;
const MAX_MAJOR_CLAIMS: usize = 128;

#[derive(Copy, Clone)]
struct CdevRegion {
    cdev: usize,
    major: u32,
    base: u32,
    count: u32,
}

#[derive(Copy, Clone)]
struct MajorClaim {
    major: u32,
    base: u32,
    count: u32,
}

struct LinuxCharOps {
    cdev: usize,
    ops: usize,
}

static CDEVS: Spinlock<[Option<CdevRegion>; MAX_CDEV_REGIONS], ModulesLockClass> =
    Spinlock::new([None; MAX_CDEV_REGIONS]);
static MAJORS: Spinlock<[Option<MajorClaim>; MAX_MAJOR_CLAIMS], ModulesLockClass> =
    Spinlock::new([None; MAX_MAJOR_CLAIMS]);

/// Register Linux char-device KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("cdev_init",                cdev_init                as *const () as usize),
        ("cdev_alloc",               cdev_alloc               as *const () as usize),
        ("cdev_add",                 cdev_add                 as *const () as usize),
        ("cdev_del",                 cdev_del                 as *const () as usize),
        ("alloc_chrdev_region",      alloc_chrdev_region      as *const () as usize),
        ("register_chrdev_region",   register_chrdev_region   as *const () as usize),
        ("unregister_chrdev_region", unregister_chrdev_region as *const () as usize),
        ("register_chrdev",          register_chrdev          as *const () as usize),
        ("unregister_chrdev",        unregister_chrdev        as *const () as usize),
        ("noop_llseek",              noop_llseek              as *const () as usize),
        ("nonseekable_open",         nonseekable_open         as *const () as usize),
    ] { export(name, addr, false); }
}

pub(super) extern "C" fn cdev_init(cdev: *mut LinuxCdev, ops: *const LinuxFileOperations) {
    if cdev.is_null() { return; }
    // SAFETY: cdev is caller-owned Linux struct cdev storage.
    unsafe {
        (*cdev).ops = ops;
        (*cdev).owner = if ops.is_null() { null_mut() } else { (*ops).owner };
        (*cdev).dev = 0;
        (*cdev).count = 0;
        (*cdev).added = 0;
        (*cdev).private = null_mut();
        (*cdev).kobj = LinuxKobject::new();
    }
}

extern "C" fn cdev_alloc() -> *mut LinuxCdev {
    let c = Box::new(LinuxCdev {
        kobj: LinuxKobject::new(),
        ops: core::ptr::null(),
        owner: null_mut(),
        dev: 0,
        count: 0,
        added: LINUX_FIELD_CLEAR,
        private: null_mut(),
    });
    Box::into_raw(c)
}

pub(super) extern "C" fn cdev_add(cdev: *mut LinuxCdev, dev: u32, count: u32) -> i32 {
    if cdev.is_null() || count == 0 { return -LINUX_EINVAL; }
    let (major, base) = (major(dev), minor(dev));
    if major == LINUX_MAJOR_DYNAMIC || major > LINUX_MAJOR_MAX { return -LINUX_EINVAL; }
    // SAFETY: cdev is caller-owned and checked non-null.
    let ops = unsafe { (*cdev).ops };
    if ops.is_null() { return -LINUX_EINVAL; }
    if region_overlaps(major, base, count) { return -LINUX_EBUSY; }
    let adapter = Arc::new(LinuxCharOps { cdev: cdev as usize, ops: ops as usize });
    if let Err(e) = vfs::register_chrdev_region(major, base, count, adapter) {
        return -errno(e);
    }
    if !record_cdev(cdev, major, base, count) {
        vfs::unregister_chrdev_region(major, base, count);
        return -LINUX_ENOMEM;
    }
    // SAFETY: cdev is caller-owned and registration succeeded.
    unsafe {
        (*cdev).dev = dev;
        (*cdev).count = count;
        (*cdev).added = LINUX_FIELD_SET;
        (*cdev).kobj.refcount = 1;
    }
    LINUX_OK
}

pub(super) extern "C" fn cdev_del(cdev: *mut LinuxCdev) {
    if cdev.is_null() { return; }
    if let Some(r) = remove_cdev(cdev) {
        vfs::unregister_chrdev_region(r.major, r.base, r.count);
    }
    // SAFETY: cdev is caller-owned and checked non-null.
    unsafe {
        (*cdev).added = LINUX_FIELD_CLEAR;
        (*cdev).kobj.refcount = 0;
    }
}

extern "C" fn alloc_chrdev_region(dev: *mut u32, firstminor: u32, count: u32, _name: *const c_char) -> i32 {
    if dev.is_null() || count == 0 { return -LINUX_EINVAL; }
    let major = match allocate_major(firstminor, count) { Some(v) => v, None => return -LINUX_EBUSY };
    // SAFETY: dev is caller-provided writable storage for dev_t.
    unsafe { *dev = mkdev(major, firstminor); }
    LINUX_OK
}

extern "C" fn register_chrdev_region(dev: u32, count: u32, _name: *const c_char) -> i32 {
    if count == 0 { return -LINUX_EINVAL; }
    let (maj, min) = (major(dev), minor(dev));
    if maj == LINUX_MAJOR_DYNAMIC || maj > LINUX_MAJOR_MAX { return -LINUX_EINVAL; }
    if !record_major(maj, min, count) { return -LINUX_EBUSY; }
    LINUX_OK
}

pub(super) extern "C" fn unregister_chrdev_region(dev: u32, count: u32) {
    if count == 0 { return; }
    let (maj, min) = (major(dev), minor(dev));
    cdev_del_by_region(maj, min, count);
    remove_major(maj, min, count);
}

extern "C" fn register_chrdev(major_req: u32, _name: *const c_char, ops: *const LinuxFileOperations) -> i32 {
    if ops.is_null() { return -LINUX_EINVAL; }
    let major = if major_req == LINUX_MAJOR_DYNAMIC {
        match allocate_major(LINUX_MINOR_FIRST, LINUX_MINOR_SPAN) { Some(v) => v, None => return -LINUX_EBUSY }
    } else {
        if major_req > LINUX_MAJOR_MAX { return -LINUX_EINVAL; }
        if !record_major(major_req, LINUX_MINOR_FIRST, LINUX_MINOR_SPAN) { return -LINUX_EBUSY; }
        major_req
    };
    let cdev = cdev_alloc();
    if cdev.is_null() {
        remove_major(major, LINUX_MINOR_FIRST, LINUX_MINOR_SPAN);
        return -LINUX_ENOMEM;
    }
    cdev_init(cdev, ops);
    let rc = cdev_add(cdev, mkdev(major, LINUX_MINOR_FIRST), LINUX_MINOR_SPAN);
    if rc != LINUX_OK {
        remove_major(major, LINUX_MINOR_FIRST, LINUX_MINOR_SPAN);
        return rc;
    }
    major as i32
}

extern "C" fn unregister_chrdev(major: u32, _name: *const c_char) {
    unregister_chrdev_region(mkdev(major, LINUX_MINOR_FIRST), LINUX_MINOR_SPAN);
}

extern "C" fn noop_llseek(_file: *mut LinuxFile, offset: i64, _whence: i32) -> i64 { offset }

extern "C" fn nonseekable_open(_inode: *mut LinuxInode, _file: *mut LinuxFile) -> i32 { LINUX_OK }

impl CharDevOps for LinuxCharOps {
    fn open(&self, devt: Devt) -> vfs::KResult<()> {
        self.open_common(devt, None)
    }

    fn open_file(&self, devt: Devt, file: &File) -> vfs::KResult<()> {
        self.open_common(devt, Some(file))
    }

    fn read(&self, _devt: Devt, off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        self.read_common(None, off, buf)
    }

    fn read_file(&self, _devt: Devt, file: &File, off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        self.read_common(Some(file), off, buf)
    }

    fn write(&self, _devt: Devt, off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        self.write_common(None, off, buf)
    }

    fn write_file(&self, _devt: Devt, file: &File, off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        self.write_common(Some(file), off, buf)
    }

    fn ioctl(&self, _devt: Devt, cmd: u32, arg: usize) -> vfs::KResult<usize> {
        let ioctl = self.ops().and_then(|o| o.unlocked_ioctl).ok_or(VfsError::Enotty)?;
        let mut file = file_for_call(self.cdev, None);
        // SAFETY: registered callback pointer comes from the Linux file_operations table.
        checked_size(unsafe { ioctl(&mut file, cmd, arg) })
    }

    fn poll(&self, _devt: Devt) -> vfs::KResult<u32> {
        let poll = self.ops().and_then(|o| o.poll).ok_or(VfsError::Einval)?;
        let mut file = file_for_call(self.cdev, None);
        // SAFETY: registered callback pointer comes from the Linux file_operations table.
        Ok(unsafe { poll(&mut file, null_mut()) })
    }

    fn poll_file(&self, _devt: Devt, file: &File) -> vfs::KResult<u32> {
        let poll = self.ops().and_then(|o| o.poll).ok_or(VfsError::Einval)?;
        let mut lf = file_for_call(self.cdev, Some(file));
        // SAFETY: registered callback pointer comes from the Linux file_operations table.
        let mask = unsafe { poll(&mut lf, null_mut()) };
        store_file_private(file, &lf);
        Ok(mask)
    }

    fn mmap_shared_frame(&self, _devt: Devt, _off: u64) -> vfs::KResult<Option<u64>> {
        let Some(mmap) = self.ops().and_then(|o| o.mmap) else { return Ok(None); };
        let mut file = file_for_call(self.cdev, None);
        // SAFETY: registered callback pointer comes from the Linux file_operations table; no VMA model is available in this shared-frame query.
        let _ = unsafe { mmap(&mut file, null_mut()) };
        Ok(None)
    }

    fn release_file(&self, devt: Devt, file: &File) {
        let Some(release) = self.ops().and_then(|o| o.release) else { return; };
        let mut inode = inode_for(devt, self.cdev);
        let mut lf = file_for_call(self.cdev, Some(file));
        // SAFETY: registered callback pointer comes from the Linux file_operations table.
        let _ = unsafe { release(&mut inode, &mut lf) };
        store_file_private(file, &lf);
    }
}

impl LinuxCharOps {
    fn open_common(&self, devt: Devt, file: Option<&File>) -> vfs::KResult<()> {
        let ops = self.ops();
        let open = ops.and_then(|o| o.open);
        if let Some(f) = open {
            let mut inode = inode_for(devt, self.cdev);
            let mut lf = file_for_call(self.cdev, file);
            // SAFETY: callback pointer comes from a registered Linux file_operations table.
            let rc = unsafe { f(&mut inode, &mut lf) };
            if let Some(file) = file { store_file_private(file, &lf); }
            if rc < 0 { Err(errno_to_vfs((-rc) as i32)) } else { Ok(()) }
        } else { Ok(()) }
    }

    fn read_common(&self, file: Option<&File>, off: u64, buf: &mut [u8]) -> vfs::KResult<usize> {
        let read = self.ops().and_then(|o| o.read).ok_or(VfsError::Einval)?;
        let mut lf = file_for_call(self.cdev, file);
        let mut pos = off as i64;
        // SAFETY: registered callback writes at most buf.len() bytes into the provided kernel buffer.
        let rc = unsafe { read(&mut lf, buf.as_mut_ptr() as *mut c_char, buf.len(), &mut pos) };
        if let Some(file) = file { store_file_private(file, &lf); }
        checked_size(rc)
    }

    fn write_common(&self, file: Option<&File>, off: u64, buf: &[u8]) -> vfs::KResult<usize> {
        let write = self.ops().and_then(|o| o.write).ok_or(VfsError::Einval)?;
        let mut lf = file_for_call(self.cdev, file);
        let mut pos = off as i64;
        // SAFETY: registered callback reads at most buf.len() bytes from the provided kernel buffer.
        let rc = unsafe { write(&mut lf, buf.as_ptr() as *const c_char, buf.len(), &mut pos) };
        if let Some(file) = file { store_file_private(file, &lf); }
        checked_size(rc)
    }

    fn ops(&self) -> Option<&LinuxFileOperations> {
        if self.ops == 0 { None } else {
            // SAFETY: ops is captured from a live cdev registration.
            Some(unsafe { &*(self.ops as *const LinuxFileOperations) })
        }
    }
}

pub(super) fn allocate_major(base: u32, count: u32) -> Option<u32> {
    for major in LINUX_MAJOR_FIRST_DYNAMIC..=LINUX_MAJOR_MAX {
        if record_major(major, base, count) { return Some(major); }
    }
    None
}

fn record_major(major: u32, base: u32, count: u32) -> bool {
    let mut g = MAJORS.lock();
    if g.iter().flatten().any(|r| ranges_overlap(r.major, r.base, r.count, major, base, count)) {
        return false;
    }
    if let Some(slot) = g.iter_mut().find(|s| s.is_none()) {
        *slot = Some(MajorClaim { major, base, count });
        true
    } else { false }
}

fn remove_major(major: u32, base: u32, count: u32) {
    let mut g = MAJORS.lock();
    if let Some(slot) = g.iter_mut().find(|s| s.is_some_and(|r| r.major == major && r.base == base && r.count == count)) {
        *slot = None;
    }
}

fn record_cdev(cdev: *mut LinuxCdev, major: u32, base: u32, count: u32) -> bool {
    let mut g = CDEVS.lock();
    if let Some(slot) = g.iter_mut().find(|s| s.is_none()) {
        *slot = Some(CdevRegion { cdev: cdev as usize, major, base, count });
        true
    } else { false }
}

fn remove_cdev(cdev: *mut LinuxCdev) -> Option<CdevRegion> {
    let mut g = CDEVS.lock();
    let slot = g.iter_mut().find(|s| s.is_some_and(|r| r.cdev == cdev as usize))?;
    let old = *slot;
    *slot = None;
    old
}

fn cdev_del_by_region(major: u32, base: u32, count: u32) {
    let mut doomed = [0usize; MAX_CDEV_REGIONS];
    let mut n = 0usize;
    {
        let g = CDEVS.lock();
        for r in g.iter().flatten() {
            if r.major == major && r.base == base && r.count == count {
                doomed[n] = r.cdev;
                n += 1;
            }
        }
    }
    for ptr in doomed.iter().take(n) { cdev_del(*ptr as *mut LinuxCdev); }
}

fn region_overlaps(major: u32, base: u32, count: u32) -> bool {
    CDEVS.lock().iter().flatten().any(|r| ranges_overlap(r.major, r.base, r.count, major, base, count))
}

fn ranges_overlap(a_major: u32, a_base: u32, a_count: u32, b_major: u32, b_base: u32, b_count: u32) -> bool {
    if a_major != b_major { return false; }
    let (a0, a1) = (a_base as u64, a_base as u64 + a_count as u64);
    let (b0, b1) = (b_base as u64, b_base as u64 + b_count as u64);
    a0 < b1 && b0 < a1
}

fn inode_for(devt: Devt, cdev: usize) -> LinuxInode {
    LinuxInode { i_rdev: devt.to_kdev(), private: cdev as *mut c_void }
}

fn file_for_call(cdev: usize, file: Option<&File>) -> LinuxFile {
    let private = file.map(|f| f.private_data() as *mut c_void).unwrap_or(cdev as *mut c_void);
    LinuxFile { private_data: private }
}

fn store_file_private(file: &File, lf: &LinuxFile) {
    file.set_private_data(lf.private_data as usize as u64);
}

fn checked_size(rc: isize) -> vfs::KResult<usize> {
    if rc < 0 { Err(errno_to_vfs((-rc) as i32)) } else { Ok(rc as usize) }
}

fn errno(e: VfsError) -> i32 { e as i32 }

fn errno_to_vfs(e: i32) -> VfsError {
    match e {
        LINUX_ENXIO => VfsError::Enxio,
        LINUX_ENODEV => VfsError::Enodev,
        LINUX_ENOMEM => VfsError::Enomem,
        LINUX_EBUSY => VfsError::Ebusy,
        LINUX_EINVAL => VfsError::Einval,
        _ => VfsError::Eio,
    }
}

pub(super) fn volatile_write_u32(p: *mut u32, v: u32) {
    if p.is_null() { return; }
    // SAFETY: caller provided writable u32 storage.
    unsafe { core::ptr::write_volatile(p, v); }
}

#[cfg(test)]
mod tests;
