extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use core::ffi::{c_char, c_void};
use core::ptr::null_mut;
use sync::{Modules as ModulesLockClass, Spinlock};
use vfs::{default_inode_ops, mk_mode, FileOps, FileType, Inode, InodeBuilder, InodeRef, KResult, VfsError};

const NAME_MAX: usize = 255;
const DENTRY_MAGIC: u32 = 0x4442_4746;
const DEBUGFS_ROOT: u8 = 1;
const DEFAULT_FILE_MODE: u16 = 0o600;
const DEFAULT_DIR_MODE: u16 = 0o755;

static NEXT_INO: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0x6d00_0000);
static LOCK: Spinlock<(), ModulesLockClass> = Spinlock::new(());

#[repr(C)]
pub struct LinuxFile { pub(crate) private_data: *mut c_void }

#[repr(C)]
pub struct LinuxInode {
    pub(crate) i_rdev: u32,
    pub(crate) private: *mut c_void,
}

pub(crate) type LinuxRead = unsafe extern "C" fn(*mut LinuxFile, *mut c_char, usize, *mut i64) -> isize;
pub(crate) type LinuxWrite = unsafe extern "C" fn(*mut LinuxFile, *const c_char, usize, *mut i64) -> isize;
pub(crate) type LinuxOpen = unsafe extern "C" fn(*mut LinuxInode, *mut LinuxFile) -> i32;
pub(crate) type LinuxRelease = unsafe extern "C" fn(*mut LinuxInode, *mut LinuxFile) -> i32;
pub(crate) type LinuxIoctl = unsafe extern "C" fn(*mut LinuxFile, u32, usize) -> isize;

#[repr(C)]
pub struct LinuxFileOperations {
    pub(crate) owner: *mut c_void,
    pub(crate) open: Option<LinuxOpen>,
    pub(crate) read: Option<LinuxRead>,
    pub(crate) write: Option<LinuxWrite>,
    pub(crate) unlocked_ioctl: Option<LinuxIoctl>,
    pub(crate) release: Option<LinuxRelease>,
    pub(crate) poll: Option<unsafe extern "C" fn(*mut LinuxFile, *mut c_void) -> u32>,
    pub(crate) mmap: Option<unsafe extern "C" fn(*mut LinuxFile, *mut c_void) -> i32>,
    pub(crate) llseek: *mut c_void,
}

unsafe impl Sync for LinuxFileOperations {}

#[repr(C)]
pub struct LinuxDentry {
    magic: u32,
    root: u8,
    path: String,
}

#[derive(Copy, Clone)]
enum NumKind { U8, U16, U32, U64, Bool }

struct NumData { ptr: usize, kind: NumKind, hex: bool }
struct NumOps;
impl FileOps for NumOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<NumData>().ok_or(VfsError::Einval)?;
        let mut body = [0u8; 34];
        let n = format_num(read_num(d), d.hex, &mut body);
        Ok(read_at(&body[..n], off, buf))
    }

    fn write(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        let d = inode.private::<NumData>().ok_or(VfsError::Einval)?;
        let v = parse_num(buf).ok_or(VfsError::Einval)?;
        write_num(d, v);
        Ok(buf.len())
    }
}

/// Register Linux debugfs KPI symbols. # C: O(1)
pub fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("debugfs_create_dir",       debugfs_create_dir       as *const () as usize),
        ("debugfs_create_file",      debugfs_create_file      as *const () as usize),
        ("debugfs_create_file_size", debugfs_create_file_size as *const () as usize),
        ("debugfs_create_u8",        debugfs_create_u8        as *const () as usize),
        ("debugfs_create_u16",       debugfs_create_u16       as *const () as usize),
        ("debugfs_create_u32",       debugfs_create_u32       as *const () as usize),
        ("debugfs_create_u64",       debugfs_create_u64       as *const () as usize),
        ("debugfs_create_x8",        debugfs_create_x8        as *const () as usize),
        ("debugfs_create_x16",       debugfs_create_x16       as *const () as usize),
        ("debugfs_create_x32",       debugfs_create_x32       as *const () as usize),
        ("debugfs_create_x64",       debugfs_create_x64       as *const () as usize),
        ("debugfs_create_bool",      debugfs_create_bool      as *const () as usize),
        ("debugfs_create_automount", crate::linux_debugfs_automount::debugfs_create_automount as *const () as usize),
        ("debugfs_create_blob",      crate::linux_debugfs_extra::debugfs_create_blob as *const () as usize),
        ("debugfs_create_symlink",   crate::linux_debugfs_extra::debugfs_create_symlink as *const () as usize),
        ("simple_attr_open",         crate::linux_debugfs_extra::simple_attr_open as *const () as usize),
        ("simple_attr_read",         crate::linux_debugfs_extra::simple_attr_read as *const () as usize),
        ("simple_attr_write",        crate::linux_debugfs_extra::simple_attr_write as *const () as usize),
        ("simple_attr_release",      crate::linux_debugfs_extra::simple_attr_release as *const () as usize),
        ("debugfs_remove",           debugfs_remove           as *const () as usize),
        ("debugfs_remove_recursive", debugfs_remove_recursive as *const () as usize),
        ("debugfs_lookup",           debugfs_lookup           as *const () as usize),
        ("debugfs_initialized",      debugfs_initialized      as *const () as usize),
    ] { export(name, addr, false); }
    export("debugfs_create_regset32", crate::linux_debugfs_extra::debugfs_create_regset32 as *const () as usize, true);
    export("debugfs_print_regs32",    crate::linux_debugfs_extra::debugfs_print_regs32    as *const () as usize, true);
}

extern "C" fn debugfs_initialized() -> i32 { 1 }

extern "C" fn debugfs_create_dir(name: *const c_char, parent: *mut LinuxDentry) -> *mut LinuxDentry {
    create_entry(name, parent, None, DEFAULT_DIR_MODE, true)
}

pub(crate) extern "C" fn debugfs_create_file(
    name: *const c_char,
    mode: u16,
    parent: *mut LinuxDentry,
    data: *mut c_void,
    fops: *const LinuxFileOperations,
) -> *mut LinuxDentry {
    let inode = crate::linux_debugfs_file::debug_file_inode(mode, data, file_ops_or_noop(fops), 0);
    create_entry(name, parent, Some(inode), mode, false)
}

extern "C" fn debugfs_create_file_size(
    name: *const c_char,
    mode: u16,
    parent: *mut LinuxDentry,
    data: *mut c_void,
    fops: *const LinuxFileOperations,
    size: u64,
) -> *mut LinuxDentry {
    let inode = crate::linux_debugfs_file::debug_file_inode(mode, data, file_ops_or_noop(fops), size);
    create_entry(name, parent, Some(inode), mode, false)
}

extern "C" fn debugfs_create_u8(name: *const c_char, mode: u16, parent: *mut LinuxDentry, value: *mut u8) -> *mut LinuxDentry {
    create_num(name, mode, parent, value as usize, NumKind::U8, false)
}
extern "C" fn debugfs_create_u16(name: *const c_char, mode: u16, parent: *mut LinuxDentry, value: *mut u16) -> *mut LinuxDentry {
    create_num(name, mode, parent, value as usize, NumKind::U16, false)
}
extern "C" fn debugfs_create_u32(name: *const c_char, mode: u16, parent: *mut LinuxDentry, value: *mut u32) -> *mut LinuxDentry {
    create_num(name, mode, parent, value as usize, NumKind::U32, false)
}
extern "C" fn debugfs_create_u64(name: *const c_char, mode: u16, parent: *mut LinuxDentry, value: *mut u64) -> *mut LinuxDentry {
    create_num(name, mode, parent, value as usize, NumKind::U64, false)
}
extern "C" fn debugfs_create_x8(name: *const c_char, mode: u16, parent: *mut LinuxDentry, value: *mut u8) -> *mut LinuxDentry {
    create_num(name, mode, parent, value as usize, NumKind::U8, true)
}
extern "C" fn debugfs_create_x16(name: *const c_char, mode: u16, parent: *mut LinuxDentry, value: *mut u16) -> *mut LinuxDentry {
    create_num(name, mode, parent, value as usize, NumKind::U16, true)
}
extern "C" fn debugfs_create_x32(name: *const c_char, mode: u16, parent: *mut LinuxDentry, value: *mut u32) -> *mut LinuxDentry {
    create_num(name, mode, parent, value as usize, NumKind::U32, true)
}
extern "C" fn debugfs_create_x64(name: *const c_char, mode: u16, parent: *mut LinuxDentry, value: *mut u64) -> *mut LinuxDentry {
    create_num(name, mode, parent, value as usize, NumKind::U64, true)
}
extern "C" fn debugfs_create_bool(name: *const c_char, mode: u16, parent: *mut LinuxDentry, value: *mut bool) -> *mut LinuxDentry {
    create_num(name, mode, parent, value as usize, NumKind::Bool, false)
}

extern "C" fn debugfs_lookup(name: *const c_char, parent: *mut LinuxDentry) -> *mut LinuxDentry {
    let path = match child_path(parent_path(parent), name) { Some(p) => p, None => return null_mut() };
    if tracefs::debug_root().lookup_path(&path).is_none() { return null_mut(); }
    Box::into_raw(Box::new(LinuxDentry { magic: DENTRY_MAGIC, root: DEBUGFS_ROOT, path }))
}

pub(crate) extern "C" fn debugfs_remove(dentry: *mut LinuxDentry) { remove_dentry(dentry); }
extern "C" fn debugfs_remove_recursive(dentry: *mut LinuxDentry) { remove_dentry(dentry); }

fn create_num(name: *const c_char, mode: u16, parent: *mut LinuxDentry, ptr: usize, kind: NumKind, hex: bool) -> *mut LinuxDentry {
    if ptr == 0 { return null_mut(); }
    let data = NumData { ptr, kind, hex };
    let inode = regular_inode(mode, Arc::new(NumOps), Arc::new(data));
    create_entry(name, parent, Some(inode), mode, false)
}

fn create_entry(name: *const c_char, parent: *mut LinuxDentry, inode: Option<InodeRef>, mode: u16, is_dir: bool) -> *mut LinuxDentry {
    let path = match child_path(parent_path(parent), name) { Some(p) => p, None => return null_mut() };
    let _g = LOCK.lock();
    if is_dir {
        tracefs::debug_root().ensure_dir_path(&path);
    } else {
        tracefs::debug_root().insert_path(&path, inode.unwrap_or_else(|| empty_file(mode)));
    }
    Box::into_raw(Box::new(LinuxDentry { magic: DENTRY_MAGIC, root: DEBUGFS_ROOT, path }))
}

pub(crate) fn create_inode_entry(name: *const c_char, parent: *mut LinuxDentry, inode: InodeRef) -> *mut LinuxDentry {
    create_entry(name, parent, Some(inode), DEFAULT_FILE_MODE, false)
}

pub(crate) fn create_path_entry(path: String, inode: InodeRef) -> *mut LinuxDentry {
    let _g = LOCK.lock();
    tracefs::debug_root().insert_path(&path, inode);
    dentry_handle(path)
}

pub(crate) fn dentry_handle(path: String) -> *mut LinuxDentry {
    Box::into_raw(Box::new(LinuxDentry { magic: DENTRY_MAGIC, root: DEBUGFS_ROOT, path }))
}

pub(crate) fn entry_path(parent: *mut LinuxDentry, name: *const c_char) -> Option<String> {
    child_path(parent_path(parent), name)
}

fn remove_dentry(dentry: *mut LinuxDentry) {
    if dentry.is_null() { return; }
    // SAFETY: dentry is a handle returned by this module's create/lookup API.
    let d = unsafe { Box::from_raw(dentry) };
    if d.magic == DENTRY_MAGIC && d.root == DEBUGFS_ROOT {
        let _g = LOCK.lock();
        tracefs::debug_root().remove_subtree(&d.path);
    }
}

fn parent_path(parent: *mut LinuxDentry) -> Option<String> {
    if parent.is_null() { return Some(String::new()); }
    // SAFETY: parent is expected to be a LinuxDentry handle returned by this module.
    let p = unsafe { &*parent };
    if p.magic != DENTRY_MAGIC || p.root != DEBUGFS_ROOT { return None; }
    Some(p.path.clone())
}

fn child_path(parent: Option<String>, name: *const c_char) -> Option<String> {
    let mut p = parent?;
    let n = read_cstr(name, NAME_MAX)?;
    if n.is_empty() || n.as_bytes().iter().any(|b| *b == b'/') { return None; }
    if !p.is_empty() { p.push('/'); }
    p.push_str(&n);
    Some(p)
}

fn read_cstr(ptr: *const c_char, max: usize) -> Option<String> {
    if ptr.is_null() { return None; }
    let mut bytes = alloc::vec::Vec::new();
    for i in 0..=max {
        // SAFETY: caller passes a NUL-terminated C string; bounded scan avoids unbounded reads.
        let b = unsafe { *ptr.add(i) } as u8;
        if b == 0 { return String::from_utf8(bytes).ok(); }
        bytes.push(b);
    }
    None
}

fn regular_inode(mode: u16, ops: Arc<dyn FileOps>, data: Arc<dyn core::any::Any + Send + Sync>) -> InodeRef {
    regular_inode_size(mode, ops, data, 0)
}

pub(crate) fn regular_inode_size(mode: u16, ops: Arc<dyn FileOps>, data: Arc<dyn core::any::Any + Send + Sync>, size: u64) -> InodeRef {
    let perm = if mode == 0 { DEFAULT_FILE_MODE } else { mode & 0o777 };
    InodeBuilder::new(
        NEXT_INO.fetch_add(1, core::sync::atomic::Ordering::Relaxed),
        mk_mode(FileType::Regular, perm),
        default_inode_ops(),
        ops,
    ).size(size).private(data).build()
}

fn empty_file(mode: u16) -> InodeRef {
    regular_inode(mode, Arc::new(EmptyOps), Arc::new(()))
}

struct EmptyOps;
impl FileOps for EmptyOps {
    fn read(&self, _inode: &Inode, _off: u64, _buf: &mut [u8]) -> KResult<usize> { Ok(0) }
    fn write(&self, _inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> { Ok(buf.len()) }
}

pub(crate) fn linux_ops(ptr: usize) -> Option<&'static LinuxFileOperations> {
    if ptr == 0 { None } else {
        // SAFETY: pointer comes from module-owned static file_operations.
        Some(unsafe { &*(ptr as *const LinuxFileOperations) })
    }
}

pub(crate) fn read_bytes_at(body: &[u8], off: u64, buf: &mut [u8]) -> usize {
    read_at(body, off, buf)
}

pub(crate) fn cstr(ptr: *const c_char, max: usize) -> Option<String> {
    read_cstr(ptr, max)
}

pub(crate) fn symlink_inode(target: &[u8]) -> InodeRef {
    InodeBuilder::new(
        NEXT_INO.fetch_add(1, core::sync::atomic::Ordering::Relaxed),
        mk_mode(FileType::Symlink, 0o777),
        default_inode_ops(),
        vfs::default_file_ops(),
    ).size(target.len() as u64).link(target.to_vec().into_boxed_slice()).build()
}

fn file_ops_or_noop(fops: *const LinuxFileOperations) -> *const LinuxFileOperations {
    if fops.is_null() { &NULL_FILE_OPS } else { fops }
}

unsafe extern "C" fn noop_read(
    _file: *mut LinuxFile,
    _buf: *mut c_char,
    _len: usize,
    _pos: *mut i64,
) -> isize { 0 }

unsafe extern "C" fn noop_write(
    _file: *mut LinuxFile,
    _buf: *const c_char,
    len: usize,
    _pos: *mut i64,
) -> isize { len as isize }

pub(crate) static NULL_FILE_OPS: LinuxFileOperations = LinuxFileOperations {
    owner: null_mut(),
    open: None,
    read: Some(noop_read),
    write: Some(noop_write),
    unlocked_ioctl: None,
    release: None,
    poll: None,
    mmap: None,
    llseek: null_mut(),
};

pub(crate) fn checked_size(v: isize) -> KResult<usize> {
    if v < 0 { Err(errno_to_vfs((-v) as i32)) } else { Ok(v as usize) }
}

pub(crate) fn errno_to_vfs(e: i32) -> VfsError {
    match e {
        2 => VfsError::Enoent,
        12 => VfsError::Enomem,
        13 => VfsError::Eacces,
        16 => VfsError::Ebusy,
        22 => VfsError::Einval,
        _ => VfsError::Eio,
    }
}

fn read_at(body: &[u8], off: u64, buf: &mut [u8]) -> usize {
    let off = off as usize;
    if off >= body.len() { return 0; }
    let n = (body.len() - off).min(buf.len());
    buf[..n].copy_from_slice(&body[off..off + n]);
    n
}

fn read_num(d: &NumData) -> u64 {
    // SAFETY: numeric helper pointers are caller-owned kernel scalars for the file lifetime.
    unsafe {
        match d.kind {
            NumKind::U8 => *(d.ptr as *const u8) as u64,
            NumKind::U16 => *(d.ptr as *const u16) as u64,
            NumKind::U32 => *(d.ptr as *const u32) as u64,
            NumKind::U64 => *(d.ptr as *const u64),
            NumKind::Bool => *(d.ptr as *const bool) as u64,
        }
    }
}

fn write_num(d: &NumData, v: u64) {
    // SAFETY: numeric helper pointers are caller-owned kernel scalars for the file lifetime.
    unsafe {
        match d.kind {
            NumKind::U8 => *(d.ptr as *mut u8) = v as u8,
            NumKind::U16 => *(d.ptr as *mut u16) = v as u16,
            NumKind::U32 => *(d.ptr as *mut u32) = v as u32,
            NumKind::U64 => *(d.ptr as *mut u64) = v,
            NumKind::Bool => *(d.ptr as *mut bool) = v != 0,
        }
    }
}

fn parse_num(buf: &[u8]) -> Option<u64> {
    let s = core::str::from_utf8(buf).ok()?.trim();
    if let Some(hex) = s.strip_prefix("0x") { u64::from_str_radix(hex, 16).ok() } else { s.parse().ok() }
}

fn format_num(v: u64, hex: bool, out: &mut [u8; 34]) -> usize {
    let mut n = 0;
    if hex {
        out[0] = b'0';
        out[1] = b'x';
        n = 2;
        push_radix(v, 16, out, &mut n);
    } else {
        push_radix(v, 10, &mut out[..32], &mut n);
    }
    out[n] = b'\n';
    n + 1
}

fn push_radix(mut v: u64, radix: u64, out: &mut [u8], n: &mut usize) {
    let mut tmp = [0u8; 16];
    let mut i = tmp.len();
    loop {
        i -= 1;
        let d = (v % radix) as u8;
        tmp[i] = if d < 10 { b'0' + d } else { b'a' + d - 10 };
        v /= radix;
        if v == 0 { break; }
    }
    for b in &tmp[i..] { out[*n] = *b; *n += 1; }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_symbols_registers_debugfs_surface() {
        export_symbols();
        assert!(crate::is_exported("debugfs_create_dir"));
        assert!(crate::is_exported("debugfs_create_file"));
        assert!(crate::is_exported("debugfs_create_automount"));
        assert!(crate::is_exported("debugfs_remove_recursive"));
    }

    #[test]
    fn numeric_file_round_trips() {
        let mut v = 7u32;
        let name = b"debugfs_num\0";
        let d = debugfs_create_u32(name.as_ptr() as *const c_char, 0o600, null_mut(), &mut v);
        assert!(!d.is_null());
        let inode = tracefs::debug_root().lookup_path("debugfs_num").expect("debugfs numeric file");
        let mut buf = [0u8; 16];
        let n = inode.read(0, &mut buf).expect("read numeric");
        assert_eq!(&buf[..n], b"7\n");
        assert_eq!(inode.write(0, b"11"), Ok(2));
        assert_eq!(v, 11);
        debugfs_remove(d);
        assert!(tracefs::debug_root().lookup_path("debugfs_num").is_none());
    }

    #[test]
    fn null_fops_create_noop_files() {
        let name = b"debugfs_null_fops\0";
        let d = debugfs_create_file(
            name.as_ptr() as *const c_char,
            0o600,
            null_mut(),
            null_mut(),
            core::ptr::null(),
        );
        assert!(!d.is_null());
        let inode = tracefs::debug_root().lookup_path("debugfs_null_fops").expect("debugfs null-fops file");
        let mut buf = [0u8; 8];
        assert_eq!(inode.read(0, &mut buf), Ok(0));
        assert_eq!(inode.write(0, b"ignored"), Ok(7));
        debugfs_remove(d);

        let size_name = b"debugfs_null_fops_size\0";
        let sized = debugfs_create_file_size(
            size_name.as_ptr() as *const c_char,
            0o400,
            null_mut(),
            null_mut(),
            core::ptr::null(),
            4096,
        );
        assert!(!sized.is_null());
        let inode = tracefs::debug_root().lookup_path("debugfs_null_fops_size").expect("sized null-fops file");
        assert_eq!(inode.size(), 4096);
        debugfs_remove(sized);
    }

}
