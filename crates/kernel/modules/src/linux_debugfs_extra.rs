extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ffi::{c_char, c_void};
use core::ptr::null_mut;
use vfs::{FileOps, Inode, KResult, VfsError};

use crate::linux_debugfs::{
    cstr, create_inode_entry, create_path_entry, entry_path, read_bytes_at, regular_inode_size,
    symlink_inode, LinuxDentry, LinuxFile, LinuxInode,
};

const TARGET_MAX: usize = 4096;
const SIMPLE_BUF: usize = 64;

type SimpleGet = unsafe extern "C" fn(*mut c_void, *mut u64) -> i32;
type SimpleSet = unsafe extern "C" fn(*mut c_void, u64) -> i32;

#[repr(C)]
pub struct DebugfsBlobWrapper {
    data: *const c_void,
    size: usize,
}

struct BlobData { wrapper: usize }
struct BlobOps;

impl FileOps for BlobOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<BlobData>().ok_or(VfsError::Einval)?;
        let wrapper = d.wrapper as *const DebugfsBlobWrapper;
        if wrapper.is_null() { return Err(VfsError::Einval); }
        // SAFETY: wrapper is module-owned storage for this debugfs file lifetime.
        let w = unsafe { &*wrapper };
        if w.data.is_null() { return Ok(0); }
        // SAFETY: blob data is caller-owned readable storage of wrapper.size bytes.
        let bytes = unsafe { core::slice::from_raw_parts(w.data as *const u8, w.size) };
        Ok(read_bytes_at(bytes, off, buf))
    }
}

struct SimpleAttr {
    data: *mut c_void,
    get: Option<SimpleGet>,
    set: Option<SimpleSet>,
    fmt: usize,
}

#[no_mangle]
pub extern "C" fn debugfs_create_blob(
    name: *const c_char,
    mode: u16,
    parent: *mut LinuxDentry,
    blob: *mut DebugfsBlobWrapper,
) -> *mut LinuxDentry {
    if blob.is_null() { return null_mut(); }
    // SAFETY: non-null pointer was checked and is module-owned blob descriptor storage.
    let size = unsafe { (*blob).size as u64 };
    let inode = regular_inode_size(mode, Arc::new(BlobOps), Arc::new(BlobData { wrapper: blob as usize }), size);
    create_inode_entry(name, parent, inode)
}

#[no_mangle]
pub extern "C" fn debugfs_create_symlink(
    name: *const c_char,
    parent: *mut LinuxDentry,
    target: *const c_char,
) -> *mut LinuxDentry {
    let path = match entry_path(parent, name) { Some(p) => p, None => return null_mut() };
    let target = match cstr(target, TARGET_MAX) { Some(t) => t, None => return null_mut() };
    let inode = symlink_inode(target.as_bytes());
    create_path_entry(path, inode)
}

#[no_mangle]
pub extern "C" fn simple_attr_open(
    inode: *mut LinuxInode,
    file: *mut LinuxFile,
    get: Option<SimpleGet>,
    set: Option<SimpleSet>,
    fmt: *const c_char,
) -> i32 {
    if file.is_null() { return -22; }
    let data = if inode.is_null() {
        null_mut()
    } else {
        // SAFETY: inode is provided by the active debugfs open path.
        unsafe { (*inode).private }
    };
    let attr = Box::new(SimpleAttr { data, get, set, fmt: fmt as usize });
    // SAFETY: file is non-null and owned by this active open callback.
    unsafe { (*file).private_data = Box::into_raw(attr) as *mut c_void; }
    0
}

#[no_mangle]
pub extern "C" fn simple_attr_read(
    file: *mut LinuxFile,
    buf: *mut c_char,
    count: usize,
    ppos: *mut i64,
) -> isize {
    let attr = match simple_attr(file) { Some(a) => a, None => return -22 };
    let get = match attr.get { Some(g) => g, None => return -22 };
    let mut value = 0u64;
    // SAFETY: callback pointer and data come from module-owned file_operations.
    let rc = unsafe { get(attr.data, &mut value) };
    if rc < 0 { return rc as isize; }
    let mut body = [0u8; SIMPLE_BUF];
    let len = format_simple(value, attr.fmt as *const c_char, &mut body);
    copy_to_user_slice(&body[..len], buf, count, ppos)
}

#[no_mangle]
pub extern "C" fn simple_attr_write(
    file: *mut LinuxFile,
    buf: *const c_char,
    count: usize,
    _ppos: *mut i64,
) -> isize {
    let attr = match simple_attr(file) { Some(a) => a, None => return -22 };
    let set = match attr.set { Some(s) => s, None => return -22 };
    if buf.is_null() { return -22; }
    // SAFETY: debugfs VFS passes a readable kernel buffer of count bytes.
    let bytes = unsafe { core::slice::from_raw_parts(buf as *const u8, count) };
    let value = match parse_u64(bytes) { Some(v) => v, None => return -22 };
    // SAFETY: callback pointer and data come from module-owned file_operations.
    let rc = unsafe { set(attr.data, value) };
    if rc < 0 { rc as isize } else { count as isize }
}

#[no_mangle]
pub extern "C" fn simple_attr_release(_inode: *mut LinuxInode, file: *mut LinuxFile) -> i32 {
    if file.is_null() { return 0; }
    // SAFETY: private_data was allocated by simple_attr_open for this active file.
    let ptr = unsafe { (*file).private_data as *mut SimpleAttr };
    if !ptr.is_null() {
        // SAFETY: pointer was produced by Box::into_raw in simple_attr_open.
        unsafe { drop(Box::from_raw(ptr)); }
        // SAFETY: file is non-null and still owned by release callback.
        unsafe { (*file).private_data = null_mut(); }
    }
    0
}

fn simple_attr(file: *mut LinuxFile) -> Option<&'static SimpleAttr> {
    if file.is_null() { return None; }
    // SAFETY: file is non-null and private_data is managed by simple_attr_open/release.
    let ptr = unsafe { (*file).private_data as *const SimpleAttr };
    if ptr.is_null() { None } else {
        // SAFETY: pointer remains valid until simple_attr_release for this callback.
        Some(unsafe { &*ptr })
    }
}

fn copy_to_user_slice(body: &[u8], buf: *mut c_char, count: usize, ppos: *mut i64) -> isize {
    if buf.is_null() || ppos.is_null() { return -22; }
    // SAFETY: ppos is supplied by VFS caller for this active operation.
    let off = unsafe { *ppos }.max(0) as usize;
    if off >= body.len() { return 0; }
    let n = (body.len() - off).min(count);
    // SAFETY: VFS caller supplies writable output buffer of count bytes.
    unsafe {
        core::ptr::copy_nonoverlapping(body[off..off + n].as_ptr(), buf as *mut u8, n);
        *ppos += n as i64;
    }
    n as isize
}

fn parse_u64(bytes: &[u8]) -> Option<u64> {
    let s = core::str::from_utf8(bytes).ok()?.trim();
    if let Some(hex) = s.strip_prefix("0x") { u64::from_str_radix(hex, 16).ok() } else { s.parse().ok() }
}

fn format_simple(value: u64, fmt: *const c_char, out: &mut [u8; SIMPLE_BUF]) -> usize {
    let hex = cstr(fmt, 32).is_some_and(|s| s.contains('x') || s.contains('X'));
    let mut n = 0;
    if hex { push_radix(value, 16, out, &mut n); } else { push_radix(value, 10, out, &mut n); }
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
    use core::sync::atomic::{AtomicU64, Ordering};

    static SIMPLE_VALUE: AtomicU64 = AtomicU64::new(9);

    unsafe extern "C" fn simple_get(_data: *mut c_void, value: *mut u64) -> i32 {
        // SAFETY: simple_attr passes a valid output pointer to the getter callback.
        unsafe { *value = SIMPLE_VALUE.load(Ordering::Relaxed); }
        0
    }

    unsafe extern "C" fn simple_set(_data: *mut c_void, value: u64) -> i32 {
        SIMPLE_VALUE.store(value, Ordering::Relaxed);
        0
    }

    #[test]
    fn blob_file_reads_back_bytes() {
        let bytes = *b"blob-data";
        let mut blob = DebugfsBlobWrapper { data: bytes.as_ptr() as *const c_void, size: bytes.len() };
        let d = debugfs_create_blob(b"debugfs_blob\0".as_ptr() as *const c_char, 0o400, null_mut(), &mut blob);
        assert!(!d.is_null());
        let inode = tracefs::debug_root().lookup_path("debugfs_blob").expect("blob file");
        let mut buf = [0u8; 16];
        let n = inode.read(0, &mut buf).expect("read blob");
        assert_eq!(&buf[..n], b"blob-data");
        crate::linux_debugfs::debugfs_remove(d);
    }

    #[test]
    fn symlink_entry_is_visible() {
        let d = debugfs_create_symlink(
            b"debugfs_link\0".as_ptr() as *const c_char,
            null_mut(),
            b"debugfs_blob\0".as_ptr() as *const c_char,
        );
        assert!(!d.is_null());
        assert!(tracefs::debug_root().lookup_path("debugfs_link").is_some());
        crate::linux_debugfs::debugfs_remove(d);
    }

    #[test]
    fn simple_attr_round_trips_value() {
        let mut inode = LinuxInode { i_rdev: 0, private: null_mut() };
        let mut file = LinuxFile { private_data: null_mut() };
        assert_eq!(
            simple_attr_open(
                &mut inode,
                &mut file,
                Some(simple_get),
                Some(simple_set),
                b"%llu\n\0".as_ptr() as *const c_char,
            ),
            0,
        );
        let mut pos = 0i64;
        let mut buf = [0i8; 16];
        let n = simple_attr_read(&mut file, buf.as_mut_ptr(), buf.len(), &mut pos);
        assert_eq!(n, 2);
        assert_eq!(buf[0] as u8, b'9');
        let mut wpos = 0i64;
        assert_eq!(simple_attr_write(&mut file, b"42".as_ptr() as *const c_char, 2, &mut wpos), 2);
        assert_eq!(SIMPLE_VALUE.load(Ordering::Relaxed), 42);
        assert_eq!(simple_attr_release(&mut inode, &mut file), 0);
        assert!(file.private_data.is_null());
    }
}
