//! DMA-BUF file ownership and importer attachment ABI.

extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::ffi::{c_char, c_void};
use core::sync::atomic::{AtomicI64, Ordering};

use vfs::{Dentry, File, FileOps, FileType, InodeBuilder, OpenFlags, default_inode_ops, mk_mode};
use vfs::pseudo_ino::RegionAllocator;

const EINVAL: i32 = 22;
const EBADF: i32 = 9;
const ENOMEM: i32 = 12;
const DMA_BUF_NAME: &[u8] = b"[dma-buf]\0";
static NEXT_INO: RegionAllocator = RegionAllocator::new(&vfs::pseudo_ino::DMA_BUF);

type Attach = unsafe extern "C" fn(*mut LinuxDmaBuf, *mut c_void) -> i32;
type Detach = unsafe extern "C" fn(*mut LinuxDmaBuf, *mut DmaBufAttachment);
type Release = unsafe extern "C" fn(*mut LinuxDmaBuf);
type Map = unsafe extern "C" fn(*mut DmaBufAttachment, u32) -> *mut c_void;
type Unmap = unsafe extern "C" fn(*mut DmaBufAttachment, *mut c_void, u32);

#[repr(C)] struct ListHead { next: *mut ListHead, prev: *mut ListHead }
#[repr(C)] struct DmaResv { bytes: [u8; 48] }
#[repr(C)] struct LinuxFile { pad: [u8; 176], f_ref: AtomicI64 }
#[repr(C)] pub struct DmaBufOps {
    attach: Option<Attach>, detach: Option<Detach>, pin: Option<unsafe extern "C" fn(*mut DmaBufAttachment) -> i32>, unpin: Option<unsafe extern "C" fn(*mut DmaBufAttachment)>,
    map_dma_buf: Option<Map>, unmap_dma_buf: Option<Unmap>, release: Option<Release>, begin_cpu_access: Option<unsafe extern "C" fn(*mut LinuxDmaBuf, u32) -> i32>, end_cpu_access: Option<unsafe extern "C" fn(*mut LinuxDmaBuf, u32) -> i32>,
    mmap: Option<unsafe extern "C" fn(*mut LinuxDmaBuf, *mut c_void) -> i32>, vmap: Option<unsafe extern "C" fn(*mut LinuxDmaBuf, *mut c_void) -> i32>, vunmap: Option<unsafe extern "C" fn(*mut LinuxDmaBuf, *mut c_void)>,
}
#[repr(C)] pub struct LinuxDmaBuf {
    size: usize, file: *mut LinuxFile, attachments: ListHead, ops: *const DmaBufOps,
    vmapping_counter: i32, vmap_ptr: [u8; 16], exp_name: *const c_char, name: *const c_char,
    name_lock: usize, owner: *mut c_void, list_node: ListHead, priv_: *mut c_void, resv: *mut DmaResv,
    poll: [u8; 24], cb_in: [u8; 40], cb_out: [u8; 40],
}
#[repr(C)] pub struct DmaBufAttachment {
    dmabuf: *mut LinuxDmaBuf, dev: *mut c_void, node: ListHead, peer2peer: bool, _pad: [u8; 7],
    importer_ops: *const c_void, importer_priv: *mut c_void, priv_: *mut c_void,
}
#[repr(C)] pub struct DmaBufExportInfo { exp_name: *const c_char, owner: *mut c_void, ops: *const DmaBufOps, size: usize, flags: u64, priv_: *mut c_void, resv: *mut DmaResv }
#[repr(C)] struct Owner { buf: LinuxDmaBuf, file: LinuxFile, resv: DmaResv }
const _: () = assert!(core::mem::size_of::<LinuxFile>() == 184);
const _: () = assert!(core::mem::size_of::<DmaBufOps>() == 96);
const _: () = assert!(core::mem::size_of::<LinuxDmaBuf>() == 232);
const _: () = assert!(core::mem::size_of::<DmaBufAttachment>() == 64);

struct DmaBufFileOps;
impl FileOps for DmaBufFileOps {
    fn on_release_file(&self, file: &File) {
        let buf = file.private_data() as *mut LinuxDmaBuf;
        // SAFETY: dma_buf_fd stores exactly one live dma-buf pointer in this anonymous file.
        unsafe { dma_buf_put(buf); }
    }
}

fn err<T>(n: i32) -> *mut T { (-(n as isize)) as usize as *mut T }
fn init_list(h: *mut ListHead) { unsafe { (*h).next = h; (*h).prev = h; } }
unsafe fn owner(buf: *mut LinuxDmaBuf) -> *mut Owner { buf.cast() }
unsafe fn refs(buf: *mut LinuxDmaBuf) -> &'static AtomicI64 { unsafe { &(*(*buf).file).f_ref } }

/// Retain an in-kernel DMA-BUF reference. # C: O(1)
pub(crate) unsafe fn get_ref(buf: *mut LinuxDmaBuf) {
    if !buf.is_null() { unsafe { refs(buf).fetch_add(1, Ordering::AcqRel); } }
}

/// Return the buffer retained by an attachment. # C: O(1)
pub(crate) unsafe fn attachment_buf(a: *mut DmaBufAttachment) -> *mut LinuxDmaBuf { unsafe { (*a).dmabuf } }

/// Export a buffer whose release is tied to its file reference. # C: O(1)
#[unsafe(no_mangle)] pub unsafe extern "C" fn dma_buf_export(info: *const DmaBufExportInfo) -> *mut LinuxDmaBuf {
    if info.is_null() { return err(EINVAL); }
    let i = unsafe { &*info };
    if i.ops.is_null() || i.size == 0 || unsafe { (*i.ops).map_dma_buf }.is_none() || unsafe { (*i.ops).unmap_dma_buf }.is_none() || unsafe { (*i.ops).release }.is_none() { return err(EINVAL); }
    let mut o = Box::new(unsafe { core::mem::zeroed::<Owner>() });
    o.file.f_ref = AtomicI64::new(1);
    o.buf.size = i.size; o.buf.file = &mut o.file; o.buf.ops = i.ops; o.buf.exp_name = if i.exp_name.is_null() { DMA_BUF_NAME.as_ptr().cast() } else { i.exp_name };
    o.buf.owner = i.owner; o.buf.priv_ = i.priv_; o.buf.resv = if i.resv.is_null() { &mut o.resv } else { i.resv };
    let p: *mut LinuxDmaBuf = &mut o.buf;
    unsafe { init_list(&mut (*p).attachments); init_list(&mut (*p).list_node); }
    Box::into_raw(o).cast()
}

/// Install an anonymous DMA-BUF file descriptor, transferring the caller's reference. # C: O(1)
#[unsafe(no_mangle)] pub unsafe extern "C" fn dma_buf_fd(buf: *mut LinuxDmaBuf, flags: u32) -> i32 {
    if buf.is_null() { return -EINVAL; }
    let Some(task) = sched::current() else { return -EINVAL; };
    let Some(table) = task.clone_fd_table() else { return -EINVAL; };
    let inode = InodeBuilder::new(NEXT_INO.alloc(), mk_mode(FileType::Regular, 0o600), default_inode_ops(), Arc::new(DmaBufFileOps)).build();
    let file = File::new(inode.clone(), Dentry::new_root(inode), OpenFlags::from_bits_retain(flags));
    file.set_private_data(buf as u64);
    match table.install_limit(file, OpenFlags::from_bits_retain(flags), task.nofile_soft()) { Ok(fd) => fd, Err(_) => -ENOMEM }
}

/// Resolve and retain a DMA-BUF descriptor. # C: O(1)
#[unsafe(no_mangle)] pub unsafe extern "C" fn dma_buf_get(fd: i32) -> *mut LinuxDmaBuf {
    let Some(task) = sched::current() else { return err(EBADF); };
    let Some(table) = task.clone_fd_table() else { return err(EBADF); };
    let Ok(file) = table.get(fd) else { return err(EBADF); };
    let buf = file.private_data() as *mut LinuxDmaBuf;
    if buf.is_null() { return err(EINVAL); }
    unsafe { get_ref(buf); }
    buf
}

/// Drop one DMA-BUF file reference and invoke exporter release at final put. # C: O(1)
#[unsafe(no_mangle)] pub unsafe extern "C" fn dma_buf_put(buf: *mut LinuxDmaBuf) {
    if buf.is_null() { return; }
    if unsafe { refs(buf).fetch_sub(1, Ordering::AcqRel) } != 1 { return; }
    let release = unsafe { (*(*buf).ops).release };
    if let Some(f) = release { unsafe { f(buf); } }
    unsafe { drop(Box::from_raw(owner(buf))); }
}

/// Attach an importer; exporter attach runs before publication to the importer. # C: O(1)
#[unsafe(no_mangle)] pub unsafe extern "C" fn dma_buf_dynamic_attach(buf: *mut LinuxDmaBuf, dev: *mut c_void, importer_ops: *const c_void, importer_priv: *mut c_void) -> *mut DmaBufAttachment {
    if buf.is_null() || dev.is_null() { return err(EINVAL); }
    let mut a = Box::new(unsafe { core::mem::zeroed::<DmaBufAttachment>() });
    a.dmabuf = buf; a.dev = dev; a.importer_ops = importer_ops; a.importer_priv = importer_priv;
    if let Some(f) = unsafe { (*(*buf).ops).attach } { let r = unsafe { f(buf, dev) }; if r != 0 { return err((-r) as i32); } }
    Box::into_raw(a)
}

/// Attach with no importer-private owner. # C: O(1)
#[unsafe(no_mangle)] pub unsafe extern "C" fn dma_buf_attach(buf: *mut LinuxDmaBuf, dev: *mut c_void) -> *mut DmaBufAttachment { unsafe { dma_buf_dynamic_attach(buf, dev, core::ptr::null(), core::ptr::null_mut()) } }

/// Detach an importer and return its allocation only after exporter teardown. # C: O(1)
#[unsafe(no_mangle)] pub unsafe extern "C" fn dma_buf_detach(buf: *mut LinuxDmaBuf, a: *mut DmaBufAttachment) {
    if buf.is_null() || a.is_null() { return; }
    if unsafe { (*a).dmabuf } != buf { return; }
    if let Some(f) = unsafe { (*(*buf).ops).detach } { unsafe { f(buf, a); } }
    unsafe { drop(Box::from_raw(a)); }
}

/// Register DMA-BUF ABI symbols used by DRM PRIME importers. # C: O(1)
pub fn export_symbols() {
    for (n, p) in [("dma_buf_export", dma_buf_export as *const () as usize), ("dma_buf_fd", dma_buf_fd as *const () as usize), ("dma_buf_get", dma_buf_get as *const () as usize), ("dma_buf_put", dma_buf_put as *const () as usize), ("dma_buf_dynamic_attach", dma_buf_dynamic_attach as *const () as usize), ("dma_buf_attach", dma_buf_attach as *const () as usize), ("dma_buf_detach", dma_buf_detach as *const () as usize)] { crate::symtab::export(n, p, false); }
}
