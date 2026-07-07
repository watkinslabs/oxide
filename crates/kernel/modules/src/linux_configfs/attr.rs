extern crate alloc;

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::ffi::c_char;
use core::ptr::null_mut;
use sync::{Modules as ModulesLockClass, RwLock, Spinlock};
use vfs::{File, FileOps, Fmode, Inode, KResult, VfsError};

use super::{attr_ref, bin_attr_ref, config_item_get, config_item_put, ConfigItem};
use crate::linux_configfs::util::{checked_size, read_at};

const SIMPLE_ATTR_SIZE: usize = 4096;

pub(super) struct AttrData {
    pub(super) item: usize,
    pub(super) attr: usize,
    pub(super) frag: Arc<RwLock<bool, ModulesLockClass>>,
}

struct ActiveAttrFile {
    item: usize,
    attr: usize,
    frag: Arc<RwLock<bool, ModulesLockClass>>,
    state: Spinlock<AttrFileState, ModulesLockClass>,
}

struct AttrFileState {
    page: Vec<u8>,
    count: usize,
    needs_read_fill: bool,
}

impl ActiveAttrFile {
    fn new(item: usize, attr: usize, frag: Arc<RwLock<bool, ModulesLockClass>>) -> Self {
        Self {
            item,
            attr,
            frag,
            state: Spinlock::new(AttrFileState { page: Vec::new(), count: 0, needs_read_fill: true }),
        }
    }

    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let mut state = self.state.lock();
        if state.needs_read_fill { self.fill_read_buffer(&mut state)?; }
        Ok(read_at(&state.page[..state.count], off, buf))
    }

    fn write(&self, buf: &[u8]) -> KResult<usize> {
        let attr = attr_ref(self.attr).ok_or(VfsError::Einval)?;
        let store = attr.store.ok_or(VfsError::Einval)?;
        let copied = buf.len().min(SIMPLE_ATTR_SIZE - 1);
        let mut page = Vec::new();
        page.resize(copied + 1, 0);
        page[..copied].copy_from_slice(&buf[..copied]);
        let dead = self.frag.read();
        if *dead { return Err(VfsError::Enoent); }
        let _item_ref = ActiveItemRef::get(self.item as *mut ConfigItem);
        // SAFETY: configfs attribute callback receives a live item pinned for this operation and a NUL-terminated kernel buffer.
        checked_size(unsafe { store(self.item as *mut ConfigItem, page.as_ptr() as *const c_char, copied) })
    }

    fn fill_read_buffer(&self, state: &mut AttrFileState) -> KResult<()> {
        let attr = attr_ref(self.attr).ok_or(VfsError::Einval)?;
        let show = attr.show.ok_or(VfsError::Einval)?;
        if state.page.len() < SIMPLE_ATTR_SIZE { state.page.resize(SIMPLE_ATTR_SIZE, 0); }
        let dead = self.frag.read();
        if *dead { return Err(VfsError::Enoent); }
        let _item_ref = ActiveItemRef::get(self.item as *mut ConfigItem);
        // SAFETY: configfs attribute callback receives a live item pinned for this operation and a page-sized kernel buffer.
        let n = checked_size(unsafe { show(self.item as *mut ConfigItem, state.page.as_mut_ptr() as *mut c_char) })?;
        if n > SIMPLE_ATTR_SIZE { return Err(VfsError::Eio); }
        state.count = n;
        state.needs_read_fill = false;
        Ok(())
    }
}

struct ActiveItemRef {
    item: *mut ConfigItem,
}

impl ActiveItemRef {
    fn get(item: *mut ConfigItem) -> Self {
        config_item_get(item);
        Self { item }
    }
}

impl Drop for ActiveItemRef {
    fn drop(&mut self) {
        config_item_put(self.item);
    }
}

pub(super) struct AttrOps;
impl FileOps for AttrOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<AttrData>().ok_or(VfsError::Einval)?;
        let active = ActiveAttrFile::new(d.item, d.attr, Arc::clone(&d.frag));
        active.read(off, buf)
    }

    fn write(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        let d = inode.private::<AttrData>().ok_or(VfsError::Einval)?;
        let active = ActiveAttrFile::new(d.item, d.attr, Arc::clone(&d.frag));
        active.write(buf)
    }

    fn on_open_file(&self, file: &File) -> KResult<()> {
        let d = file.inode().private::<AttrData>().ok_or(VfsError::Einval)?;
        let attr = attr_ref(d.attr).ok_or(VfsError::Einval)?;
        if *d.frag.read() { return Err(VfsError::Enoent); }
        if file.f_mode().contains(Fmode::READ) && attr.show.is_none() { return Err(VfsError::Eacces); }
        if file.f_mode().contains(Fmode::WRITE) && attr.store.is_none() { return Err(VfsError::Eacces); }
        let active = Box::new(ActiveAttrFile::new(d.item, d.attr, Arc::clone(&d.frag)));
        file.set_private_data(Box::into_raw(active) as u64);
        Ok(())
    }

    fn read_file(&self, file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> {
        active_attr_file(file)?.read(off, buf)
    }

    fn write_file(&self, file: &File, _off: u64, buf: &[u8]) -> KResult<usize> {
        active_attr_file(file)?.write(buf)
    }

    fn on_release_file(&self, file: &File) {
        let ptr = file.private_data() as *mut ActiveAttrFile;
        if ptr.is_null() { return; }
        file.set_private_data(0);
        // SAFETY: pointer was installed by on_open_file for this File and is cleared before dropping.
        unsafe { drop(Box::from_raw(ptr)); }
    }
}

pub(super) struct BinAttrData {
    pub(super) item: usize,
    pub(super) attr: usize,
    pub(super) frag: Arc<RwLock<bool, ModulesLockClass>>,
}

struct ActiveBinAttrFile {
    item: usize,
    attr: usize,
    frag: Arc<RwLock<bool, ModulesLockClass>>,
    state: Spinlock<BinAttrFileState, ModulesLockClass>,
}

struct BinAttrFileState {
    read_in_progress: bool,
    write_in_progress: bool,
    needs_read_fill: bool,
    bin_buffer: Vec<u8>,
}

impl ActiveBinAttrFile {
    fn new(item: usize, attr: usize, frag: Arc<RwLock<bool, ModulesLockClass>>) -> Self {
        Self {
            item,
            attr,
            frag,
            state: Spinlock::new(BinAttrFileState {
                read_in_progress: false,
                write_in_progress: false,
                needs_read_fill: true,
                bin_buffer: Vec::new(),
            }),
        }
    }

    fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let mut state = self.state.lock();
        if state.write_in_progress { return Err(VfsError::Etxtbsy); }
        state.read_in_progress = true;
        let attr = bin_attr_ref(self.attr).ok_or(VfsError::Einval)?;
        let read = attr.read.ok_or(VfsError::Einval)?;
        let dead = self.frag.read();
        if *dead { return Err(VfsError::Enoent); }
        let _item_ref = ActiveItemRef::get(self.item as *mut ConfigItem);
        // SAFETY: configfs bin attr callback receives a live item pinned for this operation and a VFS-owned output buffer.
        checked_size(unsafe {
            read(self.item as *mut ConfigItem, attr.private, null_mut(), buf.as_mut_ptr() as *mut c_char, off as i64, buf.len())
        })
    }

    fn write(&self, off: u64, buf: &[u8]) -> KResult<usize> {
        let mut state = self.state.lock();
        if state.read_in_progress { return Err(VfsError::Etxtbsy); }
        state.write_in_progress = true;
        let attr = bin_attr_ref(self.attr).ok_or(VfsError::Einval)?;
        let end = (off as usize).checked_add(buf.len()).ok_or(VfsError::Efbig)?;
        if attr.size != 0 && end > attr.size { return Err(VfsError::Efbig); }
        if state.bin_buffer.len() < end { state.bin_buffer.resize(end, 0); }
        state.bin_buffer[off as usize..end].copy_from_slice(buf);
        state.needs_read_fill = true;
        Ok(buf.len())
    }

    fn flush_write_on_release(&self) {
        let state = self.state.lock();
        if !state.write_in_progress { return; }
        let Some(attr) = bin_attr_ref(self.attr) else { return; };
        let Some(write) = attr.write else { return; };
        let dead = self.frag.read();
        if *dead { return; }
        let _item_ref = ActiveItemRef::get(self.item as *mut ConfigItem);
        // SAFETY: release flush runs before dropping this open buffer and passes the accumulated kernel buffer.
        let _ = unsafe {
            write(
                self.item as *mut ConfigItem,
                attr.private,
                null_mut(),
                state.bin_buffer.as_ptr() as *const c_char,
                0,
                state.bin_buffer.len(),
            )
        };
    }
}

pub(super) struct BinAttrOps;
impl FileOps for BinAttrOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let d = inode.private::<BinAttrData>().ok_or(VfsError::Einval)?;
        let active = ActiveBinAttrFile::new(d.item, d.attr, Arc::clone(&d.frag));
        active.read(off, buf)
    }

    fn write(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        let d = inode.private::<BinAttrData>().ok_or(VfsError::Einval)?;
        let active = ActiveBinAttrFile::new(d.item, d.attr, Arc::clone(&d.frag));
        active.write(off, buf)
    }

    fn on_open_file(&self, file: &File) -> KResult<()> {
        let d = file.inode().private::<BinAttrData>().ok_or(VfsError::Einval)?;
        let attr = bin_attr_ref(d.attr).ok_or(VfsError::Einval)?;
        if *d.frag.read() { return Err(VfsError::Enoent); }
        if file.f_mode().contains(Fmode::READ) && attr.read.is_none() { return Err(VfsError::Eacces); }
        if file.f_mode().contains(Fmode::WRITE) && attr.write.is_none() { return Err(VfsError::Eacces); }
        let active = Box::new(ActiveBinAttrFile::new(d.item, d.attr, Arc::clone(&d.frag)));
        file.set_private_data(Box::into_raw(active) as u64);
        Ok(())
    }

    fn read_file(&self, file: &File, off: u64, buf: &mut [u8]) -> KResult<usize> {
        active_bin_attr_file(file)?.read(off, buf)
    }

    fn write_file(&self, file: &File, off: u64, buf: &[u8]) -> KResult<usize> {
        active_bin_attr_file(file)?.write(off, buf)
    }

    fn on_release_file(&self, file: &File) {
        let ptr = file.private_data() as *mut ActiveBinAttrFile;
        if ptr.is_null() { return; }
        file.set_private_data(0);
        // SAFETY: pointer was installed by on_open_file for this File and is cleared before dropping.
        let active = unsafe { Box::from_raw(ptr) };
        active.flush_write_on_release();
    }
}

fn active_attr_file(file: &File) -> KResult<&'static ActiveAttrFile> {
    let ptr = file.private_data() as *const ActiveAttrFile;
    if ptr.is_null() { return Err(VfsError::Einval); }
    // SAFETY: private_data owns an ActiveAttrFile from on_open_file until on_release_file.
    Ok(unsafe { &*ptr })
}

fn active_bin_attr_file(file: &File) -> KResult<&'static ActiveBinAttrFile> {
    let ptr = file.private_data() as *const ActiveBinAttrFile;
    if ptr.is_null() { return Err(VfsError::Einval); }
    // SAFETY: private_data owns an ActiveBinAttrFile from on_open_file until on_release_file.
    Ok(unsafe { &*ptr })
}
