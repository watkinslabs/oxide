extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Devices as FsClass, Spinlock};

use crate::superblock::FileSystemType;
use crate::types::VfsError;

use super::api::{FsType, KResult};

static FILESYSTEMS: Spinlock<Vec<Arc<dyn FileSystemType>>, FsClass> = Spinlock::new(Vec::new());
static FS_TYPES: Spinlock<Vec<Arc<FsType>>, FsClass> = Spinlock::new(Vec::new());

pub fn register_filesystem(fs: Arc<dyn FileSystemType>) -> KResult<()> {
    let mut list = FILESYSTEMS.lock();
    if list.iter().any(|t| t.name() == fs.name()) { return Err(VfsError::Ebusy); }
    list.push(fs);
    Ok(())
}

pub fn unregister_filesystem(name: &str) -> KResult<()> {
    let mut list = FILESYSTEMS.lock();
    match list.iter().position(|t| t.name() == name) {
        Some(i) => { list.remove(i); Ok(()) }
        None => Err(VfsError::Einval),
    }
}

pub fn get_fs_type(name: &str) -> Option<Arc<dyn FileSystemType>> {
    let base = match name.find('.') { Some(i) => &name[..i], None => name };
    if let Some(t) = FILESYSTEMS.lock().iter().find(|t| t.name() == base).cloned() { return Some(t); }
    FS_TYPES.lock().iter().find(|t| t.name == base).cloned().map(|t| t as Arc<dyn FileSystemType>)
}

pub fn registered_filesystems() -> Vec<Arc<dyn FileSystemType>> {
    let mut v: Vec<Arc<dyn FileSystemType>> = FILESYSTEMS.lock().iter().cloned().collect();
    for t in FS_TYPES.lock().iter() { v.push(t.clone() as Arc<dyn FileSystemType>); }
    v
}

/// `/proc/filesystems` body (Linux `fs/filesystems.c` `regen_filesystems_string`
/// / `filesystems_proc_show_fallback`): one `"%s\t%s\n"` line per registered
/// type in registration order, the prefix EMPTY for `FS_REQUIRES_DEV` and
/// `nodev` otherwise. Rendered from [`registered_filesystems`] — the same list
/// `sysfs(2)` indexes (`fs_index`/`fs_name`/`fs_maxindex` walk `file_systems`)
/// — so the file and the syscall can never disagree about which types exist.
/// # C: O(N_fs)
pub fn filesystems_proc_body() -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();
    for t in registered_filesystems().iter() {
        if !t.fs_flags().contains(super::FsFlags::FS_REQUIRES_DEV) { out.extend_from_slice(b"nodev"); }
        out.push(b'\t');
        out.extend_from_slice(t.name().as_bytes());
        out.push(b'\n');
    }
    out
}

pub fn register_fs(fs: Arc<FsType>) -> KResult<()> {
    let mut list = FS_TYPES.lock();
    if list.iter().any(|t| t.name == fs.name) { return Err(VfsError::Ebusy); }
    list.push(fs);
    Ok(())
}

pub fn get_fs(name: &str) -> Option<Arc<FsType>> {
    let base = match name.find('.') { Some(i) => &name[..i], None => name };
    FS_TYPES.lock().iter().find(|t| t.name == base).cloned()
}

pub fn unregister_fs(name: &str) -> KResult<()> {
    let mut list = FS_TYPES.lock();
    match list.iter().position(|t| t.name == name) {
        Some(i) => { list.remove(i); Ok(()) }
        None => Err(VfsError::Einval),
    }
}
