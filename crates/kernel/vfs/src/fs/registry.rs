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
