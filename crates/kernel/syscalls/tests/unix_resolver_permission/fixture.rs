//! Actual resolver body with production VFS permission and Unix address/security owners.
#![allow(dead_code)]
extern crate alloc;
use syscall::errno::Errno;
use std::cell::{Cell,RefCell};
thread_local! {
    static PATH: RefCell<Option<vfs::VfsPath>> = const {RefCell::new(None)};
    static CRED: RefCell<Option<vfs::Cred>> = const {RefCell::new(None)};
    static LOOKUPS: Cell<usize> = const {Cell::new(0)};
    static CREDENTIALS: Cell<usize> = const {Cell::new(0)};
}
mod pathresolve {
    use super::*;
    pub fn resolve_path_raw(path:&str,no_follow:bool)->Result<vfs::VfsPath,vfs::VfsError> {
        assert_eq!(path,"/endpoint");assert!(!no_follow);
        LOOKUPS.set(LOOKUPS.get()+1);
        PATH.with(|p|p.borrow().clone()).ok_or(vfs::VfsError::Enoent)
    }
    pub fn current_cred()->vfs::Cred {
        CREDENTIALS.set(CREDENTIALS.get()+1);
        CRED.with(|c|c.borrow().clone()).expect("pathname credentials")
    }
}
#[path="../../src/net_errno.rs"]
mod net_errno;
#[path="../../src/namei_common/errno.rs"]
mod vfs_errno;
use vfs_errno::errno_from_vfs;
include!(concat!(env!("OUT_DIR"),"/resolver.rs"));

#[cfg(test)]
mod tests;
