//! Shared fixture for F721 path-family conformance cases (`scratch/`
//! harness, `docs/15`). A minimal writable in-memory directory backend
//! (create/mkdir/rmdir/unlink/symlink/link) driving the REAL, ungated
//! `vfs::namei` resolver + permission gates (`path_lookup_path`, `may_open`,
//! `may_create`, `may_delete`, `may_rename`, `rename_flags_check`) exactly as
//! the gated syscall shims do (`crates/kernel/syscalls/src/{083_mkdir,
//! 084_rmdir,087_unlink,082_rename,086_link,088_symlink}.rs`). Those shims
//! sit behind `#[cfg(target_os = "oxide-kernel")]` and pull in per-CPU
//! task/uaccess machinery this hosted harness does not stand up, so this
//! fixture + the real `vfs` primitives is the "hosted-testable sibling"
//! per `docs/53` layering (vfs owns the work; syscalls is the hollow shim) —
//! matching the established `vfs/tests/namei_*.rs` fixture style.
//!
//! The exact ORDER in which a gated syscall shim sequences these real
//! primitives against landlock/EROFS/debug-trace side calls is NOT
//! independently re-verified here — only the individual real vfs-level
//! decisions are (the walk's ENOTDIR/ENOENT ordering, `may_*`'s DAC/type
//! checks, and the backend `i_op` dispatch). Each conformance test file notes
//! where it sequences these itself vs. calls a real multi-step vfs entry
//! point.

#![allow(dead_code)]

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use vfs::inode::Inode;
use vfs::{CreateCtx, Dentry, FileType, InodeBuilder, InodeOps, InodeRef, KResult, VfsError,
    default_file_ops, mk_mode};

static NEXT_INO: AtomicU64 = AtomicU64::new(0x9000);
pub fn next_ino() -> u64 { NEXT_INO.fetch_add(1, Ordering::Relaxed) }

struct DirData { kids: Mutex<BTreeMap<String, InodeRef>> }

/// Writable directory backend: real `InodeOps` overrides, not a stub —
/// `mkdir`/`rmdir`/`unlink`/`symlink`/`link` here are the actual code path
/// `Inode::mkdir`/`rmdir`/`unlink_child`/`symlink_child`/`link_child`
/// dispatch into (`crates/kernel/vfs/src/inode/ops.rs`). Only the STORAGE is
/// a `BTreeMap` instead of ext4; the EEXIST/ENOENT/ENOTEMPTY/ENOTDIR
/// decisions mirror Linux `simple_*`-style in-memory fs backends
/// (`fs/libfs.c`), same class as tmpfs.
pub struct WDirOps;

impl InodeOps for WDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        inode.private::<DirData>().unwrap().kids.lock().unwrap().get(name).cloned().ok_or(VfsError::Enoent)
    }
    fn create(&self, inode: &Inode, name: &str, _mode: u32, _ctx: &CreateCtx) -> KResult<InodeRef> {
        let mut kids = inode.private::<DirData>().unwrap().kids.lock().unwrap();
        if kids.contains_key(name) { return Err(VfsError::Eexist); }
        let child = regular_file(next_ino());
        kids.insert(name.to_string(), child.clone());
        Ok(child)
    }
    fn mkdir(&self, inode: &Inode, name: &str, _mode: u32, _ctx: &CreateCtx) -> KResult<InodeRef> {
        let mut kids = inode.private::<DirData>().unwrap().kids.lock().unwrap();
        if kids.contains_key(name) { return Err(VfsError::Eexist); }
        let child = dir(next_ino(), &[]);
        kids.insert(name.to_string(), child.clone());
        Ok(child)
    }
    fn rmdir(&self, inode: &Inode, name: &str) -> KResult<()> {
        let mut kids = inode.private::<DirData>().unwrap().kids.lock().unwrap();
        let victim = kids.get(name).ok_or(VfsError::Enoent)?;
        if !matches!(victim.file_type(), FileType::Directory) { return Err(VfsError::Enotdir); }
        let empty = victim.private::<DirData>().map(|d| d.kids.lock().unwrap().is_empty()).unwrap_or(true);
        if !empty { return Err(VfsError::Enotempty); }
        kids.remove(name);
        Ok(())
    }
    fn unlink(&self, inode: &Inode, name: &str) -> KResult<()> {
        let mut kids = inode.private::<DirData>().unwrap().kids.lock().unwrap();
        if !kids.contains_key(name) { return Err(VfsError::Enoent); }
        kids.remove(name);
        Ok(())
    }
    fn symlink(&self, inode: &Inode, name: &str, target: &[u8], _ctx: &CreateCtx) -> KResult<()> {
        let mut kids = inode.private::<DirData>().unwrap().kids.lock().unwrap();
        if kids.contains_key(name) { return Err(VfsError::Eexist); }
        kids.insert(name.to_string(), symlink_inode(next_ino(), target));
        Ok(())
    }
    fn link(&self, inode: &Inode, target: &InodeRef, name: &str, _ctx: &CreateCtx) -> KResult<()> {
        let mut kids = inode.private::<DirData>().unwrap().kids.lock().unwrap();
        if kids.contains_key(name) { return Err(VfsError::Eexist); }
        kids.insert(name.to_string(), target.clone());
        Ok(())
    }
    /// Linux `vfs_rename`-adjacent backend step: after the shared
    /// `vfs::namei::may_rename` DAC/type gate already ran (each case calls it
    /// explicitly — this only performs the mechanical entry move a real
    /// backend does). ENOTEMPTY-onto-existing-nonempty-dir mirrors an
    /// ordinary directory backend's own rename (Linux e.g. `ext4_rename`).
    fn rename(&self, inode: &Inode, old_name: &str, new_dir: &Inode, new_name: &str, flags: u32, _ctx: &CreateCtx) -> KResult<()> {
        const RENAME_NOREPLACE: u32 = 1 << 0;
        let same_dir = std::ptr::eq(inode, new_dir);
        if same_dir {
            let mut kids = inode.private::<DirData>().unwrap().kids.lock().unwrap();
            let moved = kids.get(old_name).cloned().ok_or(VfsError::Enoent)?;
            if let Some(existing) = kids.get(new_name) {
                if flags & RENAME_NOREPLACE != 0 { return Err(VfsError::Eexist); }
                if matches!(existing.file_type(), FileType::Directory) {
                    let empty = existing.private::<DirData>().map(|d| d.kids.lock().unwrap().is_empty()).unwrap_or(true);
                    if !empty { return Err(VfsError::Enotempty); }
                }
            }
            kids.remove(old_name);
            kids.insert(new_name.to_string(), moved);
            return Ok(());
        }
        let moved = {
            let kids = inode.private::<DirData>().unwrap().kids.lock().unwrap();
            kids.get(old_name).cloned().ok_or(VfsError::Enoent)?
        };
        {
            let mut dst_kids = new_dir.private::<DirData>().unwrap().kids.lock().unwrap();
            if let Some(existing) = dst_kids.get(new_name) {
                if flags & RENAME_NOREPLACE != 0 { return Err(VfsError::Eexist); }
                if matches!(existing.file_type(), FileType::Directory) {
                    let empty = existing.private::<DirData>().map(|d| d.kids.lock().unwrap().is_empty()).unwrap_or(true);
                    if !empty { return Err(VfsError::Enotempty); }
                }
            }
            dst_kids.insert(new_name.to_string(), moved);
        }
        inode.private::<DirData>().unwrap().kids.lock().unwrap().remove(old_name);
        Ok(())
    }
}

pub fn dir(ino: u64, kids: &[(&str, InodeRef)]) -> InodeRef {
    let mut m = BTreeMap::new();
    for (n, i) in kids { m.insert(n.to_string(), i.clone()); }
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), Arc::new(WDirOps), default_file_ops())
        .private(Arc::new(DirData { kids: Mutex::new(m) })).build()
}

pub fn regular_file(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Regular, 0o644), Arc::new(WDirOps), default_file_ops()).build()
}

pub fn symlink_inode(ino: u64, target: &[u8]) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Symlink, 0o777), vfs::default_inode_ops(), default_file_ops())
        .link(target.to_vec().into_boxed_slice()).build()
}

/// A fresh root directory + dentry (one per case — cases never share a tree,
/// avoiding any cross-test ordering dependency).
pub fn build_root() -> Arc<Dentry> {
    Dentry::new_root(dir(2, &[]))
}
