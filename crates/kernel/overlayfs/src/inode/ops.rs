//! The namespace and metadata operations the VFS calls on a merged object.
//!
//! Every one that WRITES begins the same way: the object, and every ancestor
//! of it, is copied into the writable layer first. That is not an optimisation
//! detail — a create in a directory that exists only below has nowhere to put
//! the new name until the directory itself is there.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use syscall::errno::Errno;
use vfs::inode_ops::{CreateCtx, InodeOps};
use vfs::setattr::Iattr;
use vfs::types::S_IFMT;
use vfs::xattr::XattrError;
use vfs::{Idmap, Inode, InodeRef, KResult, VfsError};

use crate::copyup;
use crate::dirops::create::{create, creating_whiteout_refused, New};
use crate::dirops::remove::remove_name;
use crate::dirops::rename::rename;
use crate::err::{to_errno, to_vfs};
use crate::lookup::lookup;
use crate::marker;
use crate::xattr;

use super::node::{make_inode, ovl_of, refresh, OvlInode};

/// Both vtables of an overlay inode.
pub struct OvlOps;

/// The overlay state of an inode, or `EIO` — an overlay inode always has one,
/// so its absence is a bug rather than a caller error. # C: O(1)
fn ovl(inode: &Inode) -> KResult<&OvlInode> { ovl_of(inode).ok_or(VfsError::Eio) }

/// Copy this object and every ancestor of it into the writable layer.
///
/// Walks up to the topmost ancestor that is not there yet and copies down, so
/// each copy has a destination directory to be moved into.
/// # C: O(depth)
pub fn copy_up_chain(inode: &Inode) -> Result<(), Errno> {
    {
        let this = ovl(inode).map_err(to_errno)?;
        if this.entry().upper.is_some() { return Ok(()); }
    }
    // Every ancestor that is not in the writable layer yet, deepest first.
    let mut chain: Vec<Arc<OvlInode>> = Vec::new();
    let mut cur = ovl(inode).map_err(to_errno)?.parent.clone();
    while let Some(p) = cur {
        let has_upper = p.entry().upper.is_some();
        let next = p.parent.clone();
        chain.push(p);
        if has_upper { break; }
        cur = next;
    }
    // Shallowest first: each copy needs its parent already present.
    for i in (0..chain.len()).rev() {
        let child = &chain[i];
        if child.entry().upper.is_some() { continue; }
        let Some(parent) = chain.get(i + 1).map(|p| p.entry()) else { return Err(Errno::Eio) };
        let mut e = child.entry();
        copyup::copy_up(&child.stack, &parent, &mut e, &child.name, 0)?;
        child.set_entry(e);
    }
    let this = ovl(inode).map_err(to_errno)?;
    let Some(parent) = chain.first().map(|p| p.entry()) else { return Err(Errno::Eio) };
    let mut e = this.entry();
    copyup::copy_up(&this.stack, &parent, &mut e, &this.name, 0)?;
    this.set_entry(e);
    Ok(())
}

/// Copy up so the object's DATA is in the writable layer, not only its
/// metadata. # C: O(size)
fn copy_up_with_data(inode: &Inode) -> Result<(), Errno> {
    copy_up_chain(inode)?;
    let this = ovl(inode).map_err(to_errno)?;
    let mut e = this.entry();
    if e.metacopy { copyup::copy_up_data(&this.stack, &mut e)?; this.set_entry(e); }
    Ok(())
}

impl OvlOps {
    /// Resolve `name` and build its overlay inode. # C: O(layers)
    fn child(&self, name: &str, this: &OvlInode) -> KResult<InodeRef> {
        let parent = this.entry();
        let found = lookup(&this.stack, &parent, &this.stack.root, name).map_err(to_vfs)?;
        let entry = found.ok_or(VfsError::Enoent)?;
        Ok(make_inode(&this.stack, entry, this.shared(), name))
    }

    /// Create one object of any kind, having first put the parent in the
    /// writable layer. # C: O(depth)
    fn make(&self, inode: &Inode, name: &str, what: New) -> KResult<InodeRef> {
        copy_up_chain(inode).map_err(to_vfs)?;
        let this = ovl(inode)?;
        let parent = this.entry();
        let merges = !parent.lower.is_empty();
        create(&this.stack, &parent, name, what, merges).map_err(to_vfs)?;
        refresh(inode);
        self.child(name, this)
    }
}

impl InodeOps for OvlOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        self.child(name, ovl(inode)?)
    }

    fn create(&self, inode: &Inode, name: &str, mode: u32, _c: &CreateCtx) -> KResult<InodeRef> {
        self.make(inode, name, New::File(mode))
    }

    fn mkdir(&self, inode: &Inode, name: &str, mode: u32, _c: &CreateCtx) -> KResult<InodeRef> {
        self.make(inode, name, New::Dir(mode & !(S_IFMT as u32)))
    }

    fn mknod(&self, inode: &Inode, name: &str, mode: u16, rdev: u32, _c: &CreateCtx)
        -> KResult<()> {
        // The object that stands for a deleted name is the overlay's own; a
        // caller making one by hand would make an arbitrary lower file vanish.
        if creating_whiteout_refused(mode as u32, rdev) { return Err(VfsError::Eperm); }
        self.make(inode, name, New::Node(mode as u32, rdev)).map(|_| ())
    }

    fn symlink(&self, inode: &Inode, name: &str, target: &[u8], _c: &CreateCtx) -> KResult<()> {
        self.make(inode, name, New::Symlink(target.to_vec())).map(|_| ())
    }

    fn link(&self, inode: &Inode, target: &InodeRef, name: &str, _c: &CreateCtx) -> KResult<()> {
        copy_up_chain(target).map_err(to_vfs)?;
        let real = ovl_of(target).ok_or(VfsError::Exdev)?.entry().upper.ok_or(VfsError::Eio)?;
        self.make(inode, name, New::Hardlink(real)).map(|_| ())
    }

    fn unlink(&self, inode: &Inode, name: &str) -> KResult<()> {
        copy_up_chain(inode).map_err(to_vfs)?;
        let this = ovl(inode)?;
        let r = remove_name(&this.stack, &this.entry(), &this.stack.root, name, false)
            .map_err(to_vfs);
        refresh(inode);
        r
    }

    fn rmdir(&self, inode: &Inode, name: &str) -> KResult<()> {
        copy_up_chain(inode).map_err(to_vfs)?;
        let this = ovl(inode)?;
        let r = remove_name(&this.stack, &this.entry(), &this.stack.root, name, true)
            .map_err(to_vfs);
        refresh(inode);
        r
    }

    fn rename(&self, inode: &Inode, old: &str, new_dir: &Inode, new: &str, flags: u32,
              _c: &CreateCtx) -> KResult<()> {
        copy_up_chain(inode).map_err(to_vfs)?;
        copy_up_chain(new_dir).map_err(to_vfs)?;
        let this = ovl(inode)?;
        let dest = ovl(new_dir)?;
        let old_parent = this.entry();
        let new_parent = dest.entry();
        let old_entry = lookup(&this.stack, &old_parent, &this.stack.root, old)
            .map_err(to_vfs)?.ok_or(VfsError::Enoent)?;
        // The source has to be in the writable layer before it can be moved
        // there; its lower half stays where it is either way.
        let mut src = old_entry.clone();
        if src.upper.is_none() {
            copyup::copy_up(&this.stack, &old_parent, &mut src, old, 0).map_err(to_vfs)?;
        }
        let new_entry = lookup(&this.stack, &new_parent, &this.stack.root, new).map_err(to_vfs)?;
        rename(&this.stack, &old_parent, old, &src, &new_parent, new, new_entry.as_ref(), flags,
               &[old]).map_err(to_vfs)
    }

    fn readlink(&self, inode: &Inode) -> KResult<Vec<u8>> {
        ovl(inode)?.real().ok_or(VfsError::Einval)?.get_link()
    }

    fn getattr(&self, inode: &Inode, idmap: &Idmap, mask: u32, flags: u32) -> vfs::getattr::Kstat {
        let mut st = match ovl_of(inode).and_then(|o| o.real()) {
            Some(r) => r.getattr_mask(idmap, mask, flags),
            None => return vfs::getattr::Kstat::default(),
        };
        // The merge is invisible to `stat` except here: the identity is the
        // overlay's, so a copy-up does not change it.
        st.ino = inode.ino();
        st
    }

    fn setattr(&self, inode: &Inode, idmap: &Idmap, ia: &Iattr) -> KResult<()> {
        if ia.valid & vfs::setattr::ATTR_SIZE != 0 {
            copy_up_with_data(inode).map_err(to_vfs)?;
        } else {
            copy_up_chain(inode).map_err(to_vfs)?;
        }
        let this = ovl(inode)?;
        let real = this.entry().upper.ok_or(VfsError::Erofs)?;
        real.setattr(idmap, ia)?;
        refresh(inode);
        Ok(())
    }

    fn truncate(&self, inode: &Inode, len: u64) -> KResult<()> {
        copy_up_with_data(inode).map_err(to_vfs)?;
        let real = ovl(inode)?.entry().upper.ok_or(VfsError::Erofs)?;
        real.truncate(len)?;
        refresh(inode);
        Ok(())
    }

    fn getxattr(&self, inode: &Inode, name: &str) -> Result<Vec<u8>, XattrError> {
        let this = ovl_of(inode).ok_or(XattrError::NotSup)?;
        // The overlay's own markers are its bookkeeping, not the object's.
        if xattr::is_private(&this.stack.config, name) { return Err(XattrError::NotFound); }
        this.real().ok_or(XattrError::NotSup)?.getxattr(name)
    }

    fn setxattr(&self, inode: &Inode, name: &str, value: Vec<u8>, create: bool, replace: bool)
        -> Result<(), XattrError> {
        let this = ovl_of(inode).ok_or(XattrError::NotSup)?;
        if xattr::is_private(&this.stack.config, name) { return Err(XattrError::NotSup); }
        copy_up_chain(inode).map_err(|_| XattrError::NotSup)?;
        let real = this.entry().upper.ok_or(XattrError::NotSup)?;
        let r = real.setxattr(name, value, create, replace);
        refresh(inode);
        r
    }

    fn removexattr(&self, inode: &Inode, name: &str) -> Result<(), XattrError> {
        let this = ovl_of(inode).ok_or(XattrError::NotSup)?;
        if xattr::is_private(&this.stack.config, name) { return Err(XattrError::NotFound); }
        copy_up_chain(inode).map_err(|_| XattrError::NotSup)?;
        this.entry().upper.ok_or(XattrError::NotSup)?.removexattr(name)
    }

    fn listxattr(&self, inode: &Inode) -> Result<Vec<String>, XattrError> {
        let this = ovl_of(inode).ok_or(XattrError::NotSup)?;
        let real = this.real().ok_or(XattrError::NotSup)?;
        let names = real.listxattr()?;
        // Listing a marker would make a `tar` of the overlay carry it into the
        // archive, and restoring that produces a file nothing can see.
        Ok(names.into_iter().filter(|n| !xattr::is_private(&this.stack.config, n)).collect())
    }

    fn dir_is_empty(&self, inode: &Inode) -> bool {
        match ovl_of(inode) {
            Some(o) => crate::readdir::is_empty(&o.stack, &o.entry()).unwrap_or(false),
            None => true,
        }
    }
}

/// Whether the object has any marker at all, for the few callers that only
/// need to know it was produced by an overlay. # C: O(log n)
pub fn has_marker(inode: &Inode, m: crate::uapi::Marker) -> bool {
    match ovl_of(inode).and_then(|o| o.real().map(|r| (o.stack.clone(), r))) {
        Some((s, r)) => marker::present(&s.config, &r, m),
        None => false,
    }
}

/// The real object an operation on `inode` reaches, for a caller outside this
/// module. `data` selects the one holding the contents rather than the
/// metadata, which differ on a metadata-only object. # C: O(1)
pub fn real_of(inode: &Inode, data: bool) -> Option<InodeRef> {
    let o = ovl_of(inode)?;
    if data { o.realdata() } else { o.real() }
}

/// Errno as this module's failures, for the file operations beside it. # C: O(1)
pub fn err(e: Errno) -> VfsError { to_vfs(e) }
