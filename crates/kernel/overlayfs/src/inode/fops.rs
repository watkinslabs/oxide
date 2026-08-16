//! Reads, writes and directory iteration on a merged object.
//!
//! A READ goes to whichever layer holds the data — which for a metadata-only
//! object is not the layer holding its metadata. A WRITE cannot: it has to go
//! to the writable layer, so the object and its data are brought there first.
//! That is the whole of the copy-on-write behaviour, and it is why opening a
//! container image read-only copies nothing at all.

extern crate alloc;

use vfs::file_ops::{DirContext, FileOps};
use vfs::types::FileType;
use vfs::{Inode, KResult, VfsError};

use crate::readdir;

use super::node::{ovl_of, refresh};
use super::ops::{copy_up_chain, real_of, OvlOps};

impl FileOps for OvlOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        real_of(inode, true).ok_or(VfsError::Eio)?.read(off, buf)
    }

    fn write(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        // Bringing the DATA up, not just the metadata: a metadata-only object
        // written in place would keep the lower contents for every byte the
        // write did not touch.
        copy_up_chain(inode).map_err(super::ops::err)?;
        let ovl = ovl_of(inode).ok_or(VfsError::Eio)?;
        let mut e = ovl.entry();
        if e.metacopy {
            crate::copyup::copy_up_data(&ovl.stack, &mut e).map_err(super::ops::err)?;
            ovl.set_entry(e);
        }
        let real = ovl.entry().upper.ok_or(VfsError::Erofs)?;
        let n = real.write(off, buf)?;
        refresh(inode);
        Ok(n)
    }

    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let ovl = ovl_of(inode).ok_or(VfsError::Enotdir)?;
        if inode.file_type() != FileType::Directory { return Err(VfsError::Enotdir); }
        let list = readdir::merged(&ovl.stack, &ovl.entry()).map_err(super::ops::err)?;
        // The list is built whole and then emitted by position, so a caller
        // resuming from an offset resumes at the same name it left off at.
        for (i, e) in readdir::visible(&list).enumerate() {
            let pos = i as u64;
            if pos < ctx.pos { continue; }
            if !ctx.emit_dt(&e.name, e.ino, e.dtype, pos + 1) { break; }
        }
        Ok(())
    }

    fn fsync(&self, file: &vfs::file::File, datasync: bool) -> KResult<()> {
        // Only the writable layer can hold anything unwritten; a lower layer
        // is read-only for the whole life of the mount.
        let inode = file.inode();
        let Some(ovl) = ovl_of(inode) else { return Ok(()) };
        if !ovl.stack.config.should_sync() { return Ok(()); }
        let _ = datasync;
        Ok(())
    }
}
