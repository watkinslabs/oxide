//! The inode and file operations of a mounted NTFS volume.
//!
//! NTFS counts hard links and every record carries as many `$FILE_NAME`
//! attributes as it has names. The volume operation coordinates the new name
//! and count under the filesystem's one lock.

use alloc::sync::Arc;
use alloc::string::String;
use alloc::vec::Vec;

use vfs::{CreateCtx, DirContext, FileOps, FileType, Inode, InodeOps, InodeRef, KResult,
          VfsError, XattrError};

use crate::attrs;

use super::node::{node_inode, stream_inode, NtfsNode};
use crate::opts::StreamInterface;
use super::{errno_to_vfs, now};

/// The operations, for every inode of this filesystem.
pub struct NtfsOps;

impl NtfsOps {
    /// The node behind an inode. # C: O(1)
    fn node(inode: &Inode) -> KResult<&NtfsNode> {
        inode.private::<NtfsNode>().ok_or(VfsError::Einval)
    }

    /// The node behind a DIRECTORY inode. # C: O(1)
    fn dir_of(inode: &Inode) -> KResult<&NtfsNode> {
        let node = Self::node(inode)?;
        if !node.info.is_dir { return Err(VfsError::Enotdir); }
        Ok(node)
    }

    /// Build the inode for a record. # C: O(record bytes)
    fn child(node: &NtfsNode, number: u64) -> KResult<InodeRef> {
        let info = node.fs.volume.lock().stat(number).map_err(errno_to_vfs)?;
        Ok(node_inode(Arc::clone(&node.fs), info))
    }

    fn stream_name(name: &str) -> Option<Vec<u16>> { crate::name::encode(name) }
}

impl InodeOps for NtfsOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let node = Self::dir_of(inode)?;
        let (base, stream) = match node.fs.options().streams {
            StreamInterface::Windows => name.split_once(':')
                .map_or((name, None), |(base, stream)| (base, Self::stream_name(stream))),
            _ => (name, None),
        };
        if stream.is_some() && base.is_empty() { return Err(VfsError::Enoent); }
        let hit = node.fs.volume.lock().find_entry(node.info.number, base)
            .map_err(errno_to_vfs)?;
        let info = node.fs.volume.lock().stat(hit.reference.number).map_err(errno_to_vfs)?;
        match stream {
            Some(stream) if info.streams.iter().any(|n| Self::stream_name(n).as_deref() == Some(&stream)) =>
                Ok(stream_inode(Arc::clone(&node.fs), info, stream)),
            Some(_) => Err(VfsError::Enoent),
            None => Ok(node_inode(Arc::clone(&node.fs), info)),
        }
    }

    fn dir_is_empty(&self, inode: &Inode) -> bool {
        let Ok(node) = Self::dir_of(inode) else { return true };
        node.fs.volume.lock().dir_is_empty(node.info.number).unwrap_or(false)
    }

    /// `mode` is read and discarded: what a record presents with is the
    /// mount's `fmask=`/`dmask=` answer rather than anything the creator asked
    /// for, because the medium stores an access-control list and not a mode.
    fn create(&self, inode: &Inode, name: &str, _mode: u32, _ctx: &CreateCtx)
        -> KResult<InodeRef> {
        let node = Self::dir_of(inode)?;
        let hit = node.fs.volume.lock().create_file(node.info.number, name, now())
            .map_err(errno_to_vfs)?;
        Self::child(node, hit.reference.number)
    }

    fn mkdir(&self, inode: &Inode, name: &str, _mode: u32, _ctx: &CreateCtx) -> KResult<InodeRef> {
        let node = Self::dir_of(inode)?;
        let hit = node.fs.volume.lock().create_dir(node.info.number, name, now())
            .map_err(errno_to_vfs)?;
        Self::child(node, hit.reference.number)
    }

    fn rmdir(&self, inode: &Inode, name: &str) -> KResult<()> {
        let node = Self::dir_of(inode)?;
        node.fs.volume.lock().rmdir(node.info.number, name, now()).map_err(errno_to_vfs)
    }

    fn unlink(&self, inode: &Inode, name: &str) -> KResult<()> {
        let node = Self::dir_of(inode)?;
        node.fs.volume.lock().unlink(node.info.number, name, now()).map_err(errno_to_vfs)
    }

    fn link(&self, inode: &Inode, target: &InodeRef, name: &str, _ctx: &CreateCtx)
        -> KResult<()> {
        let node = Self::dir_of(inode)?;
        let target_node = Self::node(target)?;
        if !Arc::ptr_eq(&node.fs, &target_node.fs) { return Err(VfsError::Exdev); }
        node.fs.volume.lock().link(node.info.number, name, target_node.info.number, now())
            .map_err(errno_to_vfs)?;
        target.inc_nlink();
        Ok(())
    }

    fn rename(&self, inode: &Inode, old_name: &str, new_dir: &Inode, new_name: &str, flags: u32,
              _ctx: &CreateCtx) -> KResult<()> {
        let node = Self::dir_of(inode)?;
        let target = Self::dir_of(new_dir)?;
        if !Arc::ptr_eq(&node.fs, &target.fs) { return Err(VfsError::Exdev); }
        node.fs.volume.lock()
            .rename(node.info.number, old_name, target.info.number, new_name, flags, now())
            .map_err(errno_to_vfs)
    }

    fn truncate(&self, inode: &Inode, len: u64) -> KResult<()> {
        let node = Self::node(inode)?;
        if node.stream.is_some() { return Err(VfsError::Eopnotsupp); }
        node.fs.volume.lock().truncate_file(node.info.number, len, now())
            .map_err(errno_to_vfs)?;
        inode.set_size(len);
        Ok(())
    }

    fn readlink(&self, inode: &Inode) -> KResult<alloc::vec::Vec<u8>> {
        let node = Self::node(inode)?;
        let target = node.fs.volume.lock().read_link(node.info.number).map_err(errno_to_vfs)?;
        Ok(target.into_bytes())
    }

    fn getxattr(&self, inode: &Inode, name: &str) -> Result<Vec<u8>, XattrError> {
        let node = Self::node(inode).map_err(XattrError::Fs)?;
        if node.fs.options().streams != StreamInterface::Xattr {
            return Err(XattrError::NotSup);
        }
        let stream = name.strip_prefix("user.").and_then(Self::stream_name)
            .ok_or(XattrError::NotFound)?;
        node.fs.volume.lock().read_stream_whole(node.info.number, &stream)
            .map_err(|e| match e { syscall::errno::Errno::Enoent => XattrError::NotFound,
                                    e => XattrError::Fs(errno_to_vfs(e)) })
    }

    fn setxattr(&self, _inode: &Inode, _name: &str, _value: Vec<u8>, _create: bool,
                _replace: bool) -> Result<(), XattrError> { Err(XattrError::NotSup) }

    fn removexattr(&self, _inode: &Inode, _name: &str) -> Result<(), XattrError> {
        Err(XattrError::NotSup)
    }

    fn listxattr(&self, inode: &Inode) -> Result<Vec<String>, XattrError> {
        let node = Self::node(inode).map_err(XattrError::Fs)?;
        if node.fs.options().streams != StreamInterface::Xattr { return Err(XattrError::NotSup); }
        Ok(node.info.streams.iter().map(|s| alloc::format!("user.{s}")).collect())
    }
}

impl FileOps for NtfsOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let node = NtfsOps::node(inode)?;
        if node.info.is_dir { return Err(VfsError::Eisdir); }
        let name = node.stream.as_deref().unwrap_or(&[]);
        node.fs.volume.lock().read_stream(node.info.number, name, off, buf)
            .map_err(errno_to_vfs)
    }

    fn write(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        let node = NtfsOps::node(inode)?;
        if node.info.is_dir { return Err(VfsError::Eisdir); }
        let name = node.stream.as_deref().unwrap_or(&[]);
        let size = node.fs.volume.lock().write_stream(node.info.number, name, off, buf, now())
            .map_err(errno_to_vfs)?;
        inode.set_size(size);
        Ok(buf.len())
    }

    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let node = NtfsOps::dir_of(inode)?;
        let opts = node.fs.options();
        let entries = node.fs.volume.lock().read_dir(node.info.number).map_err(errno_to_vfs)?;
        // `.` and `..` are not entries of the index, so they are emitted here
        // or a listing has neither.
        let self_ino = inode.ino();
        if ctx.pos == 0 && !ctx.emit(".", self_ino, FileType::Directory, 1) { return Ok(()); }
        if ctx.pos == 1 && !ctx.emit("..", self_ino, FileType::Directory, 2) { return Ok(()); }
        let mut slot = 2u64;
        for entry in entries {
            // The volume's own metadata files carry the hidden and system
            // bits; listing them puts `$MFT` in the root of every mount.
            if attrs::hidden_from(entry.fname.attributes, &opts) { continue; }
            if ctx.pos <= slot {
                let ino = crate::ident::inode_number(entry.reference.number);
                let ftype = if entry.is_dir() { FileType::Directory } else { FileType::Regular };
                if !ctx.emit(&entry.name, ino, ftype, slot + 1) { break; }
            }
            slot += 1;
        }
        Ok(())
    }
}
