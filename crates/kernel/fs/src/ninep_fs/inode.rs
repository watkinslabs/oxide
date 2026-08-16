// `i_op` for a 9P inode — the namespace and metadata ops, forwarded as `.L`
// messages.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use ninep::uapi::{dotl, stats};
use vfs::{CreateCtx, Iattr, Idmap, Inode, InodeOps, InodeRef, Kstat, KResult, VfsError};
use vfs::generic_fillattr;

use super::attr;
use super::fs::{build_inode, data, refresh, walk_child, NinepInodeData};

/// Permission bits a create request may carry. The class bits come from the
/// operation, never from the caller's mode word.
const PERM_MASK: u32 = 0o7777;

/// The mode a new object is created with: the caller's permission bits with the
/// umask cleared. The umask is applied HERE rather than left to the server,
/// which has no way to know the caller's. # C: O(1)
fn create_mode(mode: u32, ctx: &CreateCtx) -> u32 {
    (mode & PERM_MASK) & !u32::from(ctx.umask)
}

/// `i_op` for every 9P inode.
pub struct NinepInodeOps;

impl NinepInodeOps {
    fn child(inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = data(inode)?;
        let fid = walk_child(&d.mount, &d.fid, name)?;
        build_inode(&d.mount, &fid)
    }
}

impl InodeOps for NinepInodeOps {
    /// `Twalk` of one element from this directory's handle. # C: RPC
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        Self::child(inode, name)
    }

    /// `Tlcreate` on a CLONE of the directory handle.
    ///
    /// The operation transforms the handle it is given into the new file's, so
    /// the directory's own handle must not be the one sent: the parent inode
    /// would silently start naming the child. # C: two RPCs
    fn create(&self, inode: &Inode, name: &str, mode: u32, ctx: &CreateCtx) -> KResult<InodeRef> {
        let d = data(inode)?;
        let working = d.mount.client.clone_fid(&d.fid).map_err(VfsError::from)?;
        d.mount.client
            .lcreate(&working, name, dotl::RDWR, create_mode(mode, ctx), ctx.fsgid())
            .map_err(VfsError::from)?;
        // The created handle is OPEN; the inode needs an unopened one, so the
        // child is walked afresh rather than reusing it.
        drop(working);
        Self::child(inode, name)
    }

    /// `Tmkdir` # C: two RPCs
    fn mkdir(&self, inode: &Inode, name: &str, mode: u32, ctx: &CreateCtx) -> KResult<InodeRef> {
        let d = data(inode)?;
        d.mount.client.mkdir(&d.fid, name, create_mode(mode, ctx), ctx.fsgid())
            .map_err(VfsError::from)?;
        Self::child(inode, name)
    }

    /// `Tunlinkat` with the directory-removal flag. # C: RPC
    fn rmdir(&self, inode: &Inode, name: &str) -> KResult<()> {
        let d = data(inode)?;
        let child_ino = Self::child(inode, name).ok().map(|c| c.ino());
        d.mount.client.unlinkat(&d.fid, name, true).map_err(VfsError::from)?;
        if let Some(ino) = child_ino { d.mount.forget(ino); }
        Ok(())
    }

    /// `Tmknod`. A `nodevmap` mount refuses outright rather than asking the
    /// server for a node it would then decline to materialise. # C: RPC
    fn mknod(&self, inode: &Inode, name: &str, mode: u16, rdev: u32, ctx: &CreateCtx) -> KResult<()> {
        let d = data(inode)?;
        if d.mount.opts.nodev { return Err(VfsError::Eperm); }
        let major = (rdev >> 8) & 0xfff;
        let minor = (rdev & 0xff) | ((rdev >> 20) << 8);
        let m = (u32::from(mode) & !PERM_MASK) | create_mode(u32::from(mode), ctx);
        d.mount.client.mknod(&d.fid, name, m, major, minor, ctx.fsgid())
            .map_err(VfsError::from).map(|_| ())
    }

    /// `Tsymlink`. The target is raw bytes on the wire but must be a name the
    /// server can store; a non-UTF-8 target is refused rather than mangled.
    /// # C: RPC
    fn symlink(&self, inode: &Inode, name: &str, target: &[u8], ctx: &CreateCtx) -> KResult<()> {
        let d = data(inode)?;
        let t = core::str::from_utf8(target).map_err(|_| VfsError::Einval)?;
        d.mount.client.symlink(&d.fid, name, t, ctx.fsgid())
            .map_err(VfsError::from).map(|_| ())
    }

    /// `Tlink` — the target must live on THIS mount, since a server handle
    /// cannot name an object on another one. # C: RPC
    fn link(&self, inode: &Inode, target: &InodeRef, name: &str, _ctx: &CreateCtx) -> KResult<()> {
        let d = data(inode)?;
        let t = data(target)?;
        if !Arc::ptr_eq(&d.mount, &t.mount) { return Err(VfsError::Exdev); }
        d.mount.client.link(&d.fid, &t.fid, name).map_err(VfsError::from)
    }

    /// `Tunlinkat` # C: RPC
    fn unlink(&self, inode: &Inode, name: &str) -> KResult<()> {
        let d = data(inode)?;
        let child_ino = Self::child(inode, name).ok().map(|c| c.ino());
        d.mount.client.unlinkat(&d.fid, name, false).map_err(VfsError::from)?;
        if let Some(ino) = child_ino { d.mount.forget(ino); }
        Ok(())
    }

    /// `Trenameat`, which names both ends by (directory, name).
    ///
    /// No rename FLAG is supported: `RENAME_EXCHANGE` and `RENAME_NOREPLACE`
    /// have no protocol expression, and performing a plain rename for them
    /// would silently destroy the file the caller asked to preserve.
    /// # C: RPC
    fn rename(&self, inode: &Inode, old_name: &str, new_dir: &Inode, new_name: &str,
              flags: u32, _ctx: &CreateCtx) -> KResult<()>
    {
        if flags != 0 { return Err(VfsError::Einval); }
        let d = data(inode)?;
        let nd = data(new_dir)?;
        if !Arc::ptr_eq(&d.mount, &nd.mount) { return Err(VfsError::Exdev); }
        d.mount.client.renameat(&d.fid, old_name, &nd.fid, new_name).map_err(VfsError::from)
    }

    /// `Treadlink` # C: RPC
    fn readlink(&self, inode: &Inode) -> KResult<Vec<u8>> {
        let d = data(inode)?;
        let t = d.mount.client.readlink(&d.fid).map_err(VfsError::from)?;
        Ok(t.into_bytes())
    }

    /// `Tgetattr`, unless the caller said a cached answer will do or the mount
    /// caches metadata without revalidating. # C: RPC, or O(1) when cached
    fn getattr(&self, inode: &Inode, idmap: &Idmap, _request_mask: u32, query_flags: u32) -> Kstat {
        let cached_ok = query_flags & vfs::getattr::AT_STATX_DONT_SYNC != 0
            || data(inode).map(|d| d.mount.opts.is_loose()).unwrap_or(false);
        if !cached_ok { let _ = refresh(inode); }
        generic_fillattr(inode, idmap)
    }

    /// `Tsetattr`.
    ///
    /// The server is told FIRST and the local size adjusted only after it
    /// agreed: shrinking the cached size before a truncate the server refuses
    /// would make the file appear shorter than it is. # C: RPC
    fn setattr(&self, inode: &Inode, _idmap: &Idmap, ia: &Iattr) -> KResult<()> {
        let d = data(inode)?;
        let p9 = attr::iattr_to_p9(ia);
        if p9.valid == 0 { return Ok(()); }
        d.mount.client.setattr(&d.fid, &p9).map_err(VfsError::from)?;
        if ia.valid & vfs::setattr::ATTR_SIZE != 0 { inode.set_size(ia.size); }
        Ok(())
    }

    /// A truncate is a size-only attribute change; there is no separate
    /// protocol message for it. # C: RPC
    fn truncate(&self, inode: &Inode, len: u64) -> KResult<()> {
        let d = data(inode)?;
        let p9 = ninep::codec::IattrDotl {
            valid: ninep::uapi::setattr::SIZE, size: len, ..Default::default()
        };
        d.mount.client.setattr(&d.fid, &p9).map_err(VfsError::from)?;
        inode.set_size(len);
        Ok(())
    }

    /// A directory is empty when one readdir past the dot entries yields
    /// nothing. Asked of the SERVER rather than of a cached child count, which
    /// a 9P mount does not keep. # C: RPC
    fn dir_is_empty(&self, inode: &Inode) -> bool {
        let Ok(d) = data(inode) else { return true };
        let Ok(handle) = d.mount.client.clone_fid(&d.fid) else { return true };
        if d.mount.client.lopen(&handle, dotl::RDONLY | dotl::DIRECTORY).is_err() { return true; }
        let mut cookie = 0u64;
        loop {
            let Ok(bytes) = d.mount.client.readdir(&handle, cookie, super::file::READDIR_CHUNK)
                else { return true };
            if bytes.is_empty() { return true; }
            for ent in ninep::codec::DirEntries::new(&bytes) {
                let Ok(ent) = ent else { return true };
                cookie = ent.offset;
                if ent.name != b"." && ent.name != b".." { return false; }
            }
        }
    }
}

/// The attribute mask a full refresh asks for. # C: O(1)
pub const REFRESH_MASK: u64 = stats::ALL;

/// Convenience for a caller holding an inode rather than its private data.
/// # C: O(1)
pub fn inode_data(inode: &Inode) -> KResult<&NinepInodeData> { data(inode) }
