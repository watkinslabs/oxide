// `inode_operations` (Linux `struct inode_operations`) per `16§2` — the
// namespace + metadata vtable hung off a `struct Inode` as `i_op`. The other
// half of the old god-trait split (`i_fop` = [`crate::file_ops::FileOps`]).
//
// Every method takes `&self` (the ops object) AND `inode: &Inode` (the concrete
// inode acted on), so one `Arc<dyn InodeOps>` serves every inode of a backend.
// Default bodies are Linux's "op absent" errno (`Erofs` for a mutating
// namespace op on a read-only/static inode; `Eopnotsupp`/`Einval` for the
// optional query ops), so a backend overrides only what it implements.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::idmap::Idmap;
use crate::inode::{FileAttr, FiemapExtent, Inode, S_IMMUTABLE};
use crate::inode::InodeRef;
use crate::getattr::Kstat;
use crate::inode_times::InodeTimes;
use crate::namei::Cred;
use crate::setattr::Iattr;
use crate::types::{KResult, VfsError};

/// The all-powerful root cred backing [`CreateCtx::root`] — the default-allow
/// identity for internal/path-API creates that carry no caller `Cred`.
static ROOT_CRED: Cred = Cred::root();

/// Creation context threaded into the `i_op` create-family — the Rust analogue
/// of the `struct mnt_idmap *idmap` Linux passes to `->create`/`->mkdir`/
/// `->mknod`/`->symlink`/`->link`/`->rename`, plus the caller `Cred`
/// (fsuid/fsgid + caps) and the `umask` to clear from the requested perm bits.
/// A backend that materialises a new inode stamps its owner from
/// [`fsuid`](Self::fsuid)/[`fsgid`](Self::fsgid) (the caller ids mapped DOWN
/// through the mount idmap, Linux `mapped_fsuid`/`mapped_fsgid`) and its perm
/// bits from [`apply_umask`](Self::apply_umask). # C: O(1)
pub struct CreateCtx<'a> {
    /// Per-mount id map (Linux `mnt_idmap`); identity for a non-idmapped mount.
    pub idmap: &'a crate::idmap::Idmap,
    /// Caller credentials (fsuid/fsgid + DAC caps).
    pub cred: &'a Cred,
    /// `current_umask()` — perm bits cleared from a newly created inode's mode.
    pub umask: u16,
}

impl CreateCtx<'_> {
    /// Identity/root context: no idmap, root cred, no umask. Used by internal
    /// resolves and the path-based `FilesystemType` create that carries no
    /// caller creds. # C: O(1)
    pub fn root() -> CreateCtx<'static> {
        CreateCtx { idmap: &crate::idmap::IDENTITY, cred: &ROOT_CRED, umask: 0 }
    }
    /// fs `i_uid` for a new inode: caller fsuid mapped DOWN through the mount
    /// idmap (Linux `mapped_fsuid`). # C: O(extents)
    pub fn fsuid(&self) -> u32 { self.idmap.map_in_uid(self.cred.uid) }
    /// fs `i_gid` for a new inode: caller fsgid mapped DOWN. # C: O(extents)
    pub fn fsgid(&self) -> u32 { self.idmap.map_in_gid(self.cred.gid) }
    /// Requested perm bits with the umask cleared (Linux `mode & ~umask`).
    /// # C: O(1)
    pub fn apply_umask(&self, mode: u32) -> u32 { mode & !(self.umask as u32) }
}

/// `inode_operations` — the inode's `i_op` namespace/metadata vtable.
pub trait InodeOps: Send + Sync {
    /// `i_op->lookup` — resolve `name` within this directory inode. Default
    /// `Enotdir` (a non-directory has no `lookup`). # C: backend-dependent
    fn lookup(&self, _inode: &Inode, _name: &str) -> KResult<InodeRef> {
        Err(VfsError::Enotdir)
    }

    /// `i_op->create` — create a regular child `name` (`mode` = full umode_t).
    /// `ctx` carries the mount idmap + caller cred + umask for owner/mode.
    /// Default `Erofs`. # C: backend-dependent
    fn create(&self, _inode: &Inode, _name: &str, _mode: u32, _ctx: &CreateCtx) -> KResult<InodeRef> {
        Err(VfsError::Erofs)
    }

    /// `i_op->mkdir` — create a child directory `name`. `ctx` carries the mount
    /// idmap + caller cred + umask. Default `Erofs`. # C: backend-dependent
    fn mkdir(&self, _inode: &Inode, _name: &str, _mode: u32, _ctx: &CreateCtx) -> KResult<InodeRef> {
        Err(VfsError::Erofs)
    }

    /// `i_op->rmdir` — remove the empty child directory `name`. Default `Erofs`.
    /// # C: backend-dependent
    fn rmdir(&self, _inode: &Inode, _name: &str) -> KResult<()> { Err(VfsError::Erofs) }

    /// `i_op->mknod` — create a device/FIFO/socket child. `mode` carries the
    /// `S_IF*` + perm bits, `rdev` the packed `dev_t`. `ctx` carries the mount
    /// idmap + caller cred + umask. Default `Erofs`. # C: backend-dependent
    fn mknod(&self, _inode: &Inode, _name: &str, _mode: u16, _rdev: u32, _ctx: &CreateCtx) -> KResult<()> {
        Err(VfsError::Erofs)
    }

    /// `i_op->symlink` — create a symlink child `name` with body `target`.
    /// `ctx` carries the mount idmap + caller cred (symlinks ignore umask).
    /// Default `Erofs`. # C: backend-dependent
    fn symlink(&self, _inode: &Inode, _name: &str, _target: &[u8], _ctx: &CreateCtx) -> KResult<()> {
        Err(VfsError::Erofs)
    }

    /// `i_op->link` — hard-link `target` into this directory as `name`. `ctx`
    /// carries the caller cred (the linked inode keeps its own owner). Default
    /// `Erofs`. # C: backend-dependent
    fn link(&self, _inode: &Inode, _target: &InodeRef, _name: &str, _ctx: &CreateCtx) -> KResult<()> {
        Err(VfsError::Erofs)
    }

    /// `i_op->unlink` — remove the child file `name`. Default `Erofs`.
    /// # C: backend-dependent
    fn unlink(&self, _inode: &Inode, _name: &str) -> KResult<()> { Err(VfsError::Erofs) }

    /// `i_op->rename` — rename `old_name` (in this dir) to `new_name` in
    /// `new_dir`. `ctx` carries the mount idmap + caller cred (Linux
    /// `->rename(struct mnt_idmap *, ...)`). Default `Erofs`.
    /// # C: backend-dependent
    fn rename(&self, _inode: &Inode, _old_name: &str, _new_dir: &Inode, _new_name: &str, _flags: u32, _ctx: &CreateCtx)
        -> KResult<()> { Err(VfsError::Erofs) }

    /// `i_op->get_link`/`readlink` — symlink target bytes. Default `Einval`
    /// (Linux readlink on a non-symlink). The inline `i_link` fast path is
    /// consulted by [`Inode::get_link`] BEFORE this. # C: O(target_len)
    fn readlink(&self, _inode: &Inode) -> KResult<Vec<u8>> { Err(VfsError::Einval) }

    /// `i_op->getattr` — assemble the stat/statx `Kstat`. Default
    /// `generic_fillattr` over the concrete inode fields + mount idmap.
    /// # C: O(1)
    fn getattr(&self, inode: &Inode, idmap: &Idmap, overlay: Option<InodeTimes>) -> Kstat {
        crate::getattr::generic_fillattr(inode, idmap, overlay)
    }

    /// `i_op->setattr` — apply a prepared `Iattr`. Default `simple_setattr`
    /// (writes the inode's own metadata fields). # C: O(1)
    fn setattr(&self, inode: &Inode, idmap: &Idmap, ia: &Iattr) -> KResult<()> {
        crate::setattr::simple_setattr(inode, idmap, ia)
    }

    /// `i_op->permission` — DAC check for `mask` (`MAY_*`). Default the immutable
    /// write-deny then `generic_permission`. # C: O(ngroups)
    fn permission(&self, inode: &Inode, mask: u32, cred: &Cred) -> KResult<()> {
        // Linux `inode_permission`: no writer to an immutable file, not even
        // CAP_DAC_OVERRIDE — checked before the DAC class check.
        if mask & crate::namei::MAY_WRITE != 0 && inode.i_flags() & S_IMMUTABLE != 0 {
            return Err(VfsError::Eperm);
        }
        crate::namei::generic_permission(inode, mask, cred)
    }

    /// `i_op->fallocate` — ensure backing for `[offset, offset+len)`. Default
    /// `Eopnotsupp`. # C: backend-dependent
    fn fallocate(&self, _inode: &Inode, _offset: u64, _len: u64, _keep_size: bool, _zero_range: bool)
        -> KResult<()> { Err(VfsError::Eopnotsupp) }

    /// `i_op->truncate` — set the file length to `len`. Default `Erofs`
    /// (pseudo/static inodes). # C: backend-dependent
    fn truncate(&self, _inode: &Inode, _len: u64) -> KResult<()> { Err(VfsError::Erofs) }

    /// `i_op->fiemap` — report physical extents over `[start, start+len)` via
    /// `emit` (returns `false` to stop). Default `Eopnotsupp`. # C: O(extents)
    fn fiemap(&self, _inode: &Inode, _start: u64, _len: u64,
              _emit: &mut dyn FnMut(FiemapExtent) -> bool) -> KResult<()> {
        Err(VfsError::Eopnotsupp)
    }

    /// `bmap` — logical block → physical device block (`FIBMAP`). `0` = hole.
    /// Default `Einval`. # C: O(1) amortized
    fn bmap(&self, _inode: &Inode, _block: u64) -> KResult<u64> { Err(VfsError::Einval) }

    /// `i_op->fileattr_get` — `FS_IOC_GETFLAGS`/`FS_IOC_FSGETXATTR` view. Default
    /// `Eopnotsupp`. # C: O(1)
    fn fileattr_get(&self, _inode: &Inode) -> KResult<FileAttr> { Err(VfsError::Eopnotsupp) }

    /// `i_op->fileattr_set` — apply a `chattr` flag change. Default `Eopnotsupp`.
    /// # C: O(1)
    fn fileattr_set(&self, _inode: &Inode, _fa: &FileAttr) -> KResult<()> {
        Err(VfsError::Eopnotsupp)
    }

    /// `i_op->listxattr` — append the NUL-terminated xattr names to `out`,
    /// returning the byte length. Default `Eopnotsupp` (no xattr store).
    /// # C: O(N_xattr)
    fn listxattr(&self, _inode: &Inode, _out: &mut Vec<u8>) -> KResult<usize> {
        Err(VfsError::Eopnotsupp)
    }
}

/// The "generic" default `i_op`: every method takes its trait default
/// (`generic_fillattr`/`simple_setattr`/`generic_permission` for the metadata
/// ops, `Erofs`/`Eopnotsupp` for the mutating/optional ones). Bound on inodes
/// with no backend namespace ops (anon/static/special nodes). # C: O(1)
pub struct DefaultInodeOps;
impl InodeOps for DefaultInodeOps {}

/// Shared `Arc<dyn InodeOps>` for the default vtable. # C: O(1)
pub fn default_inode_ops() -> Arc<dyn InodeOps> { Arc::new(DefaultInodeOps) }

/// Convenience: a `umode_t` from a [`crate::types::FileType`] + perm bits, the
/// shape every `make_*_inode` constructor stamps into `i_mode`. # C: O(1)
pub fn mk_mode(ft: crate::types::FileType, perm: u16) -> u32 {
    (ft.to_ifmt() as u32) | (perm as u32 & 0o7777)
}
