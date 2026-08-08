extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use crate::file_ops::DirContext;
use crate::getattr::Kstat;
use crate::idmap::Idmap;
use crate::setattr::Iattr;
use crate::timespec::Timespec64;
use crate::types::KResult;
use crate::{CreateCtx, namei};

use super::model::{FileAttr, FiemapExtent, Inode, InodeRef};

impl Inode {
    /// `i_op->lookup`. # C: backend-dependent
    pub fn lookup(&self, name: &str) -> KResult<InodeRef> { self.i_op.lookup(self, name) }
    /// `i_op->create`. # C: backend-dependent
    pub fn create_child(&self, name: &str, mode: u32, ctx: &CreateCtx) -> KResult<InodeRef> { self.i_op.create(self, name, mode, ctx) }
    /// `i_op->mkdir`. # C: backend-dependent
    pub fn mkdir(&self, name: &str, mode: u32, ctx: &CreateCtx) -> KResult<InodeRef> { self.i_op.mkdir(self, name, mode, ctx) }
    /// `i_op->rmdir`. # C: backend-dependent
    pub fn rmdir(&self, name: &str) -> KResult<()> { self.i_op.rmdir(self, name) }
    /// `i_op->unlink`. # C: backend-dependent
    pub fn unlink_child(&self, name: &str) -> KResult<()> { self.i_op.unlink(self, name) }
    /// `i_op->symlink`. # C: backend-dependent
    pub fn symlink_child(&self, name: &str, target: &[u8], ctx: &CreateCtx) -> KResult<()> { self.i_op.symlink(self, name, target, ctx) }
    /// `i_op->mknod`. # C: backend-dependent
    pub fn mknod_child(&self, name: &str, mode: u16, rdev: u32, ctx: &CreateCtx) -> KResult<()> { self.i_op.mknod(self, name, mode, rdev, ctx) }
    /// `i_op->link`. # C: backend-dependent
    pub fn link_child(&self, target: &InodeRef, name: &str, ctx: &CreateCtx) -> KResult<()> { self.i_op.link(self, target, name, ctx) }
    /// `i_op->rename`. # C: backend-dependent
    pub fn rename_child(&self, old: &str, new_dir: &Inode, new: &str, flags: u32, ctx: &CreateCtx) -> KResult<()> {
        self.i_op.rename(self, old, new_dir, new, flags, ctx)
    }
    /// `i_op->tmpfile`. # C: backend-dependent
    pub fn tmpfile(&self, mode: u32, ctx: &CreateCtx) -> KResult<InodeRef> { self.i_op.tmpfile(self, mode, ctx) }
    /// `i_op->update_time`. # C: O(1)
    pub fn update_time(&self, now: Timespec64, flags: u32) -> KResult<()> { self.i_op.update_time(self, now, flags) }
    /// `i_op->sync_lazytime` — flush a deferred timestamp. # C: backend-dependent
    pub fn sync_lazytime(&self) -> KResult<()> { self.i_op.sync_lazytime(self) }
    /// `i_op->readlink`. # C: O(target_len)
    pub fn readlink(&self) -> KResult<Vec<u8>> { self.i_op.readlink(self) }
    /// `i_op->get_link` inline fast path first. # C: O(target_len)
    pub fn get_link(&self) -> KResult<Vec<u8>> {
        if let Some(l) = self.i_link() { return Ok(l.to_vec()); }
        self.readlink()
    }
    /// Symlink-follow helper for path walk. # C: O(target_len)
    pub fn follow_link(&self) -> KResult<namei::LinkTarget> {
        if let Some(l) = self.i_link() { return Ok(namei::LinkTarget::Path(l.to_vec())); }
        self.i_op.get_link(self)
    }
    /// `i_op->truncate`. # C: backend-dependent
    pub fn truncate(&self, len: u64) -> KResult<()> { self.i_op.truncate(self, len) }
    /// `f_op->fallocate`. `mode` is a raw `FALLOC_FL_*` combination. # C: backend-dependent
    pub fn fallocate(&self, mode: u32, off: u64, len: u64) -> KResult<()> {
        self.i_op.fallocate(self, mode, off, len)
    }
    /// `i_op->fiemap`. # C: O(extents)
    pub fn fiemap(&self, start: u64, len: u64, emit: &mut dyn FnMut(FiemapExtent) -> bool) -> KResult<()> {
        self.i_op.fiemap(self, start, len, emit)
    }
    /// `bmap`. # C: O(1) amortized
    pub fn bmap(&self, block: u64) -> KResult<u64> { self.i_op.bmap(self, block) }
    /// `i_op->getxattr`. # C: O(log N)
    pub fn getxattr(&self, name: &str) -> Result<Vec<u8>, crate::xattr::XattrError> { self.i_op.getxattr(self, name) }
    /// `i_op->setxattr`. # C: O(log N)
    pub fn setxattr(&self, name: &str, value: Vec<u8>, create: bool, replace: bool) -> Result<(), crate::xattr::XattrError> {
        self.i_op.setxattr(self, name, value, create, replace)
    }
    /// `i_op->removexattr`. # C: O(log N)
    pub fn removexattr(&self, name: &str) -> Result<(), crate::xattr::XattrError> { self.i_op.removexattr(self, name) }
    /// `i_op->listxattr`. # C: O(N)
    pub fn listxattr(&self) -> Result<Vec<String>, crate::xattr::XattrError> { self.i_op.listxattr(self) }
    /// `i_op->fileattr_get`. # C: O(1)
    pub fn fileattr_get(&self) -> KResult<FileAttr> { self.i_op.fileattr_get(self) }
    /// `i_op->fileattr_set`. # C: O(1)
    pub fn fileattr_set(&self, fa: &FileAttr) -> KResult<()> { self.i_op.fileattr_set(self, fa) }
    /// `i_op->permission`. # C: O(ngroups)
    pub fn permission(&self, mask: u32, cred: &namei::Cred) -> KResult<()> { self.i_op.permission(self, mask, cred) }
    /// `i_op->getattr` with the statx request mask and query flags. # C: O(1)
    pub fn getattr_mask(&self, idmap: &Idmap, request_mask: u32, query_flags: u32) -> Kstat {
        self.i_op.getattr(self, idmap, request_mask, query_flags)
    }
    /// `i_op->getattr` for the `stat`-family callers, which have no statx mask:
    /// they ask for the basic set and accept whatever sync the backend prefers.
    /// # C: O(1)
    pub fn getattr(&self, idmap: &Idmap) -> Kstat {
        self.getattr_mask(idmap, crate::getattr::STATX_BASIC_STATS, 0)
    }
    /// `i_op->setattr`. # C: O(1)
    pub fn setattr(&self, idmap: &Idmap, ia: &Iattr) -> KResult<()> { self.i_op.setattr(self, idmap, ia) }

    /// `f_op->read`. # C: backend-dependent
    pub fn read(&self, off: u64, buf: &mut [u8]) -> KResult<usize> { self.i_fop.read(self, off, buf) }
    /// `f_op->write`. # C: backend-dependent
    pub fn write(&self, off: u64, buf: &[u8]) -> KResult<usize> { self.i_fop.write(self, off, buf) }
    /// Non-blocking read. # C: backend-dependent
    pub fn read_nonblock(&self, off: u64, buf: &mut [u8]) -> KResult<usize> { self.i_fop.read_nonblock(self, off, buf) }
    /// Non-blocking write. # C: backend-dependent
    pub fn write_nonblock(&self, off: u64, buf: &[u8]) -> KResult<usize> { self.i_fop.write_nonblock(self, off, buf) }
    /// `f_op->iterate`. # C: backend-dependent
    pub fn readdir(&self, ctx: &mut DirContext) -> KResult<()> { self.i_fop.iterate(self, ctx) }
    /// Does the backend's `iterate` already emit `.`/`..`? # C: O(1)
    pub fn dir_emits_dots(&self) -> bool { self.i_fop.iterate_emits_dots() }
    /// `f_op->poll`. # C: O(1)
    pub fn poll(&self) -> u32 { self.i_fop.poll(self) }
    /// Position-aware poll. # C: O(1)
    pub fn poll_file(&self, pos: u64) -> u32 { self.i_fop.poll_file(self, pos) }
    /// `MAP_SHARED` cache frame. # C: O(log N_pages)
    pub fn mmap_shared_frame(&self, off: u64) -> KResult<Option<crate::SharedFrame>> { self.i_fop.mmap_shared_frame(self, off) }
    /// Huge-page size this inode's pages ARE, or 0 for base pages
    /// (`hstate_inode`). # C: O(1)
    pub fn huge_page_size(&self) -> u64 { self.i_fop.huge_page_size(self) }
    /// A private copy of the huge page at `off`. # C: O(huge page)
    pub fn huge_cow_frame(&self, off: u64) -> KResult<Option<crate::SharedFrame>> {
        self.i_fop.huge_cow_frame(self, off)
    }
    /// Release one reference to a huge page this inode handed out. # C: O(log nr)
    pub fn huge_put_frame(&self, pa: u64) { self.i_fop.huge_put_frame(self, pa) }
    /// `f_op->open` hook. # C: O(1)
    pub fn on_open(&self) -> KResult<()> { self.i_fop.on_open(self) }
    /// `f_op->release` hook. # C: O(1)
    pub fn on_release(&self) { self.i_fop.on_release(self) }
    /// `f_op->flush` hook. # C: O(1)
    pub fn on_flush(&self) -> KResult<()> { self.i_fop.on_flush(self) }
    /// `show_fdinfo` extra lines. # C: O(1)
    pub fn fdinfo_extra(&self, out: &mut Vec<u8>) { self.i_fop.fdinfo_extra(self, out) }
}
