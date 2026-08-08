// hugetlbfs directory state and the namespace mutators over it.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use sync::{Inode as InodeClass, Spinlock};
use vfs::superblock::SuperBlock;
use vfs::{CookieEntry, CreateCtx, DirContext, FileOps, FileType, Ino, Inode, InodeBuilder,
          InodeOps, InodeRef, KResult, VfsError, mk_mode};

use super::accounting::HugetlbfsSb;
use super::file::make_file_inode;
use super::inode::{fsid_of, iget_or_build, next_ino};

/// # C: O(1)
pub(super) fn as_dir(i: &InodeRef) -> Option<&HugetlbfsDirData> { i.private::<HugetlbfsDirData>() }

/// One directory's children. Resolution is per-component `i_op->lookup`; there
/// is no whole-path key and no global registry.
pub struct HugetlbfsDirData {
    sb:   Spinlock<Weak<SuperBlock>, InodeClass>,
    kids: Spinlock<BTreeMap<String, InodeRef>, InodeClass>,
    acct: Arc<HugetlbfsSb>,
}

impl HugetlbfsDirData {
    /// Stamp the owning SB at `fill_super`. # C: O(1)
    pub(super) fn set_sb(&self, sb: Weak<SuperBlock>) { *self.sb.lock() = sb; }
    /// # C: O(1)
    fn sb_weak(&self) -> Weak<SuperBlock> { self.sb.lock().clone() }
}

/// Build a hugetlbfs directory inode. `i_nlink` starts at 2 (`.` plus the
/// parent's link down). # C: O(1)
pub(super) fn make_dir_inode(ino: Ino, perm: u16, uid: u32, gid: u32, sb: Weak<SuperBlock>,
                             acct: Arc<HugetlbfsSb>) -> InodeRef {
    let sb2 = sb.clone();
    iget_or_build(&sb, ino, move || {
        let mut b = InodeBuilder::new(ino, mk_mode(FileType::Directory, perm),
            Arc::new(HugetlbfsDirOps), Arc::new(HugetlbfsDirFileOps))
            .owner(uid, gid)
            .btime(crate::tmpfs::birth_time())
            .fsid(fsid_of(&sb2))
            .xattrs(vfs::SimpleXattrs::new())
            .private(Arc::new(HugetlbfsDirData {
                sb:   Spinlock::new(sb2.clone()),
                kids: Spinlock::new(BTreeMap::new()),
                acct,
            }));
        if let Some(s) = sb2.upgrade() { b = b.sb(Arc::downgrade(&s)); }
        b.build()
    })
}

/// `i_fop` for a hugetlbfs directory.
struct HugetlbfsDirFileOps;
impl FileOps for HugetlbfsDirFileOps {
    /// # C: O(N log N)
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let d = inode.private::<HugetlbfsDirData>().ok_or(VfsError::Enotdir)?;
        let mut es: Vec<CookieEntry> = d.kids.lock().iter()
            .map(|(name, c)| CookieEntry::new(name.clone(), c.ino(), c.file_type()))
            .collect();
        vfs::emit_by_cookie(&mut es, ctx)
    }
}

/// `i_op` for a hugetlbfs directory.
struct HugetlbfsDirOps;
impl InodeOps for HugetlbfsDirOps {
    /// # C: O(log N)
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<HugetlbfsDirData>().ok_or(VfsError::Enotdir)?;
        d.kids.lock().get(name).cloned().ok_or(VfsError::Enoent)
    }

    /// `hugetlbfs_create`. The mount's `nr_inodes=` is enforced here, with the
    /// `ENOSPC` a full filesystem gives. # C: O(log N)
    fn create(&self, inode: &Inode, name: &str, mode: u32, ctx: &CreateCtx) -> KResult<InodeRef> {
        let d = inode.private::<HugetlbfsDirData>().ok_or(VfsError::Enotdir)?;
        let mut g = d.kids.lock();
        if g.contains_key(name) { return Err(VfsError::Eexist); }
        let child = make_file_inode(mode as u16 & 0o7777, ctx.fsuid(), ctx.fsgid(),
                                    d.sb_weak(), d.acct.clone()).ok_or(VfsError::Enospc)?;
        g.insert(name.into(), child.clone());
        Ok(child)
    }

    /// `hugetlbfs_mkdir`. # C: O(log N)
    fn mkdir(&self, inode: &Inode, name: &str, mode: u32, ctx: &CreateCtx) -> KResult<InodeRef> {
        let d = inode.private::<HugetlbfsDirData>().ok_or(VfsError::Enotdir)?;
        let mut g = d.kids.lock();
        if g.contains_key(name) { return Err(VfsError::Eexist); }
        if !d.acct.charge_inode() { return Err(VfsError::Enospc); }
        let child = make_dir_inode(next_ino(), mode as u16 & 0o7777, ctx.fsuid(), ctx.fsgid(),
                                   d.sb_weak(), d.acct.clone());
        g.insert(name.into(), child.clone());
        inode.inc_nlink();
        Ok(child)
    }

    /// `simple_unlink`. # C: O(log N)
    fn unlink(&self, inode: &Inode, name: &str) -> KResult<()> {
        let d = inode.private::<HugetlbfsDirData>().ok_or(VfsError::Enotdir)?;
        let mut g = d.kids.lock();
        let child = g.get(name).cloned().ok_or(VfsError::Enoent)?;
        if child.file_type() == FileType::Directory { return Err(VfsError::Eisdir); }
        g.remove(name);
        child.drop_nlink();
        Ok(())
    }

    /// `simple_rmdir` — an occupied directory is `ENOTEMPTY`. # C: O(log N)
    fn rmdir(&self, inode: &Inode, name: &str) -> KResult<()> {
        let d = inode.private::<HugetlbfsDirData>().ok_or(VfsError::Enotdir)?;
        let mut g = d.kids.lock();
        let child = g.get(name).cloned().ok_or(VfsError::Enoent)?;
        let cd = child.private::<HugetlbfsDirData>().ok_or(VfsError::Enotdir)?;
        if !cd.kids.lock().is_empty() { return Err(VfsError::Enotempty); }
        g.remove(name);
        d.acct.free_inode();
        inode.drop_nlink();
        Ok(())
    }
}
