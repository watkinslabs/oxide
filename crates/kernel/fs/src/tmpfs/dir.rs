use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};

use sync::{Spinlock, Inode as InodeClass};
use vfs::{CreateCtx, Devt, DirContext, FileOps, FileType, Ino, Inode, InodeBuilder, InodeOps, InodeRef, KResult, VfsError, make_device_node_inode, mk_mode};
use vfs::superblock::SuperBlock;

use super::accounting::TmpfsSb;
use super::file::make_tmpfs_file_inode;
use super::flags::{S_IFBLK, S_IFCHR, S_IFIFO, S_IFMT, S_IFSOCK};
use super::inode::{fsid_of, iget_or_build, next_ino};
use super::special::{make_tmpfs_sock_inode, make_tmpfs_special_inode};
use super::symlink::make_tmpfs_symlink_inode;

pub(super) fn as_dir(i: &InodeRef) -> Option<&TmpfsDirData> {
    i.private::<TmpfsDirData>()
}

/// Per-instance tmpfs directory state (Linux `i_private`). Its `kids` map IS
/// the directory — resolution is per-component `i_op->lookup`, no whole-path
/// key, no global registry. Every child it creates inherits this dir's `sb`
/// weak, so `fsid` derives from the mount's `s_dev`.
pub struct TmpfsDirData {
    sb:   Spinlock<Weak<SuperBlock>, InodeClass>,
    pub(super) kids: Spinlock<BTreeMap<String, InodeRef>, InodeClass>,
    /// Owning mount's space accounting (inode charge/uncharge + block
    /// propagation to children). Shared `Arc` across the whole instance. # D33
    pub(super) acct: Arc<TmpfsSb>,
}

impl TmpfsDirData {
    /// This dir's owning-SB weak (handed to every child). # C: O(1)
    fn sb_weak(&self) -> Weak<SuperBlock> { self.sb.lock().clone() }
    /// Stamp the owning SB (`TmpfsFs::set_sb` at `fill_super`). # C: O(1)
    pub(super) fn set_sb(&self, sb: Weak<SuperBlock>) { *self.sb.lock() = sb; }
    /// Raw insert of an existing inode (rename / hardlink). # C: O(log N)
    pub(super) fn insert(&self, name: &str, inode: InodeRef) { self.kids.lock().insert(name.into(), inode); }
    /// Raw remove (rename). # C: O(log N)
    pub(super) fn remove(&self, name: &str) -> Option<InodeRef> { self.kids.lock().remove(name) }
}

/// Build a fresh tmpfs directory inode (`ino`, `perm` permission bits, owned by
/// `sb`). `i_nlink` defaults to 2 (`.` + the parent's link), per Linux
/// `simple_fs`. # C: O(1)
pub(super) fn make_tmpfs_dir_inode(ino: Ino, perm: u16, uid: u32, gid: u32, sb: Weak<SuperBlock>, acct: Arc<TmpfsSb>) -> InodeRef {
    let sb2 = sb.clone();
    iget_or_build(&sb, ino, move || {
        let mut b = InodeBuilder::new(ino, mk_mode(FileType::Directory, perm),
            Arc::new(TmpfsDirOps), Arc::new(TmpfsDirFileOps))
            .owner(uid, gid)
            .fsid(fsid_of(&sb2))
            .xattrs(vfs::SimpleXattrs::new())
            .private(Arc::new(TmpfsDirData {
                sb:   Spinlock::new(sb2.clone()),
                kids: Spinlock::new(BTreeMap::new()),
                acct,
            }));
        if let Some(s) = sb2.upgrade() { b = b.sb(Arc::downgrade(&s)); }
        b.build()
    })
}

/// `i_fop` for a tmpfs directory (readdir). # C: O(1)
struct TmpfsDirFileOps;
impl FileOps for TmpfsDirFileOps {
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let d = inode.private::<TmpfsDirData>().ok_or(VfsError::Enotdir)?;
        let g = d.kids.lock();
        let off = ctx.pos as usize;
        let mut idx = off;
        for (name, child) in g.iter().skip(off) {
            let next = idx as u64 + 1;
            if !ctx.emit(name, child.ino(), child.file_type(), next) { return Ok(()); }
            idx += 1;
        }
        Ok(())
    }
}

/// `i_op` for a tmpfs directory (lookup + namespace mutators). # C: O(log N)
struct TmpfsDirOps;
impl InodeOps for TmpfsDirOps {
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let d = inode.private::<TmpfsDirData>().ok_or(VfsError::Enotdir)?;
        d.kids.lock().get(name).cloned().ok_or(VfsError::Enoent)
    }

    /// `mkdir` — a fresh child `TmpfsDir` in this instance's tree. Honours the
    /// caller-supplied `mode` (perm bits; umask is applied at the syscall
    /// layer). The new dir starts at `i_nlink == 2` (`.` + this parent's link
    /// down) and the PARENT gains a link (the child's `..`), matching Linux
    /// `simple_mkdir`/`inc_nlink(dir)`. # C: O(log N)
    fn mkdir(&self, inode: &Inode, name: &str, mode: u32, ctx: &CreateCtx) -> KResult<InodeRef> {
        let dd = inode.private::<TmpfsDirData>().ok_or(VfsError::Enotdir)?;
        let mut g = dd.kids.lock();
        if g.contains_key(name) { return Err(VfsError::Eexist); }
        if !dd.acct.charge_inode() { return Err(VfsError::Enospc); }
        let ino = next_ino();
        let (uid, gid, m) = vfs::prepare_create_owner_mode(ctx.idmap, inode, mode as u16,
            0o1777, vfs::types::S_IFDIR, ctx.cred, ctx.umask);
        let d = make_tmpfs_dir_inode(ino, m & 0o7777, uid, gid, dd.sb_weak(), dd.acct.clone());
        g.insert(name.into(), d.clone());
        inode.inc_nlink(); // child's ".." adds a link to this parent dir
        Ok(d)
    }

    /// `rmdir` — ENOTEMPTY when the child dir still has entries. Removing the
    /// child drops this parent's `i_nlink` (the gone `..`), mirroring Linux
    /// `simple_rmdir`/`drop_nlink(dir)`. # C: O(log N)
    fn rmdir(&self, inode: &Inode, name: &str) -> KResult<()> {
        let dd = inode.private::<TmpfsDirData>().ok_or(VfsError::Enotdir)?;
        let mut g = dd.kids.lock();
        match g.get(name) {
            None => return Err(VfsError::Enoent),
            Some(i) if i.file_type() != FileType::Directory => return Err(VfsError::Enotdir),
            Some(i) => {
                if let Some(d) = as_dir(i) {
                    if !d.kids.lock().is_empty() { return Err(VfsError::Enotempty); }
                }
            }
        }
        if let Some(victim) = g.remove(name) {
            victim.set_nlink(0);   // emptied dir: drop "." + parent's link down
            inode.drop_nlink();    // the child's ".." no longer points at us
            dd.acct.free_inode();  // reclaim the dir inode (f_ffree)
        }
        Ok(())
    }

    /// `create` — a fresh regular file honouring the caller-supplied `mode`
    /// (perm bits; umask is applied at the syscall layer). # C: O(log N)
    fn create(&self, inode: &Inode, name: &str, mode: u32, ctx: &CreateCtx) -> KResult<InodeRef> {
        let dd = inode.private::<TmpfsDirData>().ok_or(VfsError::Enotdir)?;
        let mut g = dd.kids.lock();
        if g.contains_key(name) { return Err(VfsError::Eexist); }
        if !dd.acct.charge_inode() { return Err(VfsError::Enospc); }
        let (uid, gid, m) = vfs::prepare_create_owner_mode(ctx.idmap, inode, mode as u16,
            0o7777, vfs::types::S_IFREG, ctx.cred, ctx.umask);
        let child = make_tmpfs_file_inode(false, m & 0o7777, uid, gid, dd.sb_weak(), dd.acct.clone());
        g.insert(name.into(), child.clone());
        Ok(child)
    }

    /// `tmpfile` — `open(O_TMPFILE)`: a fresh anonymous regular inode in this
    /// instance's fs with NO directory entry and `i_nlink == 0` (Linux
    /// `shmem_tmpfile` → `d_tmpfile`, which drops the link), so it is reclaimed
    /// when its last fd closes; a later `linkat(AT_EMPTY_PATH)` re-links it.
    /// Owner = caller fsuid/fsgid (idmap-mapped), perm = `mode` with umask
    /// cleared. Like `create_anonymous` it is not inode-charged (no name). # C: O(1)
    fn tmpfile(&self, inode: &Inode, mode: u32, ctx: &CreateCtx) -> KResult<InodeRef> {
        let dd = inode.private::<TmpfsDirData>().ok_or(VfsError::Enotdir)?;
        let (uid, gid, m) = vfs::prepare_create_owner_mode(ctx.idmap, inode, mode as u16,
            0o7777, vfs::types::S_IFREG, ctx.cred, ctx.umask);
        let child = make_tmpfs_file_inode(false, m & 0o7777, uid, gid, dd.sb_weak(), dd.acct.clone());
        child.set_nlink(0); // O_TMPFILE: unlinked until linkat gives it a name
        Ok(child)
    }

    /// `unlink` — remove a non-directory child. A directory victim is rejected
    /// with `EISDIR` (Linux `unlink(2)`; directories go through `rmdir`).
    /// Dropping the name decrements the victim's `i_nlink` (Linux
    /// `drop_nlink`); the inode's storage is freed once the count and all open
    /// fds reach zero. # C: O(log N)
    fn unlink(&self, inode: &Inode, name: &str) -> KResult<()> {
        let dd = inode.private::<TmpfsDirData>().ok_or(VfsError::Enotdir)?;
        let mut g = dd.kids.lock();
        match g.get(name) {
            None => Err(VfsError::Enoent),
            Some(i) if i.file_type() == FileType::Directory => Err(VfsError::Eisdir),
            Some(_) => {
                let victim = g.remove(name).expect("present");
                victim.drop_nlink();
                // Reclaim the inode only when the last name is gone (a hardlink
                // target with nlink>0 keeps its single charged inode). # D33
                if victim.nlink() == 0 { dd.acct.free_inode(); }
                Ok(())
            }
        }
    }

    /// `symlink(2)` — a followable tmpfs symlink child. # C: O(log N)
    fn symlink(&self, inode: &Inode, name: &str, target: &[u8], ctx: &CreateCtx) -> KResult<()> {
        let dd = inode.private::<TmpfsDirData>().ok_or(VfsError::Enotdir)?;
        let mut g = dd.kids.lock();
        if g.contains_key(name) { return Err(VfsError::Eexist); }
        if !dd.acct.charge_inode() { return Err(VfsError::Enospc); }
        let (uid, gid) = vfs::prepare_symlink_owner(ctx.idmap, inode, ctx.cred);
        g.insert(name.into(), make_tmpfs_symlink_inode(target, uid, gid, dd.sb_weak()));
        Ok(())
    }

    /// `mknod(2)` — FIFO/socket stay tmpfs special inodes; CHR/BLK become a
    /// device-node inode that dispatches I/O to the driver registered by
    /// `(major,minor)` (so `mknod /dev/zero c 1 5` then read returns zeros).
    /// # C: O(log N)
    fn mknod(&self, inode: &Inode, name: &str, mode: u16, rdev: u32, ctx: &CreateCtx) -> KResult<()> {
        let dd = inode.private::<TmpfsDirData>().ok_or(VfsError::Enotdir)?;
        let mut g = dd.kids.lock();
        if g.contains_key(name) { return Err(VfsError::Eexist); }
        if !dd.acct.charge_inode() { return Err(VfsError::Enospc); }
        let sb = dd.sb_weak();
        let (uid, gid, m) = vfs::prepare_create_owner_mode(ctx.idmap, inode, mode,
            mode, mode, ctx.cred, ctx.umask);
        let perm = m & 0o7777;
        let child: InodeRef = match mode & S_IFMT {
            S_IFIFO  => make_tmpfs_special_inode(FileType::Fifo, perm, 0, uid, gid, sb),
            S_IFSOCK => make_tmpfs_sock_inode(perm, uid, gid, sb),
            S_IFCHR  => make_device_node_inode(
                next_ino(), FileType::CharDev,
                Devt::from_raw(rdev), perm, sb),
            S_IFBLK  => make_device_node_inode(
                next_ino(), FileType::BlockDev,
                Devt::from_raw(rdev), perm, sb),
            _ => { dd.acct.free_inode(); return Err(VfsError::Einval); }
        };
        g.insert(name.into(), child);
        Ok(())
    }

    /// `i_op->rename` (Linux `shmem_rename2` → `simple_offset_rename*` /
    /// `simple_rename_exchange`): mutate resolved parent directories directly
    /// for plain rename, `RENAME_EXCHANGE` and `RENAME_WHITEOUT`; no whole-path
    /// string rewalk. Rejects any flag outside the three shmem implements, so
    /// an unsupported bit can never be accepted-and-ignored. Directory moves
    /// carry the `..` link accounting (`drop_nlink(old_dir)` /
    /// `inc_nlink(new_dir)`) the same way `mkdir`/`rmdir` above do.
    /// # C: O(log N)
    fn rename(&self, inode: &Inode, old_name: &str, new_dir: &Inode, new_name: &str, flags: u32, _ctx: &CreateCtx)
        -> KResult<()>
    {
        use vfs::namei::{RENAME_EXCHANGE, RENAME_NOREPLACE, RENAME_WHITEOUT};
        if flags & !(RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT) != 0 {
            return Err(VfsError::Einval);
        }
        let sdir = inode.private::<TmpfsDirData>().ok_or(VfsError::Enotdir)?;
        let ddir = new_dir.private::<TmpfsDirData>().ok_or(VfsError::Enotdir)?;
        let same_parent = core::ptr::eq(sdir, ddir);
        if flags & RENAME_EXCHANGE != 0 {
            if same_parent {
                let mut g = sdir.kids.lock();
                if old_name == new_name { return if g.contains_key(old_name) { Ok(()) } else { Err(VfsError::Enoent) }; }
                let a = g.get(old_name).cloned().ok_or(VfsError::Enoent)?;
                let b = g.get(new_name).cloned().ok_or(VfsError::Enoent)?;
                g.insert(old_name.into(), b);
                g.insert(new_name.into(), a);
                return Ok(());
            }
            let (a, b) = {
                let mut sg = sdir.kids.lock();
                let mut dg = ddir.kids.lock();
                let a = sg.get(old_name).cloned().ok_or(VfsError::Enoent)?;
                let b = dg.get(new_name).cloned().ok_or(VfsError::Enoent)?;
                sg.insert(old_name.into(), b.clone());
                dg.insert(new_name.into(), a.clone());
                (a, b)
            };
            // `simple_rename_exchange`: only a MIXED pair shifts a `..` between
            // the two parents; swapping two directories leaves both counts.
            let (a_dir, b_dir) = (a.file_type() == FileType::Directory, b.file_type() == FileType::Directory);
            if a_dir && !b_dir { inode.drop_nlink(); new_dir.inc_nlink(); }
            if !a_dir && b_dir { new_dir.drop_nlink(); inode.inc_nlink(); }
            return Ok(());
        }
        // `shmem_rename2`: `!simple_empty(new_dentry)` → ENOTEMPTY. A negative
        // or non-directory destination is "empty" by that definition.
        if let Some(victim) = ddir.kids.lock().get(new_name) {
            if let Some(vd) = as_dir(victim) {
                if !vd.kids.lock().is_empty() { return Err(VfsError::Enotempty); }
            }
        }
        let moved = sdir.remove(old_name).ok_or(VfsError::Enoent)?;
        let moved_is_dir = moved.file_type() == FileType::Directory;
        let replaced = ddir.remove(new_name);
        if let Some(victim) = replaced.as_ref() {
            if victim.file_type() == FileType::Directory { victim.set_nlink(0); }
            else { victim.drop_nlink(); }
            if victim.nlink() == 0 { ddir.acct.free_inode(); }
        }
        if flags & RENAME_WHITEOUT != 0 {
            let sb = sdir.sb_weak();
            let wo = make_device_node_inode(next_ino(), FileType::CharDev, Devt::from_raw(0), 0, sb);
            sdir.insert(old_name, wo);
        }
        ddir.insert(new_name, moved);
        // A moved directory takes its `..` with it: the replaced-victim case
        // already surrendered the destination's incoming link (`set_nlink(0)`
        // above), so only the source parent drops one; otherwise the
        // destination gains one.
        if moved_is_dir {
            if replaced.is_some() { inode.drop_nlink(); }
            else if !same_parent { inode.drop_nlink(); new_dir.inc_nlink(); }
        }
        Ok(())
    }

    /// `i_op->link` (Linux `shmem_link` reached via `vfs_link`): add another
    /// name in THIS directory for the existing `target` inode (a hardlink).
    /// EEXIST if `name` is taken; a directory target is EPERM (Linux forbids
    /// directory hardlinks). Bumps the inode's in-memory `i_nlink` (Linux
    /// `inc_nlink`). The resolved-parent variant of `TmpfsFs::link_inode`.
    /// # C: O(log N)
    fn link(&self, inode: &Inode, target: &InodeRef, name: &str, _ctx: &CreateCtx) -> KResult<()> {
        if target.file_type() == FileType::Directory { return Err(VfsError::Eperm); }
        let dd = inode.private::<TmpfsDirData>().ok_or(VfsError::Enotdir)?;
        let mut g = dd.kids.lock();
        if g.contains_key(name) { return Err(VfsError::Eexist); }
        target.inc_nlink(); // a new name for the same inode (Linux inc_nlink)
        g.insert(name.into(), target.clone());
        Ok(())
    }
}
