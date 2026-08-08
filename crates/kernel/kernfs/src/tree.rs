use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use sync::{Kernfs as KernfsClass, Spinlock};
use vfs::superblock::SuperBlock;
use vfs::{CookieEntry, CreateCtx, DirContext, FileType, Ino, Inode, InodeBuilder, InodeRef, KResult, VfsError, default_file_ops, default_inode_ops, mk_mode};

use crate::dir_ops::{DirFileattr, PseudoDirFileOps, PseudoDirOps};
use crate::mount_opts::DirAttr;

/// Deterministic inode number from a path (FNV-1a, tagged into the
/// synthetic-dir range so it never collides with leaf inodes). # C: O(len)
pub fn dir_ino(path: &str) -> Ino {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in path.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    0x5000_0000_0000_0000 | (h & 0x0fff_ffff_ffff_ffff)
}

// Child module manifest: `clone` owns the per-mount-namespace deep copy.
mod clone;

fn components(path: &str) -> Vec<&str> {
    path.split('/').filter(|c| !c.is_empty()).collect()
}

/// A symlink leaf in a pseudo-fs tree (lifted from devfs `DevSymlink`).
pub struct PseudoSymlink;

impl PseudoSymlink {
    pub fn new(ino: Ino, fsid: u64, target: &[u8]) -> InodeRef {
        InodeBuilder::new(
            ino,
            mk_mode(FileType::Symlink, 0o777),
            default_inode_ops(),
            default_file_ops(),
        )
        .fsid(fsid)
        .size(target.len() as u64)
        .link(target.to_vec().into_boxed_slice())
        .build()
    }
}

pub(crate) enum PseudoEntry {
    Dir(Arc<PseudoDir>),
    Leaf(InodeRef),
}

impl PseudoEntry {
    pub(crate) fn file_type(&self) -> FileType {
        match self {
            PseudoEntry::Dir(_) => FileType::Directory,
            PseudoEntry::Leaf(i) => i.file_type(),
        }
    }

    pub(crate) fn ino(&self) -> Ino {
        match self {
            PseudoEntry::Dir(d) => d.ino,
            PseudoEntry::Leaf(i) => i.ino(),
        }
    }

    fn collect_inodes(&self, out: &mut Vec<InodeRef>) {
        match self {
            PseudoEntry::Leaf(i) => out.push(Arc::clone(i)),
            PseudoEntry::Dir(d) => {
                for child in d.children.lock().values() { child.collect_inodes(out); }
                out.push(d.as_inode());
            }
        }
    }
}

pub struct PseudoDir {
    pub(crate) ino: Ino,
    pub(crate) path: String,
    pub(crate) fsid: u64,
    pub(crate) sb: Spinlock<Weak<SuperBlock>, KernfsClass>,
    pub(crate) children: Spinlock<BTreeMap<String, PseudoEntry>, KernfsClass>,
    pub(crate) inode: Spinlock<Weak<Inode>, KernfsClass>,
    pub(crate) hooks: Spinlock<Option<Arc<dyn PseudoDirHooks>>, KernfsClass>,
    /// Owner + permission bits this directory's inode is BORN with.
    ///
    /// The inode itself is a cache entry — `as_inode` rebuilds it whenever the
    /// superblock's icache has dropped it — so a mount option that only wrote
    /// `i_uid`/`i_mode` would be forgotten at the next lookup. The durable
    /// answer lives here, on the tree node, and [`Self::set_attr`] writes both
    /// halves so the live inode and every future rebuild agree.
    pub(crate) attr: Spinlock<DirAttr, KernfsClass>,
    /// The `i_op` vector every directory inode in THIS tree is built with —
    /// the owning filesystem's inode-op default, fixed at root creation and
    /// inherited by every child dir. One choke point: `as_inode` is the only
    /// place a pseudo-directory inode is constructed.
    pub(crate) dir_iops: Arc<dyn vfs::InodeOps>,
}

pub trait PseudoDirHooks: Send + Sync {
    fn mkdir(&self, dir: &PseudoDir, name: &str, mode: u32, ctx: &CreateCtx) -> KResult<Option<InodeRef>> {
        let _ = (dir, name, mode, ctx);
        Ok(None)
    }
    fn rmdir(&self, dir: &PseudoDir, name: &str) -> KResult<bool> {
        let _ = (dir, name);
        Ok(false)
    }
}

impl PseudoDir {
    /// Tree root with the pseudo-filesystem inode-op default (no fileattr
    /// vector). # C: O(1)
    pub fn new_root(root_ino: Ino, fsid: u64) -> Arc<PseudoDir> {
        Self::new_root_with_fileattr(root_ino, fsid, DirFileattr::Absent)
    }

    /// Tree root whose directory inodes publish `fileattr`. The device
    /// filesystem passes [`DirFileattr::Shmem`] because its tree is a
    /// shmem-backed mount. # C: O(1)
    pub fn new_root_with_fileattr(root_ino: Ino, fsid: u64, fileattr: DirFileattr) -> Arc<PseudoDir> {
        Arc::new(PseudoDir {
            ino: root_ino,
            path: String::new(),
            fsid,
            sb: Spinlock::new(Weak::new()),
            children: Spinlock::new(BTreeMap::new()),
            inode: Spinlock::new(Weak::new()),
            hooks: Spinlock::new(None),
            attr: Spinlock::new(DirAttr::default()),
            dir_iops: Arc::new(PseudoDirOps::new(fileattr)),
        })
    }

    fn child_at(path: String, fsid: u64, sb: Weak<SuperBlock>,
                dir_iops: Arc<dyn vfs::InodeOps>) -> Arc<PseudoDir> {
        Arc::new(PseudoDir {
            ino: dir_ino(&path),
            path,
            fsid,
            sb: Spinlock::new(sb),
            children: Spinlock::new(BTreeMap::new()),
            inode: Spinlock::new(Weak::new()),
            hooks: Spinlock::new(None),
            attr: Spinlock::new(DirAttr::default()),
            dir_iops,
        })
    }

    /// This directory's birth owner and permission bits. # C: O(1)
    pub fn attr(&self) -> DirAttr { *self.attr.lock() }

    /// Stamp a new owner/permission on this directory: the durable record on
    /// the node AND the inode that is live right now, so a mount option takes
    /// effect immediately and survives the icache dropping the inode.
    /// # C: O(1)
    pub fn set_attr(self: &Arc<PseudoDir>, attr: DirAttr) {
        *self.attr.lock() = attr;
        let inode = self.as_inode();
        let _ = inode.set_owner(attr.uid, attr.gid);
        let _ = inode.set_perm(attr.perm);
    }

    pub fn set_sb(&self, sb: Weak<SuperBlock>) {
        *self.sb.lock() = sb.clone();
        *self.inode.lock() = Weak::new();
        let g = self.children.lock();
        for v in g.values() {
            if let PseudoEntry::Dir(d) = v {
                d.set_sb(sb.clone());
            }
        }
    }

    pub fn as_inode(self: &Arc<PseudoDir>) -> InodeRef {
        let sbw = self.sb.lock().clone();
        let me = Arc::clone(self);
        let sbw2 = sbw.clone();
        let build = move || {
            let a = *me.attr.lock();
            let mut b = InodeBuilder::new(
                me.ino,
                mk_mode(FileType::Directory, a.perm),
                Arc::clone(&me.dir_iops),
                Arc::new(PseudoDirFileOps),
            )
            .owner(a.uid, a.gid)
            .private(Arc::clone(&me) as Arc<dyn core::any::Any + Send + Sync>)
            .sb(sbw2.clone());
            if sbw2.upgrade().is_none() {
                b = b.fsid(me.fsid);
            }
            b.build()
        };
        match sbw.upgrade() {
            Some(sb) => sb.iget(self.ino, build),
            None => {
                let mut g = self.inode.lock();
                if let Some(i) = g.upgrade() {
                    return i;
                }
                let inode = build();
                *g = Arc::downgrade(&inode);
                inode
            }
        }
    }

    pub(crate) fn leaf_iget(&self, leaf: &InodeRef) -> InodeRef {
        match self.sb.lock().clone().upgrade() {
            Some(sb) => {
                let l = Arc::clone(leaf);
                sb.iget(leaf.ino(), move || l)
            }
            None => Arc::clone(leaf),
        }
    }

    pub(crate) fn sb_weak(&self) -> Weak<SuperBlock> {
        self.sb.lock().clone()
    }

    pub fn path(&self) -> &str { &self.path }

    /// Names of this directory's children, sorted. A read view over the tree
    /// that already exists, for a projection that must enumerate it rather
    /// than keep a second list of what is registered. # C: O(N children)
    pub fn child_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.children.lock().keys().cloned().collect();
        names.sort();
        names
    }

    fn child_dir(self: &Arc<PseudoDir>, name: &str) -> Arc<PseudoDir> {
        let mut g = self.children.lock();
        if let Some(PseudoEntry::Dir(d)) = g.get(name) {
            return Arc::clone(d);
        }
        let mut cp = self.path.clone();
        cp.push('/');
        cp.push_str(name);
        let d = PseudoDir::child_at(cp, self.fsid, self.sb_weak(), Arc::clone(&self.dir_iops));
        g.insert(String::from(name), PseudoEntry::Dir(Arc::clone(&d)));
        d
    }

    pub fn insert_path(self: &Arc<PseudoDir>, full_path: &str, inode: InodeRef) {
        let comps = components(full_path);
        if comps.is_empty() {
            return;
        }
        let mut dir = Arc::clone(self);
        for c in &comps[..comps.len() - 1] {
            dir = dir.child_dir(c);
        }
        let leaf = comps[comps.len() - 1];
        let mut g = dir.children.lock();
        match g.get(leaf) {
            Some(PseudoEntry::Dir(_)) => {}
            _ => {
                g.insert(String::from(leaf), PseudoEntry::Leaf(inode));
            }
        }
    }

    /// Publish one object inode under this directory.  The tree retains the
    /// only namespace reference; callers keep object lifetime in the inode.
    /// # C: O(log N)
    pub fn insert_leaf(&self, name: &str, inode: InodeRef) -> KResult<()> {
        if name.is_empty() || name.contains('/') { return Err(VfsError::Einval); }
        let mut children = self.children.lock();
        if children.contains_key(name) { return Err(VfsError::Eexist); }
        children.insert(String::from(name), PseudoEntry::Leaf(inode));
        Ok(())
    }

    /// Remove one non-directory object inode from this directory.
    /// # C: O(log N)
    pub fn remove_leaf(&self, name: &str) -> KResult<InodeRef> {
        let mut children = self.children.lock();
        match children.get(name) {
            None => return Err(VfsError::Enoent),
            Some(PseudoEntry::Dir(_)) => return Err(VfsError::Eisdir),
            Some(PseudoEntry::Leaf(_)) => {}
        }
        let removed = match children.remove(name) {
            Some(PseudoEntry::Leaf(inode)) => inode,
            _ => unreachable!(),
        };
        drop(children);
        crate::reval::forget_detached(self, core::slice::from_ref(&removed));
        Ok(removed)
    }

    pub fn ensure_dir_path(self: &Arc<PseudoDir>, path: &str) {
        let comps = components(path);
        let mut dir = Arc::clone(self);
        for c in &comps {
            dir = dir.child_dir(c);
        }
    }

    pub fn ensure_dir_path_with_hooks(self: &Arc<PseudoDir>, path: &str, hooks: Arc<dyn PseudoDirHooks>) {
        let comps = components(path);
        let mut dir = Arc::clone(self);
        for c in &comps {
            dir = dir.child_dir(c);
        }
        *dir.hooks.lock() = Some(hooks);
    }

    /// The child DIRECTORY at `path`, for a reader that must enumerate it
    /// rather than open one entry. # C: O(depth)
    pub fn lookup_dir(self: &Arc<PseudoDir>, path: &str) -> Option<Arc<PseudoDir>> {
        let comps = components(path);
        let mut dir = Arc::clone(self);
        for c in &comps {
            let g = dir.children.lock();
            let next = match g.get(*c) { Some(PseudoEntry::Dir(d)) => Arc::clone(d), _ => return None };
            drop(g);
            dir = next;
        }
        Some(dir)
    }

    pub fn lookup_path(self: &Arc<PseudoDir>, full_path: &str) -> Option<InodeRef> {
        let comps = components(full_path);
        if comps.is_empty() {
            return Some(self.as_inode());
        }
        let mut dir = Arc::clone(self);
        for (i, c) in comps.iter().enumerate() {
            let g = dir.children.lock();
            match g.get(*c) {
                Some(PseudoEntry::Leaf(inode)) => {
                    let last = i == comps.len() - 1;
                    let leaf = if last { Some(Arc::clone(inode)) } else { None };
                    drop(g);
                    return leaf.map(|l| dir.leaf_iget(&l));
                }
                Some(PseudoEntry::Dir(d)) => {
                    let d = Arc::clone(d);
                    drop(g);
                    if i == comps.len() - 1 {
                        return Some(d.as_inode());
                    }
                    dir = d;
                }
                None => return None,
            }
        }
        None
    }

    fn remove_entry(self: &Arc<PseudoDir>, path: &str) -> Option<PseudoEntry> {
        let comps = components(path);
        if comps.is_empty() {
            return None;
        }
        let mut dir = Arc::clone(self);
        for c in &comps[..comps.len() - 1] {
            let next = {
                let g = dir.children.lock();
                match g.get(*c) {
                    Some(PseudoEntry::Dir(d)) => Arc::clone(d),
                    _ => return None,
                }
            };
            dir = next;
        }
        let leaf = comps[comps.len() - 1];
        let removed = dir.children.lock().remove(leaf);
        removed
    }

    pub fn remove_subtree(self: &Arc<PseudoDir>, path: &str) -> usize {
        if self.remove_entry(path).is_some() { 1 } else { 0 }
    }

    pub fn remove_subtree_inodes(self: &Arc<PseudoDir>, path: &str) -> Vec<InodeRef> {
        let mut out = Vec::new();
        if let Some(entry) = self.remove_entry(path) { entry.collect_inodes(&mut out); }
        crate::reval::forget_detached(self, &out);
        out
    }


    pub(crate) fn op_lookup(&self, name: &str) -> KResult<InodeRef> {
        let leaf = {
            let g = self.children.lock();
            match g.get(name) {
                None => return Err(VfsError::Enoent),
                Some(PseudoEntry::Dir(d)) => return Ok(d.as_inode()),
                Some(PseudoEntry::Leaf(i)) => Arc::clone(i),
            }
        };
        Ok(self.leaf_iget(&leaf))
    }

    pub(crate) fn op_mkdir(&self, name: &str, mode: u32, ctx: &CreateCtx) -> KResult<InodeRef> {
        let hook = self.hooks.lock().clone();
        if let Some(h) = hook {
            if let Some(inode) = h.mkdir(self, name, mode, ctx)? {
                return Ok(inode);
            }
        }
        let mut g = self.children.lock();
        if g.contains_key(name) {
            return Err(VfsError::Eexist);
        }
        let mut cp = self.path.clone();
        cp.push('/');
        cp.push_str(name);
        let d = PseudoDir::child_at(cp, self.fsid, self.sb_weak(), Arc::clone(&self.dir_iops));
        g.insert(String::from(name), PseudoEntry::Dir(Arc::clone(&d)));
        Ok(d.as_inode())
    }

    pub(crate) fn op_rmdir(&self, name: &str) -> KResult<()> {
        let hook = self.hooks.lock().clone();
        if let Some(h) = hook {
            if h.rmdir(self, name)? {
                return Ok(());
            }
        }
        let mut g = self.children.lock();
        match g.get(name) {
            Some(PseudoEntry::Dir(d)) if d.children.lock().is_empty() => {}
            Some(PseudoEntry::Dir(_)) => return Err(VfsError::Enotempty),
            Some(PseudoEntry::Leaf(_)) => return Err(VfsError::Enotdir),
            None => return Err(VfsError::Enoent),
        }
        g.remove(name);
        Ok(())
    }

    pub(crate) fn op_symlink(&self, name: &str, target: &[u8]) -> KResult<()> {
        let mut g = self.children.lock();
        if g.contains_key(name) {
            return Err(VfsError::Eexist);
        }
        let mut cp = self.path.clone();
        cp.push('/');
        cp.push_str(name);
        let link = PseudoSymlink::new(dir_ino(&cp), self.fsid, target);
        g.insert(String::from(name), PseudoEntry::Leaf(link));
        Ok(())
    }

    /// The pseudo-filesystem rename op rejects any non-zero `flags` outright —
    /// it implements NO `renameat2` flag. Accepting
    /// `RENAME_NOREPLACE`/`RENAME_EXCHANGE` here (and silently dropping
    /// `RENAME_WHITEOUT`) would report success for a guarantee sysfs/cgroupfs
    /// cannot give. # C: O(log N)
    pub(crate) fn op_rename(&self, old: &str, dst: &PseudoDir, new: &str, flags: u32) -> KResult<()> {
        if flags != 0 { return Err(VfsError::Einval); }
        if core::ptr::eq(self as *const PseudoDir, dst as *const PseudoDir) {
            let mut g = self.children.lock();
            let e = g.remove(old).ok_or(VfsError::Enoent)?;
            g.insert(String::from(new), e);
            Ok(())
        } else {
            let e = self.children.lock().remove(old).ok_or(VfsError::Enoent)?;
            dst.children.lock().insert(String::from(new), e);
            Ok(())
        }
    }

    /// The ONE readdir loop every pseudo filesystem built on [`PseudoDir`]
    /// shares (devfs, devpts, sysfs's
    /// static tree, procfs's registered tree, tracefs/debugfs, configfs).
    ///
    /// The cursor is a per-entry NAME cookie ([`vfs::name_cookie`]), not an
    /// ordinal index. An ordinal shifts when a sibling is created or removed
    /// between two `getdents` calls, which duplicates or skips entries in a
    /// paginated listing and silently repoints a `seekdir(3)` cookie; a name
    /// cookie is derived from the entry alone and survives its neighbours
    /// changing. # C: O(N log N) per call
    pub(crate) fn op_readdir(&self, ctx: &mut DirContext) -> KResult<()> {
        let mut kids: Vec<CookieEntry> = {
            let g = self.children.lock();
            g.iter().map(|(k, v)| CookieEntry::new(k.clone(), v.ino(), v.file_type())).collect()
        };
        vfs::emit_by_cookie(&mut kids, ctx)
    }
}
