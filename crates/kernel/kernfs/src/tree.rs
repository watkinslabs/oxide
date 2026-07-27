use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use sync::{Kernfs as KernfsClass, Spinlock};
use vfs::superblock::SuperBlock;
use vfs::{CreateCtx, FileType, Ino, Inode, InodeBuilder, InodeRef, KResult, VfsError, default_file_ops, default_inode_ops, mk_mode};

use crate::dir_ops::{PseudoDirFileOps, PseudoDirOps};

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
    pub fn new_root(root_ino: Ino, fsid: u64) -> Arc<PseudoDir> {
        Arc::new(PseudoDir {
            ino: root_ino,
            path: String::new(),
            fsid,
            sb: Spinlock::new(Weak::new()),
            children: Spinlock::new(BTreeMap::new()),
            inode: Spinlock::new(Weak::new()),
            hooks: Spinlock::new(None),
        })
    }

    fn child_at(path: String, fsid: u64, sb: Weak<SuperBlock>) -> Arc<PseudoDir> {
        Arc::new(PseudoDir {
            ino: dir_ino(&path),
            path,
            fsid,
            sb: Spinlock::new(sb),
            children: Spinlock::new(BTreeMap::new()),
            inode: Spinlock::new(Weak::new()),
            hooks: Spinlock::new(None),
        })
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
            let mut b = InodeBuilder::new(
                me.ino,
                mk_mode(FileType::Directory, 0o755),
                Arc::new(PseudoDirOps),
                Arc::new(PseudoDirFileOps),
            )
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

    fn child_dir(self: &Arc<PseudoDir>, name: &str) -> Arc<PseudoDir> {
        let mut g = self.children.lock();
        if let Some(PseudoEntry::Dir(d)) = g.get(name) {
            return Arc::clone(d);
        }
        let mut cp = self.path.clone();
        cp.push('/');
        cp.push_str(name);
        let d = PseudoDir::child_at(cp, self.fsid, self.sb_weak());
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
        out
    }

    /// Independent copy of a device-node leaf inode for a fresh mount namespace:
    /// same behaviour (i_op/i_fop/i_private/rdev — identical device + routing
    /// ino) but its OWN mutable owner/mode so per-namespace chmod/chown does not
    /// leak. # C: O(1)
    fn clone_device_leaf(leaf: &InodeRef) -> InodeRef {
        let inode = InodeBuilder::new(
            leaf.ino(),
            leaf.i_mode() as u32,
            Arc::clone(leaf.i_op()),
            Arc::clone(leaf.i_fop()),
        )
        .rdev(leaf.rdev())
        .fsid(leaf.fsid())
        .private(Arc::clone(leaf.i_private()))
        .build();
        let _ = inode.set_owner(leaf.uid().unwrap_or(0), leaf.gid().unwrap_or(0));
        // Preserve the public-device (perm-immutable) mark so a per-namespace
        // copy of /dev/null etc. keeps its universal-access invariant too.
        if leaf.is_public_device() { inode.mark_public_device(); }
        inode
    }

    pub fn deep_clone(&self) -> Arc<PseudoDir> {
        let g = self.children.lock();
        let mut nc: BTreeMap<String, PseudoEntry> = BTreeMap::new();
        for (k, v) in g.iter() {
            let nv = match v {
                PseudoEntry::Dir(d) => PseudoEntry::Dir(d.deep_clone()),
                // Device-node leaves carry per-namespace MUTABLE metadata
                // (i_uid/i_gid/i_mode a service's PrivateDevices chmod/chown
                // writes). Sharing the Arc across mount namespaces let one
                // service's `chown /dev/null` corrupt /dev/null for EVERY other
                // namespace (the greeter then hit EACCES → glib "Failed to open
                // file to remap file descriptor"). Give each namespace its own
                // copy; share the immutable behaviour (i_op/i_fop/i_private/rdev
                // → same device, same routing ino). Non-device leaves (dynamic
                // procfs/sysfs files + symlinks) carry no mutable per-ns state,
                // so they stay shared.
                PseudoEntry::Leaf(i) => PseudoEntry::Leaf(
                    if matches!(i.file_type(), FileType::CharDev | FileType::BlockDev) {
                        Self::clone_device_leaf(i)
                    } else {
                        Arc::clone(i)
                    },
                ),
            };
            nc.insert(k.clone(), nv);
        }
        Arc::new(PseudoDir {
            ino: self.ino,
            path: self.path.clone(),
            fsid: self.fsid,
            sb: Spinlock::new(self.sb.lock().clone()),
            children: Spinlock::new(nc),
            inode: Spinlock::new(Weak::new()),
            hooks: Spinlock::new(self.hooks.lock().clone()),
        })
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
        let d = PseudoDir::child_at(cp, self.fsid, self.sb_weak());
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

    /// `kernfs_iop_rename` (Linux `fs/kernfs/dir.c`) opens with `if (flags)
    /// return -EINVAL;` — kernfs implements NO `renameat2` flag. Accepting
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

    pub(crate) fn op_readdir(
        &self,
        off: u64,
        f: &mut dyn FnMut(u64, u64, &str, FileType) -> bool,
    ) -> KResult<u64> {
        let kids: Vec<(String, u64, FileType)> = {
            let g = self.children.lock();
            g.iter().map(|(k, v)| (k.clone(), v.ino(), v.file_type())).collect()
        };
        let r_len = kids.len() as u64;
        let mut idx = off as usize;
        while idx < kids.len() {
            let (name, ino, ft) = &kids[idx];
            let next = idx as u64 + 1;
            if !f(*ino, next, name, *ft) {
                return Ok(next);
            }
            idx += 1;
        }
        Ok(r_len)
    }
}
