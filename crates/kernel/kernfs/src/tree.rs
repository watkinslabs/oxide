use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use sync::{Kernfs as KernfsClass, Spinlock};
use vfs::superblock::SuperBlock;
use vfs::{FileType, Ino, Inode, InodeBuilder, InodeRef, KResult, VfsError, default_file_ops, default_inode_ops, mk_mode};

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
}

pub struct PseudoDir {
    pub(crate) ino: Ino,
    pub(crate) path: String,
    pub(crate) fsid: u64,
    pub(crate) sb: Spinlock<Weak<SuperBlock>, KernfsClass>,
    pub(crate) children: Spinlock<BTreeMap<String, PseudoEntry>, KernfsClass>,
    pub(crate) inode: Spinlock<Weak<Inode>, KernfsClass>,
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

    pub fn remove_subtree(self: &Arc<PseudoDir>, path: &str) -> usize {
        let comps = components(path);
        if comps.is_empty() {
            return 0;
        }
        let mut dir = Arc::clone(self);
        for c in &comps[..comps.len() - 1] {
            let next = {
                let g = dir.children.lock();
                match g.get(*c) {
                    Some(PseudoEntry::Dir(d)) => Arc::clone(d),
                    _ => return 0,
                }
            };
            dir = next;
        }
        let leaf = comps[comps.len() - 1];
        if dir.children.lock().remove(leaf).is_some() {
            1
        } else {
            0
        }
    }

    pub fn deep_clone(&self) -> Arc<PseudoDir> {
        let g = self.children.lock();
        let mut nc: BTreeMap<String, PseudoEntry> = BTreeMap::new();
        for (k, v) in g.iter() {
            let nv = match v {
                PseudoEntry::Dir(d) => PseudoEntry::Dir(d.deep_clone()),
                PseudoEntry::Leaf(i) => PseudoEntry::Leaf(Arc::clone(i)),
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

    pub(crate) fn op_mkdir(&self, name: &str) -> KResult<InodeRef> {
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

    pub(crate) fn op_rename(&self, old: &str, dst: &PseudoDir, new: &str, flags: u32) -> KResult<()> {
        const RENAME_NOREPLACE: u32 = 1;
        const RENAME_EXCHANGE: u32 = 2;
        if core::ptr::eq(self as *const PseudoDir, dst as *const PseudoDir) {
            let mut g = self.children.lock();
            if flags & RENAME_EXCHANGE != 0 {
                let a = g.remove(old).ok_or(VfsError::Enoent)?;
                match g.remove(new) {
                    Some(b) => {
                        g.insert(String::from(new), a);
                        g.insert(String::from(old), b);
                        Ok(())
                    }
                    None => {
                        g.insert(String::from(old), a);
                        Err(VfsError::Enoent)
                    }
                }
            } else {
                if flags & RENAME_NOREPLACE != 0 && g.contains_key(new) {
                    return Err(VfsError::Eexist);
                }
                let e = g.remove(old).ok_or(VfsError::Enoent)?;
                g.insert(String::from(new), e);
                Ok(())
            }
        } else if flags & RENAME_EXCHANGE != 0 {
            let a = self.children.lock().remove(old).ok_or(VfsError::Enoent)?;
            let b = match dst.children.lock().remove(new) {
                Some(b) => b,
                None => {
                    self.children.lock().insert(String::from(old), a);
                    return Err(VfsError::Enoent);
                }
            };
            dst.children.lock().insert(String::from(new), a);
            self.children.lock().insert(String::from(old), b);
            Ok(())
        } else {
            if flags & RENAME_NOREPLACE != 0 && dst.children.lock().contains_key(new) {
                return Err(VfsError::Eexist);
            }
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
