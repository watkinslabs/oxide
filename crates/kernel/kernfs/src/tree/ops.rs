use super::*;

impl PseudoDir {
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
            if let Some(inode) = h.mkdir(self, name, mode, ctx)? { return Ok(inode); }
        }
        let mut g = self.children.lock();
        if g.contains_key(name) { return Err(VfsError::Eexist); }
        let mut cp = self.path.clone(); cp.push('/'); cp.push_str(name);
        let d = PseudoDir::child_at(cp, self.fsid, self.sb_weak(),
            Arc::clone(&self.dir_iops), self.dir_xattrs);
        g.insert(String::from(name), PseudoEntry::Dir(Arc::clone(&d)));
        Ok(d.as_inode())
    }

    pub(crate) fn op_rmdir(&self, name: &str) -> KResult<()> {
        let hook = self.hooks.lock().clone();
        if let Some(h) = hook { if h.rmdir(self, name)? { return Ok(()); } }
        let mut g = self.children.lock();
        match g.get(name) {
            Some(PseudoEntry::Dir(d)) if d.children.lock().is_empty() => {}
            Some(PseudoEntry::Dir(_)) => return Err(VfsError::Enotempty),
            Some(PseudoEntry::Leaf(_)) => return Err(VfsError::Enotdir),
            None => return Err(VfsError::Enoent),
        }
        g.remove(name); Ok(())
    }

    pub(crate) fn op_symlink(&self, name: &str, target: &[u8]) -> KResult<()> {
        let mut g = self.children.lock();
        if g.contains_key(name) { return Err(VfsError::Eexist); }
        let mut cp = self.path.clone(); cp.push('/'); cp.push_str(name);
        let link = PseudoSymlink::new(dir_ino(&cp), self.fsid, target);
        g.insert(String::from(name), PseudoEntry::Leaf(link)); Ok(())
    }

    /// Reject every non-zero rename flag: this pseudo-filesystem does not
    /// implement any `renameat2` guarantee. # C: O(log N)
    pub(crate) fn op_rename(&self, old: &str, dst: &PseudoDir, new: &str, flags: u32) -> KResult<()> {
        if flags != 0 { return Err(VfsError::Einval); }
        if core::ptr::eq(self as *const PseudoDir, dst as *const PseudoDir) {
            let mut g = self.children.lock();
            let e = g.remove(old).ok_or(VfsError::Enoent)?;
            g.insert(String::from(new), e); Ok(())
        } else {
            let e = self.children.lock().remove(old).ok_or(VfsError::Enoent)?;
            dst.children.lock().insert(String::from(new), e); Ok(())
        }
    }

    /// Emit the shared pseudo-filesystem directory view using stable name
    /// cookies so sibling changes do not duplicate or skip entries. # C: O(N log N)
    pub(crate) fn op_readdir(&self, ctx: &mut DirContext) -> KResult<()> {
        let mut kids: Vec<CookieEntry> = {
            let g = self.children.lock();
            g.iter().map(|(k, v)| CookieEntry::new(k.clone(), v.ino(), v.file_type())).collect()
        };
        vfs::emit_by_cookie(&mut kids, ctx)
    }
}
