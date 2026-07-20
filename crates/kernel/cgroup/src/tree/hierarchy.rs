use alloc::string::{String, ToString};
use alloc::vec::Vec;

use vfs::VfsError;

use super::controllers::{CORE_FILES, NONROOT_FILES, controller_files, ctrl_bit};
use super::types::{KResult, Node, ROOT, Tree};

impl Tree {
    /// Resolve a relative cgroup path ("" or "a/b/c") to a node id.
    /// # C: O(components · log n)
    pub fn resolve(&self, rel: &str) -> Option<u64> {
        let mut cur = ROOT;
        for comp in rel.split('/').filter(|s| !s.is_empty()) {
            cur = *self.nodes.get(&cur)?.children.get(comp)?;
        }
        Some(cur)
    }

    /// Absolute hierarchy path of a node (`/` for root, `/a/b` else).
    /// # C: O(depth · log n)
    pub fn path_of(&self, id: u64) -> String {
        let mut parts: Vec<&str> = Vec::new();
        let mut cur = id;
        while let Some(n) = self.nodes.get(&cur) {
            match n.parent {
                Some(p) => { parts.push(n.name.as_str()); cur = p; }
                None => break,
            }
        }
        if parts.is_empty() { return "/".to_string(); }
        parts.reverse();
        let mut out = String::new();
        for p in parts { out.push('/'); out.push_str(p); }
        out
    }

    /// Create child `name` under `parent`. Returns the new id +
    /// controllers available to it (= parent.subtree_control).
    /// # C: O(log n)
    pub fn create(&mut self, parent: u64, name: &str) -> KResult<(u64, u8)> {
        if name.is_empty() || name.contains('/') { return Err(VfsError::Einval); }
        let avail = {
            let p = self.nodes.get(&parent).ok_or(VfsError::Enoent)?;
            if p.children.contains_key(name) { return Err(VfsError::Eexist); }
            p.subtree_control
        };
        let id = self.next_id;
        self.next_id += 1;
        self.nodes.insert(id, Node::new(name.to_string(), Some(parent), avail));
        self.nodes.get_mut(&parent).unwrap().children.insert(name.to_string(), id);
        Ok((id, avail))
    }

    /// Remove an empty, uncharged leaf cgroup. A cgid remains the canonical
    /// PageMeta/swap-slot owner until those objects are released.
    /// # C: O(log n)
    pub fn remove(&mut self, id: u64) -> KResult<()> {
        if id == ROOT { return Err(VfsError::Ebusy); }
        let (parent, name) = {
            let n = self.nodes.get(&id).ok_or(VfsError::Enoent)?;
            if !n.children.is_empty() || !n.procs.is_empty()
                || n.memory.total() != 0 || n.swap_current != 0 {
                return Err(VfsError::Ebusy);
            }
            (n.parent.unwrap(), n.name.clone())
        };
        self.nodes.get_mut(&parent).unwrap().children.remove(&name);
        self.nodes.remove(&id);
        Ok(())
    }

    /// Apply a `+ctrl -ctrl` write to subtree_control. Returns the
    /// new available-set for children so the caller can re-sync their
    /// interface files. EINVAL on an unknown controller or one not
    /// available here; ENOSPC if enabling a controller a child lacks.
    /// # C: O(tokens + children)
    pub fn write_subtree_control(&mut self, id: u64, buf: &str) -> KResult<u8> {
        let avail = self.nodes.get(&id).ok_or(VfsError::Enoent)?.avail;
        let mut set = self.nodes.get(&id).unwrap().subtree_control;
        for tok in buf.split_whitespace() {
            let (add, name) = match tok.as_bytes().first() {
                Some(b'+') => (true, &tok[1..]),
                Some(b'-') => (false, &tok[1..]),
                _ => return Err(VfsError::Einval),
            };
            let bit = ctrl_bit(name).ok_or(VfsError::Einval)?;
            if add {
                if avail & bit == 0 { return Err(VfsError::Enospc); }
                set |= bit;
            } else {
                set &= !bit;
            }
        }
        self.nodes.get_mut(&id).unwrap().subtree_control = set;
        let kids: Vec<u64> = self.nodes.get(&id).unwrap().children.values().copied().collect();
        for k in &kids {
            if let Some(c) = self.nodes.get_mut(k) { c.avail = set; }
        }
        Ok(set)
    }

    /// Full ordered control-file set for an existing node: core files +
    /// (non-root only) kill/freeze + the available-controller files. This
    /// is the EXACT set the old devfs registration produced (CORE_FILES,
    /// then NONROOT_FILES when not root, then `controller_files(avail)`),
    /// so the synthesized inode surface matches byte-for-byte.
    /// # C: O(controllers)
    pub fn node_files(&self, id: u64) -> Vec<&'static str> {
        let n = match self.nodes.get(&id) { Some(n) => n, None => return Vec::new() };
        let mut v: Vec<&'static str> = Vec::new();
        v.extend_from_slice(CORE_FILES);
        if id != ROOT { v.extend_from_slice(NONROOT_FILES); }
        v.extend(controller_files(n.avail));
        v
    }

    /// True iff `name` is one of this node's control files.
    /// # C: O(controllers)
    pub fn has_file(&self, id: u64, name: &str) -> bool {
        self.node_files(id).iter().any(|f| *f == name)
    }

    /// Child node id for `name` under `id`, if it exists.
    /// # C: O(log n)
    pub fn child_id(&self, id: u64, name: &str) -> Option<u64> {
        self.nodes.get(&id)?.children.get(name).copied()
    }

    /// DAC owner `(uid, gid)` of node `id`'s DIRECTORY inode (root:root if the
    /// node is gone). # C: O(log n)
    pub fn dir_owner(&self, id: u64) -> (u32, u32) {
        self.nodes.get(&id).map(|n| (n.uid, n.gid)).unwrap_or((0, 0))
    }

    /// DAC owner `(uid, gid)` of control file `(id, file)`: the per-file chown
    /// override if present, else the node's frozen creation owner. # C: O(log n)
    pub fn file_owner(&self, id: u64, file: &str) -> (u32, u32) {
        match self.nodes.get(&id) {
            Some(n) => n.file_owner.get(file).copied().unwrap_or((n.file_uid, n.file_gid)),
            None => (0, 0),
        }
    }

    /// `chown(2)` the cgroup DIRECTORY inode — persists so the re-synthesized
    /// inode keeps the owner (systemd delegation). ENOENT if the node is gone.
    /// # C: O(log n)
    pub fn set_dir_owner(&mut self, id: u64, uid: u32, gid: u32) -> KResult<()> {
        let n = self.nodes.get_mut(&id).ok_or(VfsError::Enoent)?;
        n.uid = uid;
        n.gid = gid;
        Ok(())
    }

    /// `chown(2)` a single control-file inode `(id, file)` — records a per-file
    /// override (systemd delegates cgroup.procs/threads/subtree_control this
    /// way). ENOENT if the node is gone. # C: O(log n)
    pub fn set_file_owner(&mut self, id: u64, file: &str, uid: u32, gid: u32) -> KResult<()> {
        let n = self.nodes.get_mut(&id).ok_or(VfsError::Enoent)?;
        n.file_owner.insert(file.to_string(), (uid, gid));
        Ok(())
    }

    /// Stamp the creating task's owner on a freshly created node (Linux
    /// `cgroup_create` uses `current_fsuid`/`current_fsgid`): sets the directory
    /// owner AND the frozen control-file default so a delegated user's own
    /// sub-cgroups are user-owned. # C: O(log n)
    pub fn set_created_owner(&mut self, id: u64, uid: u32, gid: u32) {
        if let Some(n) = self.nodes.get_mut(&id) {
            n.uid = uid;
            n.gid = gid;
            n.file_uid = uid;
            n.file_gid = gid;
        }
    }

    /// Ordered child-cgroup names of `id`.
    /// # C: O(children)
    pub fn child_names(&self, id: u64) -> Vec<String> {
        match self.nodes.get(&id) {
            Some(n) => n.children.keys().cloned().collect(),
            None => Vec::new(),
        }
    }
}
