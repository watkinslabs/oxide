use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::InodeRef;

use super::types::{BpfDeviceMode, Tree};

/// Errors from the cgroup-owned device-program attachment list.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BpfDeviceError {
    Offline,
    Duplicate,
    Missing,
    Full,
    Stale,
    Denied,
    Invalid,
}

/// Direct-program metadata plus the immutable effective array used by the
/// open/mknod hot path.
pub struct BpfDeviceQuery {
    pub direct: Arc<[InodeRef]>,
    pub effective: Arc<[InodeRef]>,
    pub revision: u64,
    pub mode: Option<BpfDeviceMode>,
}

impl Tree {
    /// Validate the online state at cgroup-fd resolution time.
    /// # C: O(log nodes)
    pub(crate) fn bpf_device_require_online(&self, cgid: u64) -> Result<(), BpfDeviceError> {
        self.nodes.get(&cgid).map(|_| ()).ok_or(BpfDeviceError::Offline)
    }

    /// Attach one program with `BPF_F_ALLOW_MULTI`.  Direct ownership and
    /// descendant effective arrays change under the hierarchy's single lock.
    /// # C: O(descendants * effective programs)
    pub fn bpf_device_attach(
        &mut self,
        cgid: u64,
        prog: InodeRef,
        mode: BpfDeviceMode,
        replace: Option<&InodeRef>,
        expected_revision: u64,
    ) -> Result<(), BpfDeviceError> {
        let revision = self.nodes.get(&cgid)
            .ok_or(BpfDeviceError::Offline)?.bpf_device.revision;
        if expected_revision != 0 && expected_revision != revision {
            return Err(BpfDeviceError::Stale);
        }
        if !self.bpf_device_hierarchy_allows_attach(cgid) {
            return Err(BpfDeviceError::Denied);
        }
        let node = self.nodes.get_mut(&cgid).ok_or(BpfDeviceError::Offline)?;
        if node.bpf_device.mode.is_some_and(|current| current != mode) {
            return Err(BpfDeviceError::Denied);
        }
        if node.bpf_device.direct.len() >= 64 { return Err(BpfDeviceError::Full); }
        match mode {
            BpfDeviceMode::Multi => {
                if node.bpf_device.direct.iter().any(|p| {
                    Arc::ptr_eq(p, &prog) && replace.is_none_or(|old| !Arc::ptr_eq(p, old))
                }) {
                    return Err(BpfDeviceError::Duplicate);
                }
                if let Some(old) = replace {
                    let pos = node.bpf_device.direct.iter()
                        .position(|p| Arc::ptr_eq(p, old))
                        .ok_or(BpfDeviceError::Missing)?;
                    node.bpf_device.direct[pos] = prog;
                } else {
                    node.bpf_device.direct.push(prog);
                }
            }
            BpfDeviceMode::Single | BpfDeviceMode::Override => {
                if replace.is_some() { return Err(BpfDeviceError::Invalid); }
                if node.bpf_device.direct.is_empty() {
                    node.bpf_device.direct.push(prog);
                } else {
                    node.bpf_device.direct[0] = prog;
                }
            }
        }
        node.bpf_device.mode = Some(mode);
        node.bpf_device.revision = node.bpf_device.revision.wrapping_add(1);
        self.rebuild_bpf_device(cgid);
        Ok(())
    }

    /// Detach one exact program.  `BPF_F_ALLOW_MULTI` requires identity.
    /// # C: O(descendants * effective programs)
    pub fn bpf_device_detach(
        &mut self,
        cgid: u64,
        prog: Option<&InodeRef>,
        expected_revision: u64,
    ) -> Result<(), BpfDeviceError> {
        let node = self.nodes.get_mut(&cgid).ok_or(BpfDeviceError::Offline)?;
        if expected_revision != 0 && expected_revision != node.bpf_device.revision {
            return Err(BpfDeviceError::Stale);
        }
        if node.bpf_device.direct.is_empty() { return Err(BpfDeviceError::Missing); }
        let pos = if node.bpf_device.mode == Some(BpfDeviceMode::Multi) {
            let prog = prog.ok_or(BpfDeviceError::Invalid)?;
            node.bpf_device.direct.iter().position(|p| Arc::ptr_eq(p, prog))
                .ok_or(BpfDeviceError::Missing)?
        } else {
            0
        };
        node.bpf_device.direct.remove(pos);
        if node.bpf_device.direct.is_empty() { node.bpf_device.mode = None; }
        node.bpf_device.revision = node.bpf_device.revision.wrapping_add(1);
        self.rebuild_bpf_device(cgid);
        Ok(())
    }

    /// Acquire the immutable effective program array for the permission hot path.
    /// # C: O(1)
    pub fn bpf_device_effective(&self, cgid: u64) -> Option<Arc<[InodeRef]>> {
        self.nodes.get(&cgid).map(|n| Arc::clone(&n.bpf_device.effective))
    }

    /// Direct/effective query snapshot. # C: O(direct)
    pub fn bpf_device_query(&self, cgid: u64) -> Result<BpfDeviceQuery, BpfDeviceError> {
        let node = self.nodes.get(&cgid).ok_or(BpfDeviceError::Offline)?;
        Ok(BpfDeviceQuery {
            direct: Arc::from(node.bpf_device.direct.clone()),
            effective: Arc::clone(&node.bpf_device.effective),
            revision: node.bpf_device.revision,
            mode: node.bpf_device.mode,
        })
    }

    fn rebuild_bpf_device(&mut self, root: u64) {
        let mut pending = Vec::from([root]);
        while let Some(id) = pending.pop() {
            let mut programs = Vec::new();
            let mut current = Some(id);
            while let Some(cgid) = current {
                let Some(node) = self.nodes.get(&cgid) else { break };
                if programs.is_empty() || node.bpf_device.mode == Some(BpfDeviceMode::Multi) {
                    programs.extend(node.bpf_device.direct.iter().cloned());
                }
                current = node.parent;
            }
            let Some(node) = self.nodes.get_mut(&id) else { continue };
            node.bpf_device.effective = Arc::from(programs);
            pending.extend(node.children.values().copied());
        }
    }

    fn bpf_device_hierarchy_allows_attach(&self, cgid: u64) -> bool {
        let mut current = self.nodes.get(&cgid).and_then(|n| n.parent);
        while let Some(id) = current {
            let Some(node) = self.nodes.get(&id) else { return false };
            if !node.bpf_device.direct.is_empty() {
                return matches!(
                    node.bpf_device.mode,
                    Some(BpfDeviceMode::Override | BpfDeviceMode::Multi),
                );
            }
            current = node.parent;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use crate::tree::ROOT;
    use vfs::{FileType, InodeBuilder, default_file_ops, default_inode_ops, mk_mode};

    fn prog(ino: u64) -> InodeRef {
        InodeBuilder::new(ino, mk_mode(FileType::CharDev, 0o600),
            default_inode_ops(), default_file_ops()).build()
    }

    #[test]
    fn direct_programs_publish_to_descendants_and_detach_by_identity() {
        let mut t = Tree::new();
        t.mount_root();
        let (child, _) = t.create(ROOT, "child").unwrap();
        let root_prog = prog(100);
        let child_prog = prog(101);
        t.bpf_device_attach(
            ROOT, Arc::clone(&root_prog), BpfDeviceMode::Multi, None, 0,
        ).unwrap();
        t.bpf_device_attach(
            child, Arc::clone(&child_prog), BpfDeviceMode::Multi, None, 0,
        ).unwrap();
        let effective = t.bpf_device_effective(child).unwrap();
        assert_eq!(effective.len(), 2);
        assert!(Arc::ptr_eq(&effective[0], &child_prog));
        assert!(Arc::ptr_eq(&effective[1], &root_prog));
        assert_eq!(
            t.bpf_device_attach(
                child, child_prog.clone(), BpfDeviceMode::Multi, None, 0,
            ),
            Err(BpfDeviceError::Duplicate),
        );
        t.bpf_device_detach(ROOT, Some(&root_prog), 0).unwrap();
        let effective = t.bpf_device_effective(child).unwrap();
        assert_eq!(effective.len(), 1);
        assert!(Arc::ptr_eq(&effective[0], &child_prog));
    }

    #[test]
    fn removed_cgroup_drops_state_and_rejects_stale_identity() {
        let mut t = Tree::new();
        t.mount_root();
        let (child, _) = t.create(ROOT, "child").unwrap();
        let p = prog(102);
        t.bpf_device_attach(child, p, BpfDeviceMode::Multi, None, 0).unwrap();
        t.remove(child).unwrap();
        assert!(t.bpf_device_effective(child).is_none());
        assert_eq!(
            t.bpf_device_attach(child, prog(103), BpfDeviceMode::Multi, None, 0),
            Err(BpfDeviceError::Offline),
        );
    }

    #[test]
    fn new_child_inherits_published_effective_array_and_revisions_are_direct() {
        let mut t = Tree::new();
        t.mount_root();
        let p = prog(104);
        t.bpf_device_attach(ROOT, p.clone(), BpfDeviceMode::Multi, None, 0).unwrap();
        let (child, _) = t.create(ROOT, "late").unwrap();
        let effective = t.bpf_device_effective(child).unwrap();
        assert_eq!(effective.len(), 1);
        assert!(Arc::ptr_eq(&effective[0], &p));
        assert_eq!(t.bpf_device_query(ROOT).unwrap().revision, 1);
        assert_eq!(t.bpf_device_query(child).unwrap().revision, 0);
    }

    #[test]
    fn expected_revision_is_an_atomic_attach_and_detach_guard() {
        let mut t = Tree::new();
        t.mount_root();
        let p = prog(105);
        assert_eq!(
            t.bpf_device_attach(ROOT, p.clone(), BpfDeviceMode::Multi, None, 2),
            Err(BpfDeviceError::Stale),
        );
        t.bpf_device_attach(ROOT, p.clone(), BpfDeviceMode::Multi, None, 0).unwrap();
        assert_eq!(
            t.bpf_device_detach(ROOT, Some(&p), 2),
            Err(BpfDeviceError::Stale),
        );
        t.bpf_device_detach(ROOT, Some(&p), 1).unwrap();
        assert_eq!(t.bpf_device_query(ROOT).unwrap().revision, 2);
    }

    #[test]
    fn classic_modes_enforce_hierarchy_and_replace_semantics() {
        let mut t = Tree::new();
        t.mount_root();
        let (child, _) = t.create(ROOT, "child").unwrap();
        let root_prog = prog(106);
        let child_prog = prog(107);
        t.bpf_device_attach(
            ROOT, root_prog.clone(), BpfDeviceMode::Single, None, 0,
        ).unwrap();
        assert_eq!(
            t.bpf_device_attach(
                child, child_prog.clone(), BpfDeviceMode::Multi, None, 0,
            ),
            Err(BpfDeviceError::Denied),
        );

        t.bpf_device_detach(ROOT, None, 0).unwrap();
        t.bpf_device_attach(
            ROOT, root_prog.clone(), BpfDeviceMode::Override, None, 0,
        ).unwrap();
        t.bpf_device_attach(
            child, child_prog.clone(), BpfDeviceMode::Single, None, 0,
        ).unwrap();
        let effective = t.bpf_device_effective(child).unwrap();
        assert_eq!(effective.len(), 1);
        assert!(Arc::ptr_eq(&effective[0], &child_prog));
    }

    #[test]
    fn multi_replace_preserves_position_and_rejects_a_missing_old_program() {
        let mut t = Tree::new();
        t.mount_root();
        let first = prog(108);
        let second = prog(109);
        let replacement = prog(110);
        t.bpf_device_attach(
            ROOT, first.clone(), BpfDeviceMode::Multi, None, 0,
        ).unwrap();
        t.bpf_device_attach(
            ROOT, second.clone(), BpfDeviceMode::Multi, None, 0,
        ).unwrap();
        t.bpf_device_attach(
            ROOT, replacement.clone(), BpfDeviceMode::Multi, Some(&first), 0,
        ).unwrap();
        let direct = t.bpf_device_query(ROOT).unwrap().direct;
        assert!(Arc::ptr_eq(&direct[0], &replacement));
        assert!(Arc::ptr_eq(&direct[1], &second));
        assert_eq!(
            t.bpf_device_attach(
                ROOT, prog(111), BpfDeviceMode::Multi, Some(&first), 0,
            ),
            Err(BpfDeviceError::Missing),
        );
    }

    #[test]
    fn online_check_does_not_make_rmdir_busy_and_mutation_revalidates() {
        let mut t = Tree::new();
        t.mount_root();
        let (child, _) = t.create(ROOT, "child").unwrap();
        t.bpf_device_require_online(child).unwrap();
        t.remove(child).unwrap();
        assert_eq!(
            t.bpf_device_require_online(child),
            Err(BpfDeviceError::Offline),
        );
        assert_eq!(
            t.bpf_device_attach(child, prog(112), BpfDeviceMode::Multi, None, 0),
            Err(BpfDeviceError::Offline),
        );
    }
}
