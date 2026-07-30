use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use vfs::InodeRef;

use super::bpf_types::{
    BpfAttachEntry, BpfAttachError, BpfAttachMode, BpfAttachOrder, BpfAttachOwner,
    BpfAttachPosition, BpfAttachQuery, BpfDeviceError, BpfDeviceMode, BpfDeviceQuery,
    CgroupBpfAttachType, CgroupBpfRuntime, MAX_BPF_ATTACH_PROGS,
};
use super::controllers::ALL;
use super::types::{Node, ROOT, Tree};

impl Tree {
    /// Validate the target at cgroup-fd resolution time. # C: O(log nodes)
    pub(crate) fn bpf_require_online(&self, cgid: u64) -> Result<(), BpfAttachError> {
        self.nodes.get(&cgid).map(|_| ()).ok_or(BpfAttachError::Offline)
    }

    /// Validate one nonzero optimistic revision before anchor lookup. # C: O(log nodes)
    pub(crate) fn bpf_check_revision(
        &self,
        cgid: u64,
        attach_type: CgroupBpfAttachType,
        expected_revision: u64,
    ) -> Result<(), BpfAttachError> {
        let revision = self.nodes.get(&cgid)
            .ok_or(BpfAttachError::Offline)?.bpf.state(attach_type).revision;
        if expected_revision != 0 && expected_revision != revision {
            Err(BpfAttachError::Stale)
        } else {
            Ok(())
        }
    }

    /// Attach one program to one cgroup/type direct list. # C: O(descendants * effective programs)
    pub fn bpf_attach(
        &mut self,
        cgid: u64,
        attach_type: CgroupBpfAttachType,
        prog: InodeRef,
        mode: BpfAttachMode,
        order: BpfAttachOrder<'_>,
        replace: Option<&InodeRef>,
        expected_revision: u64,
    ) -> Result<(), BpfAttachError> {
        self.bpf_attach_owner(
            cgid, attach_type, BpfAttachOwner::Legacy(prog), mode, order,
            replace, expected_revision,
        )
    }

    /// Attach one link-owned program identity. # C: O(descendants * effective programs)
    pub fn bpf_attach_link(
        &mut self,
        cgid: u64,
        attach_type: CgroupBpfAttachType,
        link_id: u64,
        prog: InodeRef,
        order: BpfAttachOrder<'_>,
        expected_revision: u64,
    ) -> Result<(), BpfAttachError> {
        self.bpf_attach_owner(
            cgid, attach_type, BpfAttachOwner::Link { id: link_id, prog },
            BpfAttachMode::Multi, order, None, expected_revision,
        )
    }

    fn bpf_attach_owner(
        &mut self,
        cgid: u64,
        attach_type: CgroupBpfAttachType,
        owner: BpfAttachOwner,
        mode: BpfAttachMode,
        order: BpfAttachOrder<'_>,
        replace: Option<&InodeRef>,
        expected_revision: u64,
    ) -> Result<(), BpfAttachError> {
        if mode != BpfAttachMode::Multi && replace.is_some() {
            return Err(BpfAttachError::Invalid);
        }
        if replace.is_some() && !matches!(order.position, BpfAttachPosition::Last) {
            return Err(BpfAttachError::Invalid);
        }
        self.bpf_check_revision(cgid, attach_type, expected_revision)?;
        if !self.bpf_hierarchy_allows_attach(cgid, attach_type) {
            return Err(BpfAttachError::Denied);
        }

        let node = self.nodes.get_mut(&cgid).ok_or(BpfAttachError::Offline)?;
        let state = node.bpf.state_mut(attach_type);
        if state.mode.is_some_and(|current| current != mode) {
            return Err(BpfAttachError::Denied);
        }
        if state.direct.len() >= MAX_BPF_ATTACH_PROGS {
            return Err(BpfAttachError::Full);
        }
        match mode {
            BpfAttachMode::Multi => {
                if state.direct.iter().any(|entry| match (&owner, &entry.owner) {
                    (BpfAttachOwner::Legacy(prog), BpfAttachOwner::Legacy(attached)) => {
                        Arc::ptr_eq(attached, prog)
                            && replace.is_none_or(|old| !Arc::ptr_eq(attached, old))
                    }
                    (BpfAttachOwner::Link { id, .. }, BpfAttachOwner::Link {
                        id: attached, ..
                    }) => id == attached,
                    _ => false,
                }) {
                    return Err(BpfAttachError::Duplicate);
                }
                if let Some(old) = replace {
                    let pos = state.direct.iter()
                        .position(|entry| matches!(
                            &entry.owner,
                            BpfAttachOwner::Legacy(prog) if Arc::ptr_eq(prog, old)
                        ))
                        .ok_or(BpfAttachError::Missing)?;
                    state.direct[pos] = BpfAttachEntry { owner, preorder: order.preorder };
                } else {
                    let pos = match order.position {
                        BpfAttachPosition::Empty => {
                            if !state.direct.is_empty() { return Err(BpfAttachError::Invalid); }
                            0
                        }
                        BpfAttachPosition::First => 0,
                        BpfAttachPosition::Last => state.direct.len(),
                        BpfAttachPosition::Before(anchor) => {
                            let pos = state.direct.iter()
                                .position(|entry| entry.owner.matches_anchor(anchor))
                                .ok_or(BpfAttachError::Missing)?;
                            if state.direct[pos].preorder != order.preorder {
                                return Err(BpfAttachError::Invalid);
                            }
                            pos
                        }
                        BpfAttachPosition::After(anchor) => {
                            let pos = state.direct.iter()
                                .position(|entry| entry.owner.matches_anchor(anchor))
                                .ok_or(BpfAttachError::Missing)?;
                            if state.direct[pos].preorder != order.preorder {
                                return Err(BpfAttachError::Invalid);
                            }
                            pos + 1
                        }
                    };
                    state.direct.insert(pos, BpfAttachEntry { owner, preorder: order.preorder });
                }
            }
            BpfAttachMode::Single | BpfAttachMode::Override => {
                let entry = BpfAttachEntry { owner, preorder: order.preorder };
                if state.direct.is_empty() {
                    if matches!(
                        order.position,
                        BpfAttachPosition::Before(_) | BpfAttachPosition::After(_),
                    ) {
                        return Err(BpfAttachError::Missing);
                    }
                    state.direct.push(entry);
                } else {
                    // Linux find_attach_entry() returns the existing non-multi
                    // entry without resolving the otherwise-unused relative fd.
                    state.direct[0] = entry;
                }
            }
        }
        state.mode = Some(mode);
        state.revision = state.revision.wrapping_add(1);
        self.rebuild_bpf_attach(cgid, attach_type);
        Ok(())
    }

    /// Detach one exact program from one cgroup/type direct list. # C: O(descendants * effective programs)
    pub fn bpf_detach(
        &mut self,
        cgid: u64,
        attach_type: CgroupBpfAttachType,
        prog: Option<&InodeRef>,
        expected_revision: u64,
    ) -> Result<(), BpfAttachError> {
        let node = self.nodes.get_mut(&cgid).ok_or(BpfAttachError::Offline)?;
        let state = node.bpf.state_mut(attach_type);
        if expected_revision != 0 && expected_revision != state.revision {
            return Err(BpfAttachError::Stale);
        }
        if state.direct.is_empty() { return Err(BpfAttachError::Missing); }
        let pos = if state.mode == Some(BpfAttachMode::Multi) {
            let prog = prog.ok_or(BpfAttachError::Invalid)?;
            state.direct.iter().position(|entry| matches!(
                &entry.owner,
                BpfAttachOwner::Legacy(attached) if Arc::ptr_eq(attached, prog)
            ))
                .ok_or(BpfAttachError::Missing)?
        } else {
            0
        };
        state.direct.remove(pos);
        if state.direct.is_empty() { state.mode = None; }
        state.revision = state.revision.wrapping_add(1);
        self.rebuild_bpf_attach(cgid, attach_type);
        Ok(())
    }

    /// Detach one exact link identity. # C: O(descendants * effective programs)
    pub fn bpf_detach_link(
        &mut self,
        cgid: u64,
        attach_type: CgroupBpfAttachType,
        link_id: u64,
    ) -> Result<(), BpfAttachError> {
        let node = self.nodes.get_mut(&cgid).ok_or(BpfAttachError::Offline)?;
        let state = node.bpf.state_mut(attach_type);
        let pos = state.direct.iter().position(|entry| matches!(
            &entry.owner, BpfAttachOwner::Link { id, .. } if *id == link_id
        )).ok_or(BpfAttachError::Missing)?;
        state.direct.remove(pos);
        if state.direct.is_empty() { state.mode = None; }
        state.revision = state.revision.wrapping_add(1);
        self.rebuild_bpf_attach(cgid, attach_type);
        Ok(())
    }

    /// Snapshot one online cgroup/type effective list. # C: O(log nodes)
    pub fn bpf_effective(
        &self,
        cgid: u64,
        attach_type: CgroupBpfAttachType,
    ) -> Option<Arc<[InodeRef]>> {
        self.nodes.get(&cgid).map(|node| node.bpf.runtime.effective(attach_type))
    }

    /// Snapshot direct metadata and one effective list. # C: O(direct)
    pub fn bpf_query(
        &self,
        cgid: u64,
        attach_type: CgroupBpfAttachType,
    ) -> Result<BpfAttachQuery, BpfAttachError> {
        let node = self.nodes.get(&cgid).ok_or(BpfAttachError::Offline)?;
        let state = node.bpf.state(attach_type);
        Ok(BpfAttachQuery {
            direct: Arc::from(state.direct.iter()
                .map(|entry| Arc::clone(entry.owner.prog())).collect::<Vec<_>>()),
            effective: node.bpf.runtime.effective(attach_type),
            revision: state.revision,
            mode: state.mode,
        })
    }

    /// Republish one type below a changed hierarchy node. # C: O(descendants * effective programs)
    pub(super) fn rebuild_bpf_attach(
        &mut self,
        root: u64,
        attach_type: CgroupBpfAttachType,
    ) {
        let mut pending = Vec::from([root]);
        while let Some(id) = pending.pop() {
            let mut preorder_layers: Vec<Vec<InodeRef>> = Vec::new();
            let mut postorder: Vec<InodeRef> = Vec::new();
            let mut count = 0usize;
            let mut current = Some(id);
            while let Some(cgid) = current {
                let Some(node) = self.nodes.get(&cgid) else { break };
                let state = node.bpf.state(attach_type);
                if count == 0 || state.mode == Some(BpfAttachMode::Multi) {
                    let preorder: Vec<InodeRef> = state.direct.iter()
                        .filter(|entry| entry.preorder)
                        .map(|entry| Arc::clone(entry.owner.prog())).collect();
                    postorder.extend(state.direct.iter()
                        .filter(|entry| !entry.preorder)
                        .map(|entry| Arc::clone(entry.owner.prog())));
                    count += state.direct.len();
                    if !preorder.is_empty() { preorder_layers.push(preorder); }
                }
                current = node.parent;
            }
            let mut programs = Vec::with_capacity(count);
            for layer in preorder_layers.into_iter().rev() { programs.extend(layer); }
            programs.extend(postorder);
            let Some(node) = self.nodes.get(&id) else { continue };
            node.bpf.runtime.publish(attach_type, Arc::from(programs));
            pending.extend(node.children.values().copied());
        }
    }

    /// Pin one task's live runtime, falling back to ROOT. # C: O(log nodes)
    pub(crate) fn bpf_runtime_for_task(&mut self, tid: u64) -> Arc<CgroupBpfRuntime> {
        self.ensure_bpf_root();
        let cgid = self.cgroup_of(tid);
        self.nodes.get(&cgid).or_else(|| self.nodes.get(&ROOT))
            .map(|node| Arc::clone(&node.bpf.runtime))
            .expect("cgroup BPF root must exist")
    }

    /// Pin the canonical ROOT runtime. # C: O(log nodes)
    pub(crate) fn bpf_root_runtime(&mut self) -> Arc<CgroupBpfRuntime> {
        self.ensure_bpf_root();
        Arc::clone(&self.nodes.get(&ROOT).expect("cgroup BPF root must exist").bpf.runtime)
    }

    /// Pin one online cgroup's live runtime. # C: O(log nodes)
    pub(crate) fn bpf_runtime(
        &self,
        cgid: u64,
    ) -> Result<Arc<CgroupBpfRuntime>, BpfAttachError> {
        self.nodes.get(&cgid).map(|node| Arc::clone(&node.bpf.runtime))
            .ok_or(BpfAttachError::Offline)
    }

    fn ensure_bpf_root(&mut self) {
        self.nodes.entry(ROOT)
            .or_insert_with(|| Node::new(ROOT, String::new(), None, ALL));
        if self.next_id <= ROOT { self.next_id = ROOT + 1; }
    }

    fn bpf_hierarchy_allows_attach(
        &self,
        cgid: u64,
        attach_type: CgroupBpfAttachType,
    ) -> bool {
        let mut current = self.nodes.get(&cgid).and_then(|node| node.parent);
        while let Some(id) = current {
            let Some(node) = self.nodes.get(&id) else { return false };
            let state = node.bpf.state(attach_type);
            if !state.direct.is_empty() {
                return matches!(
                    state.mode,
                    Some(BpfAttachMode::Override | BpfAttachMode::Multi),
                );
            }
            current = node.parent;
        }
        true
    }

    /// Compatibility attach for append-only device programs. # C: O(descendants * effective programs)
    pub fn bpf_device_attach(
        &mut self,
        cgid: u64,
        prog: InodeRef,
        mode: BpfDeviceMode,
        replace: Option<&InodeRef>,
        expected_revision: u64,
    ) -> Result<(), BpfDeviceError> {
        self.bpf_attach(
            cgid, CgroupBpfAttachType::Device, prog, mode,
            BpfAttachOrder::DEFAULT, replace, expected_revision,
        )
    }

    /// Compatibility device-program detach. # C: O(descendants * effective programs)
    pub fn bpf_device_detach(
        &mut self,
        cgid: u64,
        prog: Option<&InodeRef>,
        expected_revision: u64,
    ) -> Result<(), BpfDeviceError> {
        self.bpf_detach(cgid, CgroupBpfAttachType::Device, prog, expected_revision)
    }

    /// Compatibility device-program effective snapshot. # C: O(log nodes)
    pub fn bpf_device_effective(&self, cgid: u64) -> Option<Arc<[InodeRef]>> {
        self.bpf_effective(cgid, CgroupBpfAttachType::Device)
    }

    /// Compatibility device-program query. # C: O(direct)
    pub fn bpf_device_query(&self, cgid: u64) -> Result<BpfDeviceQuery, BpfDeviceError> {
        self.bpf_query(cgid, CgroupBpfAttachType::Device)
    }
}
