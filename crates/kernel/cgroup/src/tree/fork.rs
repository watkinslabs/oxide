use vfs::VfsError;
use alloc::sync::Arc;
use alloc::vec::Vec;

use super::controllers::{CPU, CPUSET, PIDS};
use super::types::{ROOT, Tree};

const THREADED_CONTROLLERS: u8 = CPU | CPUSET | PIDS;

/// State sampled atomically with membership publication and applied before the
/// new task is allowed to run.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ForkCommit { pub frozen: bool, pub killed: bool }

impl Tree {
    /// Pin a live explicit clone destination before checking its permissions.
    /// # C: O(log n)
    pub fn pin_fork_target(&mut self, cgid: u64) -> super::types::KResult<()> {
        let node = self.nodes.get_mut(&cgid).ok_or(VfsError::Enodev)?;
        node.fork_pins = node.fork_pins.saturating_add(1);
        Ok(())
    }

    /// Release a destination pin which never acquired a pids reservation.
    /// # C: O(log n)
    pub fn unpin_fork_target(&mut self, cgid: u64) {
        let node = self.nodes.get_mut(&cgid).expect("fork destination remains pinned");
        assert!(node.fork_pins != 0, "fork destination owns one cgroup pin");
        node.fork_pins -= 1;
    }

    /// Common ancestor whose cgroup.procs delegation authorizes a migration.
    /// # C: O(depth)
    pub fn fork_common_ancestor(&self, src: u64, dst: u64) -> super::types::KResult<u64> {
        if !self.nodes.contains_key(&dst) { return Err(VfsError::Enodev); }
        let mut common = src;
        while !self.is_descendant(dst, common) {
            common = self.nodes.get(&common).and_then(|node| node.parent)
                .ok_or(VfsError::Enodev)?;
        }
        Ok(common)
    }

    /// Validate namespace visibility, migration destination, and thread domain.
    /// Destination/common-ancestor DAC checks precede this call.
    /// # C: O(depth + subtree)
    pub fn validate_fork_destination(&self, src: u64, dst: u64, thread: bool,
        ns_root: Option<&str>) -> super::types::KResult<()> {
        let node = self.nodes.get(&dst).ok_or(VfsError::Enodev)?;
        if let Some(root) = ns_root {
            if !self.is_under_path(src, root) || !self.is_under_path(dst, root) {
                return Err(VfsError::Enoent);
            }
        }
        let can_thread_root = dst == ROOT
            || (!self.populated_domain_child(dst)
                && node.subtree_control & !THREADED_CONTROLLERS == 0);
        if !can_thread_root && node.subtree_control != 0 { return Err(VfsError::Ebusy); }
        if thread && src != dst { return Err(VfsError::Eopnotsupp); }
        Ok(())
    }

    /// Add a pids reservation to an already pinned explicit destination.
    /// # C: O(depth * subtree)
    pub fn reserve_pinned_fork(&mut self, cgid: u64) -> super::types::KResult<()> {
        let events = self.reserve_pinned_fork_events(cgid)?;
        if events.is_some() { return Err(VfsError::Eagain); }
        Ok(())
    }

    /// Prepared explicit reservation plus event sources to notify on refusal.
    /// # C: O(depth * subtree)
    pub fn reserve_pinned_fork_events(&mut self, cgid: u64)
        -> super::types::KResult<Option<Vec<Arc<vfs::PollSubscribers>>>> {
        if !self.nodes.contains_key(&cgid) { return Err(VfsError::Enodev); }
        if let Some(limit) = self.pids_limit_exceeded(cgid) {
            return Ok(Some(self.record_pids_rejection(cgid, limit)));
        }
        let node = self.nodes.get_mut(&cgid).unwrap();
        assert!(node.fork_pins != 0, "explicit fork destination remains pinned");
        node.pending_forks = node.pending_forks.saturating_add(1);
        self.update_pids_peak(cgid);
        Ok(None)
    }

    /// Reserve one pids-controller task charge and pin its destination.
    /// # C: O(depth * subtree)
    pub fn prepare_fork(&mut self, cgid: u64) -> super::types::KResult<()> {
        let events = self.prepare_fork_events(cgid)?;
        if events.is_some() { return Err(VfsError::Eagain); }
        Ok(())
    }

    /// Prepared inherited reservation plus event sources to notify on refusal.
    /// # C: O(depth * subtree)
    pub fn prepare_fork_events(&mut self, cgid: u64)
        -> super::types::KResult<Option<Vec<Arc<vfs::PollSubscribers>>>> {
        if !self.mounted { return Ok(None); }
        if !self.nodes.contains_key(&cgid) { return Err(VfsError::Enodev); }
        if let Some(limit) = self.pids_limit_exceeded(cgid) {
            return Ok(Some(self.record_pids_rejection(cgid, limit)));
        }
        let node = self.nodes.get_mut(&cgid).unwrap();
        node.pending_forks = node.pending_forks.saturating_add(1);
        node.fork_pins = node.fork_pins.saturating_add(1);
        self.update_pids_peak(cgid);
        Ok(None)
    }

    /// Cancel one unpublished fork's reservation and destination pin.
    /// # C: O(log n)
    pub fn cancel_fork(&mut self, cgid: u64) {
        if !self.mounted { return; }
        let node = self.nodes.get_mut(&cgid).expect("prepared fork destination remains pinned");
        assert!(node.pending_forks != 0, "prepared fork owns one pids charge");
        assert!(node.fork_pins != 0, "prepared fork owns one cgroup pin");
        node.pending_forks -= 1;
        node.fork_pins -= 1;
    }

    /// Convert one prepared charge into canonical task membership.
    /// # C: O(threads)
    pub fn commit_fork(&mut self, cgid: u64, child_tid: u64, parent_tid: u64,
        thread: bool, kill_seq: u64) -> ForkCommit {
        if !self.mounted { return ForkCommit::default(); }
        {
            let node = self.nodes.get_mut(&cgid).expect("prepared fork destination remains pinned");
            assert!(node.pending_forks != 0, "prepared fork owns one pids charge");
            assert!(node.fork_pins != 0, "prepared fork owns one cgroup pin");
        }
        if thread {
            self.add_thread_into(cgid, parent_tid, child_tid);
        } else {
            self.add_proc(cgid, child_tid).expect("pinned cgroup accepts prepared process");
        }
        let node = self.nodes.get_mut(&cgid).unwrap();
        node.pending_forks -= 1;
        node.fork_pins -= 1;
        ForkCommit {
            frozen: self.effective_frozen(cgid),
            killed: self.nodes.get(&cgid).is_some_and(|node| node.kill_seq != kill_seq),
        }
    }

    /// Every task charged to the pids controller, including admitted forks.
    /// # C: O(subtree)
    pub(super) fn subtree_pids_count(&self, id: u64) -> u64 {
        let node = match self.nodes.get(&id) { Some(node) => node, None => return 0 };
        let mut count = self.subtree_proc_count(id).saturating_add(node.pending_forks);
        for &child in node.children.values() {
            count = count.saturating_add(self.subtree_pending_forks(child));
        }
        count
    }

    fn subtree_pending_forks(&self, id: u64) -> u64 {
        let node = match self.nodes.get(&id) { Some(node) => node, None => return 0 };
        let mut count = node.pending_forks;
        for &child in node.children.values() {
            count = count.saturating_add(self.subtree_pending_forks(child));
        }
        count
    }

    /// True when one additional pids charge would exceed an ancestor limit.
    /// # C: O(depth * subtree)
    pub fn fork_would_exceed_pids(&self, cgid: u64) -> bool {
        self.pids_limit_exceeded(cgid).is_some()
    }

    fn pids_limit_exceeded(&self, cgid: u64) -> Option<u64> {
        let mut cur = Some(cgid);
        while let Some(id) = cur {
            let node = match self.nodes.get(&id) { Some(node) => node, None => break };
            if node.avail & PIDS != 0 {
                if let Some(max) = node.pids_max {
                    if self.subtree_pids_count(id).saturating_add(1) > max { return Some(id); }
                }
            }
            cur = node.parent;
        }
        None
    }

    fn record_pids_rejection(&mut self, cgid: u64, limit: u64)
        -> Vec<Arc<vfs::PollSubscribers>> {
        let mut wake = Vec::new();
        if let Some(node) = self.nodes.get_mut(&cgid) {
            node.pids_forkfail_local = node.pids_forkfail_local.saturating_add(1);
        }
        if crate::state::root_flags().has(crate::root_flags::RootFlag::PidsLocalEvents) {
            if let Some(node) = self.nodes.get(&cgid) {
                wake.push(Arc::clone(&node.pids_events_poll));
                wake.push(Arc::clone(&node.pids_events_local_poll));
            }
            return wake;
        }
        if let Some(node) = self.nodes.get_mut(&limit) {
            node.pids_events_local = node.pids_events_local.saturating_add(1);
            wake.push(Arc::clone(&node.pids_events_local_poll));
        }
        let mut cur = Some(limit);
        while let Some(id) = cur {
            let Some(node) = self.nodes.get_mut(&id) else { break };
            cur = node.parent;
            if cur.is_none() { break; }
            node.pids_events = node.pids_events.saturating_add(1);
            wake.push(Arc::clone(&node.pids_events_poll));
        }
        wake
    }

    pub(super) fn update_pids_peak(&mut self, cgid: u64) {
        let mut cur = Some(cgid);
        while let Some(id) = cur {
            let count = self.subtree_pids_count(id);
            let Some(node) = self.nodes.get_mut(&id) else { break };
            node.pids_peak = node.pids_peak.max(count);
            cur = node.parent;
        }
    }

    /// Snapshot effective freezer request and cgroup.kill generation. # C: O(depth)
    pub fn fork_state(&self, cgid: u64) -> super::types::KResult<(bool, u64)> {
        let node = self.nodes.get(&cgid).ok_or(VfsError::Enodev)?;
        Ok((self.effective_frozen(cgid), node.kill_seq))
    }

    fn effective_frozen(&self, mut cgid: u64) -> bool {
        loop {
            let Some(node) = self.nodes.get(&cgid) else { return false };
            if node.frozen { return true; }
            let Some(parent) = node.parent else { return false };
            cgid = parent;
        }
    }

    /// Advance kill generations for every affected descendant before callers
    /// signal the membership snapshot. # C: O(subtree + tasks)
    pub fn kill_subtree(&mut self, id: u64) -> super::types::KResult<Vec<u64>> {
        if !self.nodes.contains_key(&id) { return Err(VfsError::Enoent); }
        let mut ids = Vec::new();
        self.collect_descendants(id, &mut ids);
        for cgid in ids {
            if let Some(node) = self.nodes.get_mut(&cgid) {
                node.kill_seq = node.kill_seq.wrapping_add(1);
            }
        }
        Ok(self.subtree_pids(id))
    }

    fn collect_descendants(&self, id: u64, out: &mut Vec<u64>) {
        let Some(node) = self.nodes.get(&id) else { return };
        out.push(id);
        for child in node.children.values() { self.collect_descendants(*child, out); }
    }

    fn is_descendant(&self, mut child: u64, ancestor: u64) -> bool {
        loop {
            if child == ancestor { return true; }
            let Some(parent) = self.nodes.get(&child).and_then(|node| node.parent) else {
                return false;
            };
            child = parent;
        }
    }

    fn populated_domain_child(&self, cgid: u64) -> bool {
        self.nodes.get(&cgid).is_some_and(|node| node.children.values()
            .any(|child| self.populated(*child)))
    }
}
