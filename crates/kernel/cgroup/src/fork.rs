use crate::root_flags::RootFlag;
use crate::state::{TREE, notify_events_chain};

struct PinnedTarget {
    cgid: u64,
    active: bool,
}

impl PinnedTarget {
    fn acquire(cgid: u64) -> vfs::KResult<Self> {
        TREE.lock().pin_fork_target(cgid)?;
        Ok(Self { cgid, active: true })
    }

    fn transfer(mut self) { self.active = false; }
}

impl Drop for PinnedTarget {
    fn drop(&mut self) {
        if self.active { TREE.lock().unpin_fork_target(self.cgid); }
    }
}

/// Prepared cgroup membership for one unpublished task. The destination is
/// pinned and one pids-controller slot is owned until commit or drop.
pub struct PreparedFork {
    tx: Option<super::fork_lock::ForkTransaction>,
    cgid: u64,
    parent_tid: u64,
    thread: bool,
    kill_seq: u64,
    tracked: bool,
    active: bool,
}

impl PreparedFork {
    /// Resolve, pin, and reserve the destination under the hierarchy lock.
    /// # C: O(depth * subtree)
    pub fn prepare(explicit: Option<u64>, parent_tid: u64, thread: bool,
        cred: &vfs::Cred)
        -> vfs::KResult<Self> {
        let mounted = TREE.lock().is_mounted();
        if !mounted {
            return Ok(Self { tx: None, cgid: crate::ROOT_CGROUP, parent_tid, thread,
                kill_seq: 0, tracked: false, active: true });
        }
        let tx = Some(super::fork_lock::ForkTransaction::inherited());
        let inherited = TREE.lock().cgroup_of(parent_tid);
        let Some(cgid) = explicit else {
            let mut tree = TREE.lock();
            tree.prepare_fork(inherited)?;
            let (_, kill_seq) = tree.fork_state(inherited)?;
            return Ok(Self { tx, cgid: inherited, parent_tid, thread,
                kill_seq, tracked: true, active: true });
        };

        let pin = PinnedTarget::acquire(cgid)?;
        let common = TREE.lock().fork_common_ancestor(inherited, cgid)?;
        may_write_procs(cgid, cred)?;
        may_write_procs(common, cred)?;
        let ns_root = if crate::state::root_flags().has(RootFlag::NsDelegate) {
            Some(crate::state::caller_ns_root())
        } else { None };
        let kill_seq = {
            let mut tree = TREE.lock();
            tree.validate_fork_destination(inherited, cgid, thread, ns_root.as_deref())?;
            tree.reserve_pinned_fork(cgid)?;
            tree.fork_state(cgid)?.1
        };
        pin.transfer();
        Ok(Self { tx, cgid, parent_tid, thread, kill_seq, tracked: true, active: true })
    }

    /// Destination owning the child's task and stack charges. # C: O(1)
    pub fn cgid(&self) -> u64 { self.cgid }

    /// Publish the reserved slot as canonical membership without failure.
    /// # C: O(threads)
    pub fn commit(mut self, child_tid: u64) {
        let _transaction = self.tx.as_ref();
        if self.tracked {
            TREE.lock().commit_fork(
                self.cgid, child_tid, self.parent_tid, self.thread, self.kill_seq);
            self.active = false;
            notify_events_chain(self.cgid);
        } else {
            self.active = false;
        }
    }
}

fn may_write_procs(cgid: u64, cred: &vfs::Cred) -> vfs::KResult<()> {
    let inode = crate::inode::make_cg_file(cgid, "cgroup.procs");
    vfs::inode_permission(&inode, vfs::MAY_WRITE, cred)
}

impl Drop for PreparedFork {
    fn drop(&mut self) {
        if !self.active || !self.tracked { return; }
        TREE.lock().cancel_fork(self.cgid);
    }
}
