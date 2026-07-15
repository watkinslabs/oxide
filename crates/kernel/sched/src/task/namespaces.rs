use alloc::sync::Arc;

use namespace_identity::{NamespaceKind, NamespaceRef};
use vfs::mntns::MntNamespaceRef;

use super::Task;

/// One retained owner for every non-network namespace kind.
pub(crate) struct TaskNamespaces {
    membership: u64,
    cgroup: NamespaceRef,
    ipc: NamespaceRef,
    pid: NamespaceRef,
    pid_for_children: NamespaceRef,
    time: NamespaceRef,
    user: NamespaceRef,
    uts: NamespaceRef,
    mount: MntNamespaceRef,
}

/// Retained point-in-time task namespace set.
#[derive(Clone)]
pub struct TaskNamespaceSnapshot {
    pub membership: u64,
    pub cgroup: NamespaceRef,
    pub ipc: NamespaceRef,
    pub pid: NamespaceRef,
    pub pid_for_children: NamespaceRef,
    pub time: NamespaceRef,
    pub user: NamespaceRef,
    pub uts: NamespaceRef,
    pub mount: MntNamespaceRef,
}

impl TaskNamespaces {
    pub(super) fn initial() -> Self {
        Self {
            membership: 0,
            cgroup: namespace_identity::initial(NamespaceKind::Cgroup),
            ipc: namespace_identity::initial(NamespaceKind::Ipc),
            pid: namespace_identity::initial(NamespaceKind::Pid),
            pid_for_children: namespace_identity::initial(NamespaceKind::Pid),
            time: namespace_identity::initial(NamespaceKind::Time),
            user: namespace_identity::initial(NamespaceKind::User),
            uts: namespace_identity::initial(NamespaceKind::Uts),
            mount: vfs::mntns::initial(),
        }
    }

    fn snapshot(&self) -> TaskNamespaceSnapshot {
        TaskNamespaceSnapshot {
            membership: self.membership,
            cgroup: Arc::clone(&self.cgroup), ipc: Arc::clone(&self.ipc),
            pid: Arc::clone(&self.pid),
            pid_for_children: Arc::clone(&self.pid_for_children),
            time: Arc::clone(&self.time),
            user: Arc::clone(&self.user), uts: Arc::clone(&self.uts),
            mount: Arc::clone(&self.mount),
        }
    }

    fn from_snapshot(snapshot: TaskNamespaceSnapshot) -> Self {
        Self {
            membership: snapshot.membership, cgroup: snapshot.cgroup,
            ipc: snapshot.ipc, pid: snapshot.pid,
            pid_for_children: snapshot.pid_for_children, time: snapshot.time,
            user: snapshot.user, uts: snapshot.uts, mount: snapshot.mount,
        }
    }

    fn replace(&mut self, namespace: NamespaceRef) -> Result<NamespaceRef, NamespaceRef> {
        let slot = match namespace.kind() {
            NamespaceKind::Cgroup => &mut self.cgroup,
            NamespaceKind::Ipc => &mut self.ipc,
            NamespaceKind::Pid => &mut self.pid,
            NamespaceKind::Time => &mut self.time,
            NamespaceKind::User => &mut self.user,
            NamespaceKind::Uts => &mut self.uts,
        };
        Ok(core::mem::replace(slot, namespace))
    }
}

impl Task {
    /// Retain the complete non-network namespace set atomically.
    /// # C: O(1)
    /// # Ctx: caller holds no lock ranked `Namespace` or higher
    /// # Lk: takes `Namespace` (rank 75)
    /// # Sleeps: no
    pub fn namespace_snapshot(&self) -> Option<TaskNamespaceSnapshot> {
        self.namespaces.lock().as_ref().map(TaskNamespaces::snapshot)
    }

    /// Replace the complete namespace set with a retained snapshot.
    /// # C: O(1) + final-owner drops
    /// # Ctx: caller holds no lock ranked `Namespace` or higher
    /// # Lk: takes `Namespace` (rank 75)
    /// # Sleeps: no
    pub fn replace_namespace_set(&self, snapshot: TaskNamespaceSnapshot)
        -> Result<(), TaskNamespaceSnapshot>
    {
        let pid_namespace_id = snapshot.pid.id().as_u64();
        let replacement = TaskNamespaces::from_snapshot(snapshot);
        let old = {
            let mut slot = self.namespaces.lock();
            if slot.is_none() { return Err(replacement.snapshot()); }
            self.pid.set_namespace_id(pid_namespace_id);
            slot.replace(replacement)
        };
        drop(old);
        Ok(())
    }

    /// Replace one concrete non-mount namespace owner.
    /// # C: O(1) + final-owner drop
    /// # Ctx: caller holds no lock ranked `Namespace` or higher
    /// # Lk: takes `Namespace` (rank 75)
    /// # Sleeps: no
    pub fn replace_namespace(&self, namespace: NamespaceRef) -> Result<(), NamespaceRef> {
        let old = {
            let mut set = self.namespaces.lock();
            let Some(set) = set.as_mut() else { return Err(namespace); };
            if namespace.kind() == NamespaceKind::Pid {
                self.pid.set_namespace_id(namespace.id().as_u64());
            }
            set.replace(namespace)?
        };
        drop(old);
        Ok(())
    }

    /// Replace the concrete mount namespace owner.
    /// # C: O(1) + final-owner drop
    /// # Ctx: caller holds no lock ranked `Namespace` or higher
    /// # Lk: takes `Namespace` (rank 75)
    /// # Sleeps: no
    pub fn replace_mount_namespace(&self, namespace: MntNamespaceRef)
        -> Result<(), MntNamespaceRef>
    {
        let old = {
            let mut set = self.namespaces.lock();
            let Some(set) = set.as_mut() else { return Err(namespace); };
            core::mem::replace(&mut set.mount, namespace)
        };
        drop(old);
        Ok(())
    }

    /// Set the PID namespace inherited by the next child.
    /// # C: O(1) + final-owner drop
    pub fn replace_pid_namespace_for_children(&self, namespace: NamespaceRef)
        -> Result<(), NamespaceRef>
    {
        if namespace.kind() != NamespaceKind::Pid { return Err(namespace); }
        let old = {
            let mut set = self.namespaces.lock();
            let Some(set) = set.as_mut() else { return Err(namespace); };
            core::mem::replace(&mut set.pid_for_children, namespace)
        };
        drop(old);
        Ok(())
    }

    /// Retain the PID namespace inherited by a new child.
    /// # C: O(1)
    pub fn pid_namespace_for_children(&self) -> Option<NamespaceRef> {
        self.namespaces.lock().as_ref().map(|set| Arc::clone(&set.pid_for_children))
    }

    /// Add clone/unshare provenance bits to the live namespace set.
    /// # C: O(1)
    pub fn add_namespace_membership(&self, bits: u64) -> bool {
        let mut set = self.namespaces.lock();
        let Some(set) = set.as_mut() else { return false; };
        set.membership |= bits;
        true
    }

    /// Clear clone/unshare provenance bits after setns.
    /// # C: O(1)
    pub fn clear_namespace_membership(&self, bits: u64) -> bool {
        let mut set = self.namespaces.lock();
        let Some(set) = set.as_mut() else { return false; };
        set.membership &= !bits;
        true
    }

    /// Current namespace identity for `kind`.
    /// # C: O(1)
    pub fn namespace_id(&self, kind: NamespaceKind) -> Option<u64> {
        let set = self.namespaces.lock();
        let set = set.as_ref()?;
        Some(match kind {
            NamespaceKind::Cgroup => set.cgroup.id().as_u64(),
            NamespaceKind::Ipc => set.ipc.id().as_u64(),
            NamespaceKind::Pid => set.pid.id().as_u64(),
            NamespaceKind::Time => set.time.id().as_u64(),
            NamespaceKind::User => set.user.id().as_u64(),
            NamespaceKind::Uts => set.uts.id().as_u64(),
        })
    }

    /// Retain one concrete non-mount namespace owner.
    /// # C: O(1)
    pub fn namespace_owner(&self, kind: NamespaceKind) -> Option<NamespaceRef> {
        let set = self.namespaces.lock();
        let set = set.as_ref()?;
        Some(Arc::clone(match kind {
            NamespaceKind::Cgroup => &set.cgroup, NamespaceKind::Ipc => &set.ipc,
            NamespaceKind::Pid => &set.pid, NamespaceKind::Time => &set.time,
            NamespaceKind::User => &set.user, NamespaceKind::Uts => &set.uts,
        }))
    }

    /// Current mount namespace identity.
    /// # C: O(1)
    pub fn mount_namespace_id(&self) -> Option<u64> {
        self.namespaces.lock().as_ref().map(|set| set.mount.id())
    }


    /// Retain the concrete current mount namespace owner.
    /// # C: O(1)
    pub fn mount_namespace_snapshot(&self) -> Option<MntNamespaceRef> {
        self.namespaces.lock().as_ref().map(|set| Arc::clone(&set.mount))
    }

    /// Release every non-network namespace owner before zombie publication.
    /// # C: O(1) + final-owner drops
    pub fn release_namespaces(&self) {
        let old = self.namespaces.lock().take();
        drop(old);
    }
}
